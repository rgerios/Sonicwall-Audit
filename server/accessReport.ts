import { classifyDestination, ipScope, isIpAddress, serviceLabel } from '../shared/destinations.ts';
import type {
  AccessCategoryRow,
  AccessCountryRow,
  AccessDestinationRow,
  AccessReportData,
  AccessServiceRow,
  AccessSourceRow,
  AccessTimelinePoint,
} from '../shared/accessReport.ts';
import type { Intel } from './intel.ts';
import type { SyslogEvent } from './types.ts';

/** Um agrupamento (origem, destino, serviço, bloqueado?) com contadores: mesma forma na memória e no banco. */
export interface AccessGroupRow {
  src: string;
  dst: string;
  proto: string;
  port: string;
  app: string;
  blocked: boolean;
  c: number;
  up: number;
  down: number;
}

export interface AccessHourRow {
  t: string;
  c: number;
  blocked: number;
  up: number;
  down: number;
}

export interface AccessAggregate {
  groups: AccessGroupRow[];
  hours: AccessHourRow[];
  totalEvents: number;
  timedOut: boolean;
}

const isBlocked = (a: string) => a === 'drop' || a === 'deny' || a === 'reset';

/** Agrega eventos em memória no mesmo formato que o SQL devolve. */
export function aggregateEventsInMemory(events: SyslogEvent[]): AccessAggregate {
  const groups = new Map<string, AccessGroupRow>();
  const hours = new Map<string, AccessHourRow>();
  let total = 0;
  for (const ev of events) {
    if (ev.action === 'system') continue;
    const src = (ev.srcIp || '').trim();
    const dst = (ev.dstIp || '').trim();
    if (!src || !dst || src === '-' || dst === '-') continue;
    total += 1;
    const blocked = isBlocked(ev.action);
    const up = ev.bytesSent || 0;
    const down = ev.bytesRcvd || 0;
    const key = `${src}|${dst}|${ev.protocol}|${ev.dstPort ?? ''}|${blocked ? 1 : 0}`;
    let g = groups.get(key);
    if (!g) {
      g = { src, dst, proto: ev.protocol || '', port: ev.dstPort === null ? '' : String(ev.dstPort), app: ev.appName || '', blocked, c: 0, up: 0, down: 0 };
      groups.set(key, g);
    }
    g.c += 1;
    g.up += up;
    g.down += down;
    const ms = Date.parse(ev.ingestedAt || ev.timestamp || '');
    if (Number.isFinite(ms)) {
      const t = new Date(Math.floor(ms / 3600_000) * 3600_000).toISOString();
      let h = hours.get(t);
      if (!h) {
        h = { t, c: 0, blocked: 0, up: 0, down: 0 };
        hours.set(t, h);
      }
      h.c += 1;
      if (blocked) h.blocked += 1;
      h.up += up;
      h.down += down;
    }
  }
  return {
    groups: [...groups.values()],
    hours: [...hours.values()].sort((a, b) => a.t.localeCompare(b.t)),
    totalEvents: total,
    timedOut: false,
  };
}

const bump = (m: Map<string, number>, k: string, n = 1) => m.set(k, (m.get(k) ?? 0) + n);
const top = (m: Map<string, number>): string | null => {
  let best: string | null = null;
  let max = -1;
  for (const [k, v] of m) if (v > max) [best, max] = [k, v];
  return best;
};

export function buildAccessReport(params: {
  agg: AccessAggregate;
  vendor: 'sonicwall' | 'fortigate';
  minutes: number;
  sinceIso: string | null;
  dataSource: 'memory' | 'database';
  intel: Intel;
  lookupHost?: (ip: string) => string | null | undefined;
  topN?: number;
}): AccessReportData {
  const { agg, intel } = params;
  const topN = params.topN ?? 25;

  interface Src {
    ip: string;
    c: number;
    blocked: number;
    up: number;
    down: number;
    dests: Set<string>;
    cats: Map<string, number>;
    countries: Map<string, number>;
  }
  interface Dst {
    ip: string;
    c: number;
    blocked: number;
    bytes: number;
    category: string;
    host: string | null;
  }
  const srcs = new Map<string, Src>();
  const dsts = new Map<string, Dst>();
  const cats = new Map<string, { c: number; bytes: number; dsts: Set<string> }>();
  const countries = new Map<string, { c: number; blocked: number; bytes: number; ips: Set<string> }>();
  const services = new Map<string, { c: number; bytes: number }>();
  const dstIntel = new Map<string, ReturnType<Intel['lookup']>>();
  const catCache = new Map<string, string>();

  let connections = 0;
  let blockedTotal = 0;
  let up = 0;
  let down = 0;
  let threatConnections = 0;
  let groupedEvents = 0;

  for (const g of agg.groups) {
    groupedEvents += g.c;
    const bytes = g.up + g.down;
    const scope = isIpAddress(g.dst) ? ipScope(g.dst) : 'public';
    const service = serviceLabel(g.proto, g.port ? Number(g.port) : null, g.app || null);
    const host = scope === 'public' ? (params.lookupHost?.(g.dst) ?? null) : null;
    const ck = `${host ?? ''}|${service}|${scope}`;
    let category = catCache.get(ck);
    if (!category) {
      category = classifyDestination({ host, service, appCategory: null, scope });
      catCache.set(ck, category);
    }

    connections += g.c;
    if (g.blocked) blockedTotal += g.c;
    up += g.up;
    down += g.down;

    let info = dstIntel.get(g.dst);
    if (!info) {
      info = scope === 'public' ? intel.lookup(g.dst) : { country: null, asn: null, asnOrg: null, threats: [] };
      dstIntel.set(g.dst, info);
    }
    if (info.threats.length > 0) threatConnections += g.c;

    let s = srcs.get(g.src);
    if (!s) {
      s = { ip: g.src, c: 0, blocked: 0, up: 0, down: 0, dests: new Set(), cats: new Map(), countries: new Map() };
      srcs.set(g.src, s);
    }
    s.c += g.c;
    if (g.blocked) s.blocked += g.c;
    s.up += g.up;
    s.down += g.down;
    s.dests.add(g.dst);
    bump(s.cats, category, g.c);
    if (info.country) bump(s.countries, info.country, g.c);

    let d = dsts.get(g.dst);
    if (!d) {
      d = { ip: g.dst, c: 0, blocked: 0, bytes: 0, category, host };
      dsts.set(g.dst, d);
    }
    d.c += g.c;
    if (g.blocked) d.blocked += g.c;
    d.bytes += bytes;

    const cat = cats.get(category) ?? { c: 0, bytes: 0, dsts: new Set<string>() };
    cat.c += g.c;
    cat.bytes += bytes;
    cat.dsts.add(g.dst);
    cats.set(category, cat);

    if (info.country) {
      const ct = countries.get(info.country) ?? { c: 0, blocked: 0, bytes: 0, ips: new Set<string>() };
      ct.c += g.c;
      if (g.blocked) ct.blocked += g.c;
      ct.bytes += bytes;
      ct.ips.add(g.dst);
      countries.set(info.country, ct);
    }
    const sv = services.get(service) ?? { c: 0, bytes: 0 };
    sv.c += g.c;
    sv.bytes += bytes;
    services.set(service, sv);
  }

  const sourceRows: AccessSourceRow[] = [...srcs.values()]
    .map((s) => ({
      ip: s.ip,
      connections: s.c,
      blocked: s.blocked,
      uploadBytes: s.up,
      downloadBytes: s.down,
      totalBytes: s.up + s.down,
      destinations: s.dests.size,
      topCategory: top(s.cats),
      topCountry: top(s.countries),
    }))
    .sort((a, b) => b.totalBytes - a.totalBytes || b.connections - a.connections);

  const destRows: AccessDestinationRow[] = [...dsts.values()]
    .sort((a, b) => b.c - a.c)
    .slice(0, topN)
    .map((d) => {
      const info = dstIntel.get(d.ip);
      return {
        ip: d.ip,
        host: d.host,
        category: d.category,
        country: info?.country ?? null,
        asnOrg: info?.asnOrg ?? null,
        connections: d.c,
        blocked: d.blocked,
        totalBytes: d.bytes,
        threats: [...new Set((info?.threats ?? []).map((t) => t.list))],
      };
    });

  const categoryRows: AccessCategoryRow[] = [...cats.entries()]
    .map(([name, v]) => ({ name, connections: v.c, totalBytes: v.bytes, destinations: v.dsts.size }))
    .sort((a, b) => b.connections - a.connections);
  const countryRows: AccessCountryRow[] = [...countries.entries()]
    .map(([code, v]) => ({ code, connections: v.c, blocked: v.blocked, totalBytes: v.bytes, ips: v.ips.size }))
    .sort((a, b) => b.connections - a.connections);
  const serviceRows: AccessServiceRow[] = [...services.entries()]
    .map(([name, v]) => ({ name, connections: v.c, totalBytes: v.bytes }))
    .sort((a, b) => b.connections - a.connections)
    .slice(0, 15);

  const timeline: AccessTimelinePoint[] = agg.hours.map((h) => ({
    t: h.t,
    connections: h.c,
    blocked: h.blocked,
    uploadBytes: h.up,
    downloadBytes: h.down,
  }));
  const firstMs = timeline.length ? Date.parse(timeline[0].t) : Date.now();
  const spanSec = Math.max(3600, (Date.now() - (params.sinceIso ? Date.parse(params.sinceIso) : firstMs)) / 1000);
  const totalBytes = up + down;
  const peakHourBytes = timeline.reduce((m, h) => Math.max(m, h.uploadBytes + h.downloadBytes), 0);
  const topSources = sourceRows.slice(0, topN);
  const topBytes = topSources.reduce((n, s) => n + s.totalBytes, 0);

  return {
    generatedAt: new Date().toISOString(),
    vendor: params.vendor,
    minutes: params.minutes,
    periodStart: params.sinceIso,
    periodEnd: new Date().toISOString(),
    analyzedEvents: agg.totalEvents,
    dataSource: params.dataSource,
    coveragePct: agg.totalEvents > 0 ? Math.min(100, Math.round((groupedEvents / agg.totalEvents) * 1000) / 10) : 100,
    timedOut: agg.timedOut,
    totals: {
      connections,
      blocked: blockedTotal,
      uploadBytes: up,
      downloadBytes: down,
      totalBytes,
      sources: srcs.size,
      destinations: dsts.size,
      countries: countries.size,
      avgMbps: Math.round(((totalBytes * 8) / spanSec / 1e6) * 1000) / 1000,
      peakHourMbps: Math.round(((peakHourBytes * 8) / 3600 / 1e6) * 1000) / 1000,
      threatConnections,
    },
    timeline,
    sources: topSources,
    destinations: destRows,
    categories: categoryRows,
    countries: countryRows.slice(0, 20),
    services: serviceRows,
    othersSources: { count: Math.max(0, sourceRows.length - topSources.length), totalBytes: Math.max(0, totalBytes - topBytes) },
  };
}
