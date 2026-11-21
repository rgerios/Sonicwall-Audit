import { ipScope, isIpAddress } from '../shared/destinations.ts';
import type {
  BehaviorCountry,
  BehaviorFlow,
  BehaviorIp,
  BehaviorOrigin,
  BehaviorReport,
  BehaviorThreatCategory,
} from '../shared/behavior.ts';
import type { Intel, IntelLookup } from './intel.ts';
import type { SyslogEvent } from './types.ts';

const MAX_IPS_TRACKED = 30_000;
// Na primeira carga mostra o último minuto (ajustável, útil para demonstração com logs antigos)
const DEFAULT_FLOW_WINDOW_MS = Math.max(1000, Number(process.env.BEHAVIOR_FLOW_WINDOW_MS) || 60_000);
const MAX_FLOWS = 500;
const FALLBACK_ORIGIN = 'BR';

interface IpAcc {
  ip: string;
  lookup: IntelLookup;
  connections: number;
  blocked: number;
  bytes: number;
  sources: Map<string, number>;
  lastSeen: string | null;
}

const isBlocked = (action: string) => action === 'drop' || action === 'deny' || action === 'reset';

export function buildBehaviorReport(params: {
  events: SyslogEvent[];
  minutes: number;
  intel: Intel;
  origin: BehaviorOrigin;
  /** Só devolve em `flows` as conexões ingeridas depois deste instante (ISO). */
  since?: string;
  dataSource: 'memory' | 'database';
  truncated: boolean;
}): BehaviorReport {
  const { events, intel } = params;
  const ips = new Map<string, IpAcc>();
  const lookups = new Map<string, IntelLookup>();
  const countries = new Map<string, BehaviorCountry & { ipSet: Set<string>; threatSet: Set<string> }>();
  const recent: Array<BehaviorFlow & { ms: number }> = [];
  const sinceMs = params.since ? Date.parse(params.since) : NaN;
  const flowCutoff = Number.isFinite(sinceMs) ? sinceMs : Date.now() - DEFAULT_FLOW_WINDOW_MS;
  let analyzed = 0;
  let blockedTotal = 0;
  let threatConnections = 0;
  let unknownConnections = 0;
  let connectionsTotal = 0;

  for (const ev of events) {
    if (ev.action === 'system') continue;
    const dst = (ev.dstIp || '').trim();
    if (!dst || dst === '-' || !isIpAddress(dst) || ipScope(dst) !== 'public') continue;
    analyzed += 1;

    let lookup = lookups.get(dst);
    if (!lookup) {
      lookup = intel.lookup(dst);
      lookups.set(dst, lookup);
    }
    const blocked = isBlocked(ev.action);
    const bytes = (ev.bytesSent || 0) + (ev.bytesRcvd || 0);
    const threat = lookup.threats.length > 0;
    const seen = ev.ingestedAt || ev.timestamp || null;

    connectionsTotal += 1;
    if (blocked) blockedTotal += 1;
    if (threat) threatConnections += 1;

    let acc = ips.get(dst);
    if (!acc && ips.size < MAX_IPS_TRACKED) {
      acc = { ip: dst, lookup, connections: 0, blocked: 0, bytes: 0, sources: new Map(), lastSeen: null };
      ips.set(dst, acc);
    }
    if (acc) {
      acc.connections += 1;
      if (blocked) acc.blocked += 1;
      acc.bytes += bytes;
      if (ev.srcIp && (acc.sources.has(ev.srcIp) || acc.sources.size < 50)) {
        acc.sources.set(ev.srcIp, (acc.sources.get(ev.srcIp) ?? 0) + 1);
      }
      if (seen && (!acc.lastSeen || seen > acc.lastSeen)) acc.lastSeen = seen;
    }

    if (!lookup.country) {
      unknownConnections += 1;
    } else {
      let c = countries.get(lookup.country);
      if (!c) {
        c = {
          code: lookup.country,
          connections: 0,
          blocked: 0,
          bytes: 0,
          ips: 0,
          threatIps: 0,
          ipSet: new Set(),
          threatSet: new Set(),
        };
        countries.set(lookup.country, c);
      }
      c.connections += 1;
      if (blocked) c.blocked += 1;
      c.bytes += bytes;
      c.ipSet.add(dst);
      if (threat) c.threatSet.add(dst);
      const ms = seen ? Date.parse(seen) : NaN;
      if (Number.isFinite(ms) && ms > flowCutoff && recent.length < 20_000) {
        recent.push({ at: seen as string, country: lookup.country, blocked, threat, ms });
      }
    }
  }

  const countryList: BehaviorCountry[] = [...countries.values()]
    .map(({ ipSet, threatSet, ...c }) => ({ ...c, ips: ipSet.size, threatIps: threatSet.size }))
    .sort((a, b) => b.connections - a.connections);

  const toIp = (a: IpAcc): BehaviorIp => ({
    ip: a.ip,
    country: a.lookup.country,
    asn: a.lookup.asn,
    asnOrg: a.lookup.asnOrg,
    connections: a.connections,
    blocked: a.blocked,
    bytes: a.bytes,
    threats: [...new Set(a.lookup.threats.map((t) => t.list))],
    categories: [...new Set(a.lookup.threats.map((t) => t.category))] as BehaviorThreatCategory[],
    topSources: [...a.sources.entries()]
      .sort((x, y) => y[1] - x[1])
      .slice(0, 5)
      .map(([ip, count]) => ({ ip, count })),
    lastSeen: a.lastSeen,
  });

  const all = [...ips.values()].sort((a, b) => b.connections - a.connections);
  recent.sort((a, b) => a.ms - b.ms);
  const flowsSampleEvery = Math.max(1, Math.ceil(recent.length / MAX_FLOWS));
  const flows: BehaviorFlow[] = recent
    .filter((_, i) => i % flowsSampleEvery === 0)
    .map(({ ms: _ms, ...f }) => f);

  return {
    generatedAt: new Date().toISOString(),
    minutes: params.minutes,
    origin: params.origin,
    analyzedEvents: analyzed,
    publicIps: ips.size,
    totals: {
      connections: connectionsTotal,
      blocked: blockedTotal,
      countries: countryList.length,
      threatConnections,
      unknownConnections,
    },
    countries: countryList,
    ips: all.slice(0, 150).map(toIp),
    threats: all.filter((a) => a.lookup.threats.length > 0).slice(0, 100).map(toIp),
    flows,
    flowsTotal: recent.length,
    flowsSampleEvery,
    intel: intelStatus(intel),
    dataSource: params.dataSource,
    truncated: params.truncated,
  };
}

const intelStatus = (intel: Intel) => intel.status();

// --- País do firewall, descoberto automaticamente -----------------------------------------------------

/**
 * Descobre onde o firewall está sem configuração: 1) IP público de uma interface WAN; 2) IP de origem
 * traduzido (NAT) mais frequente nos logs, que é o IP público que a internet enxerga; 3) Brasil.
 */
export function detectOrigin(events: SyslogEvent[], wanIps: string[], intel: Intel): BehaviorOrigin {
  for (const ip of wanIps) {
    if (isIpAddress(ip) && ipScope(ip) === 'public') {
      const country = intel.lookup(ip).country;
      if (country) return { country, ip, source: 'wan' };
    }
  }
  const counts = new Map<string, number>();
  for (const ev of events) {
    const ip = (ev.natSrcIp || '').trim();
    if (!ip || !isIpAddress(ip) || ipScope(ip) !== 'public') continue;
    counts.set(ip, (counts.get(ip) ?? 0) + 1);
  }
  const sorted = [...counts.entries()].sort((a, b) => b[1] - a[1]);
  for (const [ip] of sorted.slice(0, 5)) {
    const country = intel.lookup(ip).country;
    if (country) return { country, ip, source: 'nat' };
  }
  return { country: FALLBACK_ORIGIN, ip: null, source: 'fallback' };
}
