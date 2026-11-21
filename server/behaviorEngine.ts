import fs from 'node:fs/promises';
import path from 'node:path';
import { ipScope, isIpAddress } from '../shared/destinations.ts';
import type {
  BehaviorCountry,
  BehaviorFlow,
  BehaviorIp,
  BehaviorReport,
  BehaviorThreatCategory,
} from '../shared/behavior.ts';
import type { Intel, IntelLookup } from './intel.ts';
import type { SyslogEvent } from './types.ts';

const MAX_IPS_TRACKED = 30_000;
const FLOW_WINDOW_MS = 5 * 60_000;
const MAX_FLOWS = 120;
const DEFAULT_ORIGIN = 'BR';

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
  originCountry: string;
  dataSource: 'memory' | 'database';
  truncated: boolean;
}): BehaviorReport {
  const { events, intel } = params;
  const ips = new Map<string, IpAcc>();
  const lookups = new Map<string, IntelLookup>();
  const countries = new Map<string, BehaviorCountry & { ipSet: Set<string>; threatSet: Set<string> }>();
  const recent: Array<BehaviorFlow & { ms: number }> = [];
  const flowCutoff = Date.now() - FLOW_WINDOW_MS;
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
      if (Number.isFinite(ms) && ms >= flowCutoff && recent.length < 4000) {
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
  const flows: BehaviorFlow[] = recent
    .sort((a, b) => b.ms - a.ms)
    .slice(0, MAX_FLOWS)
    .map(({ ms: _ms, ...f }) => f);

  return {
    generatedAt: new Date().toISOString(),
    minutes: params.minutes,
    originCountry: params.originCountry,
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
    intel: intelStatus(intel),
    dataSource: params.dataSource,
    truncated: params.truncated,
  };
}

const intelStatus = (intel: Intel) => intel.status();

// --- País do firewall (origem das linhas do mapa), por localidade ------------------------------------

const originFile = (dataDir: string) => path.join(dataDir, 'intel', 'origin.json');

export async function readOriginCountry(dataDir: string, siteId: string): Promise<string> {
  try {
    const map = JSON.parse(await fs.readFile(originFile(dataDir), 'utf8')) as Record<string, string>;
    const code = map[siteId];
    return typeof code === 'string' && /^[A-Z]{2}$/.test(code) ? code : DEFAULT_ORIGIN;
  } catch {
    return DEFAULT_ORIGIN;
  }
}

export async function writeOriginCountry(dataDir: string, siteId: string, code: string): Promise<void> {
  let map: Record<string, string> = {};
  try {
    map = JSON.parse(await fs.readFile(originFile(dataDir), 'utf8')) as Record<string, string>;
  } catch {
    /* primeiro uso */
  }
  map[siteId] = code;
  await fs.mkdir(path.dirname(originFile(dataDir)), { recursive: true });
  await fs.writeFile(originFile(dataDir), JSON.stringify(map, null, 2));
}
