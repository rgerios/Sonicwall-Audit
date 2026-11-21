import {
  classifyDestination,
  extractDestinationHints,
  ipScope,
  isIpAddress,
  registrableDomain,
  serviceLabel,
  type DestinationNode,
  type DestinationsReport,
} from '../shared/destinations.ts';
import type { SyslogEvent } from './types.ts';

interface Accumulator {
  id: string;
  host: string | null;
  hostSource: 'log' | 'rdns' | null;
  ips: Map<string, number>;
  scope: ReturnType<typeof ipScope>;
  connections: number;
  blocked: number;
  bytes: number;
  sources: Map<string, number>;
  services: Map<string, number>;
  appCategories: Map<string, number>;
  lastSeen: string | null;
}

const MAX_SOURCES_TRACKED = 2000;

const bump = (map: Map<string, number>, key: string) => map.set(key, (map.get(key) ?? 0) + 1);
const topKey = (map: Map<string, number>): string | null => {
  let best: string | null = null;
  let bestCount = -1;
  for (const [k, v] of map) if (v > bestCount) [best, bestCount] = [k, v];
  return best;
};

function isTrafficEvent(ev: SyslogEvent): boolean {
  if (ev.action === 'system') return false;
  const ip = (ev.dstIp || '').trim();
  return Boolean(ip) && ip !== '-' && isIpAddress(ip);
}

/**
 * Agrupa os eventos por destino (FQDN quando conhecido, senão IP). `lookupHost` devolve o FQDN
 * em cache do DNS reverso para um IP público, ou nada se ainda não foi resolvido.
 */
export function buildDestinationNodes(
  events: SyslogEvent[],
  options: { lookupHost?: (ip: string) => string | null | undefined; maxNodes?: number } = {}
): { nodes: DestinationNode[]; omitted: { destinations: number; connections: number }; analyzed: number } {
  const maxNodes = options.maxNodes ?? 150;
  const acc = new Map<string, Accumulator>();
  let analyzed = 0;

  for (const ev of events) {
    if (!isTrafficEvent(ev)) continue;
    analyzed += 1;
    const ip = ev.dstIp.trim();
    const scope = ipScope(ip);
    const hints = extractDestinationHints(ev.raw);
    let host = hints.host;
    let hostSource: 'log' | 'rdns' | null = host ? 'log' : null;
    if (!host && scope === 'public') {
      const cached = options.lookupHost?.(ip);
      if (cached) {
        host = cached;
        hostSource = 'rdns';
      }
    }
    const id = host ?? ip.toLowerCase();
    let a = acc.get(id);
    if (!a) {
      a = {
        id,
        host,
        hostSource,
        ips: new Map(),
        scope,
        connections: 0,
        blocked: 0,
        bytes: 0,
        sources: new Map(),
        services: new Map(),
        appCategories: new Map(),
        lastSeen: null,
      };
      acc.set(id, a);
    }
    a.connections += 1;
    if (ev.action === 'drop' || ev.action === 'deny' || ev.action === 'reset') a.blocked += 1;
    a.bytes += (ev.bytesSent || 0) + (ev.bytesRcvd || 0);
    bump(a.ips, ip);
    if (ev.srcIp && (a.sources.has(ev.srcIp) || a.sources.size < MAX_SOURCES_TRACKED)) bump(a.sources, ev.srcIp);
    bump(a.services, serviceLabel(ev.protocol, ev.dstPort, ev.appName));
    if (hints.appCategory) bump(a.appCategories, hints.appCategory);
    const seen = ev.ingestedAt || ev.timestamp || null;
    if (seen && (!a.lastSeen || seen > a.lastSeen)) a.lastSeen = seen;
  }

  const all: DestinationNode[] = [...acc.values()].map((a) => {
    const topService = topKey(a.services) ?? 'Outro';
    const host = a.host;
    return {
      id: a.id,
      label: host ?? a.id,
      host,
      hostSource: a.hostSource,
      ip: topKey(a.ips) ?? '',
      ips: [...a.ips.entries()].sort((x, y) => y[1] - x[1]).slice(0, 5).map(([ip]) => ip),
      group: host ? registrableDomain(host) : null,
      scope: a.scope,
      category: classifyDestination({
        host,
        service: topService,
        appCategory: topKey(a.appCategories),
        scope: a.scope,
      }),
      connections: a.connections,
      blocked: a.blocked,
      bytes: a.bytes,
      sources: a.sources.size,
      topSources: [...a.sources.entries()]
        .sort((x, y) => y[1] - x[1])
        .slice(0, 5)
        .map(([ip, count]) => ({ ip, count })),
      services: [...a.services.entries()]
        .sort((x, y) => y[1] - x[1])
        .slice(0, 5)
        .map(([name, count]) => ({ name, count })),
      lastSeen: a.lastSeen,
    };
  });

  all.sort((x, y) => y.connections - x.connections || y.bytes - x.bytes);
  const nodes = all.slice(0, maxNodes);
  const rest = all.slice(maxNodes);
  return {
    nodes,
    omitted: { destinations: rest.length, connections: rest.reduce((s, n) => s + n.connections, 0) },
    analyzed,
  };
}

export function buildDestinationsReport(params: {
  events: SyslogEvent[];
  minutes: number;
  windowSize: number;
  lookupHost?: (ip: string) => string | null | undefined;
  resolver: { enabled: boolean; resolved: number; pending: number };
  maxNodes?: number;
}): DestinationsReport {
  const { nodes, omitted, analyzed } = buildDestinationNodes(params.events, {
    lookupHost: params.lookupHost,
    maxNodes: params.maxNodes,
  });
  return {
    generatedAt: new Date().toISOString(),
    minutes: params.minutes,
    analyzedEvents: analyzed,
    windowSize: params.windowSize,
    totalConnections: nodes.reduce((s, n) => s + n.connections, 0) + omitted.connections,
    resolver: params.resolver,
    nodes,
    omitted,
  };
}

/** IPs de origem aceitos no filtro: só caracteres de IPv4/IPv6 (ou prefixos deles). */
export function normalizeSourceFilter(raw: unknown): string | null {
  const value = String(raw ?? '').trim().toLowerCase();
  if (!value) return '';
  if (value.length > 45 || !/^[0-9a-f:.]+$/.test(value)) return null;
  return value;
}

/** Mantém só os eventos cujo IP de origem contém o texto do filtro (mesma regra da tela de Syslogs). */
export function filterEventsBySource(events: SyslogEvent[], srcIp: string): SyslogEvent[] {
  if (!srcIp) return events;
  return events.filter((ev) => (ev.srcIp || '').toLowerCase().includes(srcIp));
}
