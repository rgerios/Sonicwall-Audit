import type {
  FirewallConnectionPublic,
  FirewallRule,
  FirewallSiteRecord,
  FirewallVendor,
  HourlyLogVolumePoint,
  NatPolicy,
  SyncStatus,
  SyslogEvent,
} from './types.ts';

export const HOUR_MS = 60 * 60 * 1000;

export interface HourBucket {
  total: number;
  allow: number;
  blocked: number;
}

/** Contadores mantidos fora da janela em memória: valem para todo o histórico armazenado. */
export interface SiteRuntime {
  total: number;
  oldestAt: string | null;
  newestAt: string | null;
  byAction: Record<string, number>;
  bySeverity: Record<string, number>;
  hourly: Map<number, HourBucket>;
  lastEventAtMs: number | null;
  syncing: boolean;
}

export function envInt(name: string, fallback: number, min: number): number {
  const n = Number(process.env[name]);
  return Number.isFinite(n) && n >= min ? Math.floor(n) : fallback;
}

export function isBlockedAction(action: string): boolean {
  return action === 'drop' || action === 'deny' || action === 'reset';
}

/**
 * Instante usado para posicionar o evento no gráfico por hora. Eventos UDP chegam em tempo
 * real (evita divergência de fuso do firewall); em uploads vale o horário do próprio log.
 */
export function resolveEventTimeMs(ev: SyslogEvent): number {
  const ingestedParsed = Date.parse(ev.ingestedAt || '');
  const ingestedMs = Number.isFinite(ingestedParsed) ? ingestedParsed : Date.now();
  if (ev.source === 'udp') return ingestedMs;
  const parsed = Date.parse((ev.timestamp || '').replace(' ', 'T'));
  if (
    Number.isFinite(parsed) &&
    parsed <= ingestedMs + 5 * 60 * 1000 &&
    parsed >= ingestedMs - 366 * 24 * HOUR_MS
  ) {
    return parsed;
  }
  return ingestedMs;
}

export function emptyRuntime(): SiteRuntime {
  return {
    total: 0,
    oldestAt: null,
    newestAt: null,
    byAction: {},
    bySeverity: {},
    hourly: new Map(),
    lastEventAtMs: null,
    syncing: false,
  };
}

export function addEventsToRuntime(rt: SiteRuntime, events: SyslogEvent[]): void {
  for (const ev of events) {
    rt.total += 1;
    rt.byAction[ev.action] = (rt.byAction[ev.action] || 0) + 1;
    rt.bySeverity[ev.severity] = (rt.bySeverity[ev.severity] || 0) + 1;

    const bucketStart = Math.floor(resolveEventTimeMs(ev) / HOUR_MS) * HOUR_MS;
    const bucket = rt.hourly.get(bucketStart) || { total: 0, allow: 0, blocked: 0 };
    bucket.total += 1;
    if (ev.action === 'allow') bucket.allow += 1;
    else if (isBlockedAction(ev.action)) bucket.blocked += 1;
    rt.hourly.set(bucketStart, bucket);

    if (ev.ingestedAt) {
      if (!rt.oldestAt || ev.ingestedAt < rt.oldestAt) rt.oldestAt = ev.ingestedAt;
      if (!rt.newestAt || ev.ingestedAt > rt.newestAt) rt.newestAt = ev.ingestedAt;
      const ms = Date.parse(ev.ingestedAt);
      if (Number.isFinite(ms) && (rt.lastEventAtMs === null || ms > rt.lastEventAtMs)) {
        rt.lastEventAtMs = ms;
      }
    }
  }
  if (rt.hourly.size > 60) {
    const cutoff = Date.now() - 50 * HOUR_MS;
    for (const key of rt.hourly.keys()) {
      if (key < cutoff) rt.hourly.delete(key);
    }
  }
}

export function toPublicConnection(
  site: FirewallSiteRecord,
  vendor: FirewallVendor
): FirewallConnectionPublic {
  return {
    host: site.connection.host,
    port: site.connection.port,
    protocol: site.connection.protocol,
    username: site.connection.username,
    hasSavedPassword: Boolean(site.connection.passwordEncrypted),
    authMode: site.connection.authMode || (vendor === 'fortigate' ? 'token' : 'basic'),
    vdom: site.connection.vdom || (vendor === 'fortigate' ? 'root' : undefined),
    ignoreTlsErrors: site.connection.ignoreTlsErrors,
  };
}

export function toSyncStatus(site: FirewallSiteRecord): SyncStatus {
  return {
    autoSyncMinutes: site.autoSyncMinutes,
    lastAttemptAt: site.lastSyncAttemptAt,
    lastError: site.lastSyncError,
    consecutiveFailures: site.consecutiveSyncFailures,
  };
}

export function buildHourlyLogVolume(
  hourly: Map<number, HourBucket>,
  nowMs = Date.now()
): HourlyLogVolumePoint[] {
  const currentHourStart = Math.floor(nowMs / HOUR_MS) * HOUR_MS;
  const points: HourlyLogVolumePoint[] = [];
  for (let offset = 23; offset >= 0; offset -= 1) {
    const startMs = currentHourStart - offset * HOUR_MS;
    const bucket = hourly.get(startMs);
    points.push({
      hourLabel: `${String(new Date(startMs).getHours()).padStart(2, '0')}:00`,
      total: bucket?.total ?? 0,
      allow: bucket?.allow ?? 0,
      blocked: bucket?.blocked ?? 0,
    });
  }
  return points;
}

export function computeWindowRankings(syslogs: SyslogEvent[]): {
  topBlockedSources: Array<{ ip: string; count: number; zone: string }>;
  topTargetedPorts: Array<{ port: string; protocol: string; count: number; blocked: number }>;
  zoneTraffic: Array<{ pair: string; allow: number; blocked: number }>;
} {
  const blockedSrcCounts = new Map<string, { count: number; zone: string }>();
  const portCounts = new Map<
    string,
    { port: string; protocol: string; count: number; blocked: number }
  >();
  const zoneCounts = new Map<string, { allow: number; blocked: number }>();

  for (const ev of syslogs) {
    const isBlocked = isBlockedAction(ev.action);
    if (isBlocked && ev.srcIp !== '-') {
      const prev = blockedSrcCounts.get(ev.srcIp) || { count: 0, zone: ev.srcZone };
      blockedSrcCounts.set(ev.srcIp, { count: prev.count + 1, zone: ev.srcZone });
    }
    if (ev.dstPort !== null) {
      const key = `${ev.protocol.split('/')[0]}-${ev.dstPort}`;
      const prev = portCounts.get(key) || {
        port: String(ev.dstPort),
        protocol: ev.protocol,
        count: 0,
        blocked: 0,
      };
      prev.count += 1;
      if (isBlocked) prev.blocked += 1;
      portCounts.set(key, prev);
    }
    const pair = `${ev.srcZone} -> ${ev.dstZone}`;
    const zPrev = zoneCounts.get(pair) || { allow: 0, blocked: 0 };
    if (isBlocked) zPrev.blocked += 1;
    else if (ev.action === 'allow') zPrev.allow += 1;
    zoneCounts.set(pair, zPrev);
  }

  return {
    topBlockedSources: Array.from(blockedSrcCounts.entries())
      .map(([ip, v]) => ({ ip, count: v.count, zone: v.zone }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 8),
    topTargetedPorts: Array.from(portCounts.values())
      .sort((a, b) => b.count - a.count)
      .slice(0, 8),
    zoneTraffic: Array.from(zoneCounts.entries())
      .map(([pair, v]) => ({ pair, allow: v.allow, blocked: v.blocked }))
      .sort((a, b) => b.allow + b.blocked - (a.allow + a.blocked))
      .slice(0, 8),
  };
}

export function policySignature(p: FirewallRule | NatPolicy): string {
  if ('fromZone' in p) {
    return [p.name, p.fromZone, p.toZone, p.source, p.destination, p.service, p.action, p.enabled].join('|');
  }
  return [
    p.name,
    p.inboundInterface,
    p.outboundInterface,
    p.origSource,
    p.transSource,
    p.origDestination,
    p.transDestination,
    p.origService,
    p.transService,
    p.enabled,
  ].join('|');
}

export function diffPolicies<T extends FirewallRule | NatPolicy>(
  label: string,
  previous: T[],
  next: T[],
  details: string[]
): { added: number; removed: number; modified: number } {
  const keyOf = (p: T) => p.uuid || p.id;
  const prevMap = new Map(previous.map((p) => [keyOf(p), p]));
  const nextMap = new Map(next.map((p) => [keyOf(p), p]));
  let added = 0;
  let removed = 0;
  let modified = 0;

  for (const [key, p] of nextMap) {
    const old = prevMap.get(key);
    if (!old) {
      added += 1;
      details.push(`+ ${label} "${p.name}"`);
    } else if (policySignature(old) !== policySignature(p)) {
      modified += 1;
      details.push(
        old.enabled !== p.enabled
          ? `~ ${label} "${p.name}" ${p.enabled ? 'habilitada' : 'desabilitada'}`
          : `~ ${label} "${p.name}" alterada`
      );
    }
  }
  for (const [key, p] of prevMap) {
    if (!nextMap.has(key)) {
      removed += 1;
      details.push(`- ${label} "${p.name}"`);
    }
  }
  return { added, removed, modified };
}
