import type {
  FirewallConnectionPublic,
  FirewallRule,
  FirewallSiteRecord,
  FirewallVendor,
  HourlyLogVolumePoint,
  IpConsumptionConsumer,
  IpConsumptionDestination,
  IpConsumptionReport,
  IpConsumptionTimelinePoint,
  NatPolicy,
  SyncStatus,
  SyslogEvent,
  TelemetrySnapshot,
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

/**
 * Quando a API do firewall (ex.: FortiOS /api/v2/monitor/system/interface) retorna apenas
 * contadores acumulados (rx_bytes/tx_bytes) sem taxa instantânea, calcula Rx/Tx em Mbps
 * pela variação de bytes entre a coleta anterior e a atual.
 */
export function deriveInterfaceThroughput(
  previousTelemetry: TelemetrySnapshot | undefined,
  previousSyncAt: string | null | undefined,
  nextTelemetry: TelemetrySnapshot,
  nowIso: string,
  capToLinkSpeed = false
): TelemetrySnapshot {
  if (!previousTelemetry?.interfaces?.length || !previousSyncAt) {
    return nextTelemetry;
  }
  const prevMs = Date.parse(previousSyncAt);
  const nowMs = Date.parse(nowIso);
  const elapsedSec = (nowMs - prevMs) / 1000;
  if (!Number.isFinite(elapsedSec) || elapsedSec < 1) {
    return nextTelemetry;
  }

  const prevByName = new Map(previousTelemetry.interfaces.map((i) => [i.name, i]));
  const interfaces = nextTelemetry.interfaces.map((curr) => {
    if (curr.rxMbps > 0 || curr.txMbps > 0) return curr;
    const prev = prevByName.get(curr.name);
    if (!prev) return curr;

    const deltaRx = curr.rxBytes >= prev.rxBytes ? curr.rxBytes - prev.rxBytes : 0;
    const deltaTx = curr.txBytes >= prev.txBytes ? curr.txBytes - prev.txBytes : 0;
    // (SonicWall e FortiGate) Taxa acima de ~2x a velocidade do link é impossível: contador reiniciado ou unidade errada.
    // piso de 10 Gbps: velocidade de link mal informada pela API não pode zerar uma leitura real
    const cap = capToLinkSpeed ? Math.max(curr.linkSpeedMbps * 2, 10_000) : Number.POSITIVE_INFINITY;
    const toMbps = (delta: number) => {
      const v = Number(((delta * 8) / (elapsedSec * 1_000_000)).toFixed(2));
      return v > cap ? 0 : v;
    };
    const rxMbps = toMbps(deltaRx);
    const txMbps = toMbps(deltaTx);
    const utilizationPercent =
      curr.linkSpeedMbps > 0
        ? Number(Math.min(100, ((rxMbps + txMbps) / curr.linkSpeedMbps) * 100).toFixed(1))
        : 0;

    return {
      ...curr,
      rxMbps,
      txMbps,
      utilizationPercent,
    };
  });

  return {
    ...nextTelemetry,
    interfaces,
  };
}

/**
 * Calcula o consumo de banda (bytes enviados/recebidos e vazão média em Mbps) de um IP
 * específico (ou dos maiores consumidores quando `ip` está vazio) dentro de uma janela
 * recente de syslogs.
 */
export function computeIpConsumption(
  events: SyslogEvent[],
  ipRaw: string,
  windowMinutesRaw = 15,
  nowMs = Date.now()
): IpConsumptionReport {
  const ip = ipRaw.trim();
  const windowMinutes = Math.max(1, Math.min(1440, Math.floor(windowMinutesRaw) || 15));
  const windowMs = windowMinutes * 60 * 1000;
  const cutoffMs = nowMs - windowMs;
  const windowSec = windowMinutes * 60;

  const consumerMap = new Map<
    string,
    { bytesSent: number; bytesRcvd: number; events: number }
  >();

  let totalBytesSent = 0;
  let totalBytesRcvd = 0;
  let eventCount = 0;
  let allowCount = 0;
  let blockedCount = 0;
  let lastSeenAt: string | null = null;

  const bucketCount = 12;
  const bucketMs = windowMs / bucketCount;
  const buckets = Array.from({ length: bucketCount }, () => ({
    bytesSent: 0,
    bytesRcvd: 0,
    events: 0,
  }));

  const destMap = new Map<
    string,
    { ip: string; port: number | null; protocol: string; bytesSent: number; bytesRcvd: number; events: number }
  >();
  const serviceMap = new Map<string, { totalBytes: number; events: number }>();

  for (const ev of events) {
    const evMs = resolveEventTimeMs(ev);
    if (evMs < cutoffMs || evMs > nowMs + 5 * 60 * 1000) continue;

    const sent = Math.max(0, Number(ev.bytesSent) || 0);
    const rcvd = Math.max(0, Number(ev.bytesRcvd) || 0);

    if (ev.srcIp && ev.srcIp !== '-') {
      const c = consumerMap.get(ev.srcIp) || { bytesSent: 0, bytesRcvd: 0, events: 0 };
      c.bytesSent += sent;
      c.bytesRcvd += rcvd;
      c.events += 1;
      consumerMap.set(ev.srcIp, c);
    }

    if (!ip) continue;

    const isSrc = ev.srcIp === ip;
    const isDst = ev.dstIp === ip;
    if (!isSrc && !isDst) continue;

    // Se o IP consultado foi o destino do pacote, o que o firewall registrou como rcvd é o que
    // esse IP enviou, e o sent é o que esse IP recebeu.
    const ipSent = isSrc ? sent : rcvd;
    const ipRcvd = isSrc ? rcvd : sent;
    const peerIp = isSrc ? ev.dstIp : ev.srcIp;
    const peerPort = isSrc ? ev.dstPort : ev.srcPort;

    totalBytesSent += ipSent;
    totalBytesRcvd += ipRcvd;
    eventCount += 1;
    if (ev.action === 'allow') allowCount += 1;
    else if (isBlockedAction(ev.action)) blockedCount += 1;

    const evIso = ev.ingestedAt || new Date(evMs).toISOString();
    if (!lastSeenAt || evIso > lastSeenAt) lastSeenAt = evIso;

    const idx = Math.min(
      bucketCount - 1,
      Math.max(0, Math.floor((evMs - cutoffMs) / bucketMs))
    );
    buckets[idx].bytesSent += ipSent;
    buckets[idx].bytesRcvd += ipRcvd;
    buckets[idx].events += 1;

    if (peerIp && peerIp !== '-') {
      const dKey = `${peerIp}:${peerPort ?? '-'}:${ev.protocol}`;
      const d = destMap.get(dKey) || {
        ip: peerIp,
        port: peerPort,
        protocol: ev.protocol,
        bytesSent: 0,
        bytesRcvd: 0,
        events: 0,
      };
      d.bytesSent += ipSent;
      d.bytesRcvd += ipRcvd;
      d.events += 1;
      destMap.set(dKey, d);
    }

    const svcName = ev.appName || (peerPort !== null ? `${ev.protocol}/${peerPort}` : ev.protocol || 'other');
    const svc = serviceMap.get(svcName) || { totalBytes: 0, events: 0 };
    svc.totalBytes += ipSent + ipRcvd;
    svc.events += 1;
    serviceMap.set(svcName, svc);
  }

  const bucketSec = bucketMs / 1000;
  const timeline: IpConsumptionTimelinePoint[] = buckets.map((b, idx) => {
    const startMs = cutoffMs + idx * bucketMs;
    const d = new Date(startMs);
    const label = `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
    const total = b.bytesSent + b.bytesRcvd;
    return {
      bucketLabel: label,
      bytesSent: b.bytesSent,
      bytesRcvd: b.bytesRcvd,
      mbps: bucketSec > 0 ? Number(((total * 8) / (bucketSec * 1_000_000)).toFixed(2)) : 0,
      events: b.events,
    };
  });

  const topDestinations: IpConsumptionDestination[] = Array.from(destMap.values())
    .map((d) => ({
      ...d,
      totalBytes: d.bytesSent + d.bytesRcvd,
    }))
    .sort((a, b) => b.totalBytes - a.totalBytes || b.events - a.events)
    .slice(0, 8);

  const topServices = Array.from(serviceMap.entries())
    .map(([service, v]) => ({ service, totalBytes: v.totalBytes, events: v.events }))
    .sort((a, b) => b.totalBytes - a.totalBytes || b.events - a.events)
    .slice(0, 6);

  const topConsumers: IpConsumptionConsumer[] = Array.from(consumerMap.entries())
    .map(([consumerIp, c]) => {
      const total = c.bytesSent + c.bytesRcvd;
      return {
        ip: consumerIp,
        totalBytes: total,
        bytesSent: c.bytesSent,
        bytesRcvd: c.bytesRcvd,
        avgMbps: Number(((total * 8) / (windowSec * 1_000_000)).toFixed(2)),
        events: c.events,
      };
    })
    .sort((a, b) => b.totalBytes - a.totalBytes || b.events - a.events)
    .slice(0, 10);

  const totalBytes = totalBytesSent + totalBytesRcvd;

  return {
    ip,
    windowMinutes,
    totalBytes,
    bytesSent: totalBytesSent,
    bytesRcvd: totalBytesRcvd,
    avgMbps: Number(((totalBytes * 8) / (windowSec * 1_000_000)).toFixed(2)),
    sentMbps: Number(((totalBytesSent * 8) / (windowSec * 1_000_000)).toFixed(2)),
    rcvdMbps: Number(((totalBytesRcvd * 8) / (windowSec * 1_000_000)).toFixed(2)),
    eventCount,
    allowCount,
    blockedCount,
    lastSeenAt,
    timeline,
    topDestinations,
    topServices,
    topConsumers,
  };
}
