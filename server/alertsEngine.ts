import type {
  AlertSettings,
  ApplianceMetadata,
  ConfigChangeEntry,
  FirewallVendor,
  OverviewAlert,
  SyslogEvent,
  TelemetrySnapshot,
} from './types.ts';

export const DEFAULT_ALERT_SETTINGS: AlertSettings = {
  bandwidthUtilizationLimitPercent: 80,
  bandwidthMbpsLimit: 0,
  hourlyLogVolumeLimit: 0,
  syslogTrafficMbLimit: 0,
  blockedTrafficRatioLimitPercent: 60,
  anomalyDetectionEnabled: true,
  anomalySpikeMultiplier: 3,
  portScanUniquePortsThreshold: 15,
  alertOnIps: true,
  alertOnCriticalLogs: true,
  suspiciousBlockThreshold: 50,
  alertWindowMinutes: 60,
  cpuLimitPercent: 90,
  memoryLimitPercent: 90,
  silenceMinutes: 15,
  alertOnVpnDown: true,
  alertOnLicense: true,
  alertOnConfigChange: true,
  adminLoginFailureThreshold: 5,
};

function boundedInt(raw: unknown, min: number, max: number, fallback: number, allowZero = false): number {
  const n = Number(raw);
  if (!Number.isFinite(n)) return fallback;
  if (allowZero && n === 0) return 0;
  if (n < min || n > max) return fallback;
  return Math.round(n);
}

export function normalizeAlertSettings(raw?: Partial<AlertSettings> | null): AlertSettings {
  const d = DEFAULT_ALERT_SETTINGS;
  const trafficMb = Number(raw?.syslogTrafficMbLimit);
  const spikeMult = Number(raw?.anomalySpikeMultiplier);

  return {
    bandwidthUtilizationLimitPercent: boundedInt(raw?.bandwidthUtilizationLimitPercent, 5, 100, d.bandwidthUtilizationLimitPercent),
    bandwidthMbpsLimit: boundedInt(raw?.bandwidthMbpsLimit, 0, 100000, d.bandwidthMbpsLimit),
    hourlyLogVolumeLimit: boundedInt(raw?.hourlyLogVolumeLimit, 0, 100_000_000, d.hourlyLogVolumeLimit),
    syslogTrafficMbLimit:
      Number.isFinite(trafficMb) && trafficMb >= 0 && trafficMb <= 100_000_000
        ? Number(trafficMb.toFixed(2))
        : d.syslogTrafficMbLimit,
    blockedTrafficRatioLimitPercent: boundedInt(raw?.blockedTrafficRatioLimitPercent, 5, 100, d.blockedTrafficRatioLimitPercent, true),
    anomalyDetectionEnabled: raw?.anomalyDetectionEnabled !== false,
    anomalySpikeMultiplier:
      Number.isFinite(spikeMult) && spikeMult >= 1.2 && spikeMult <= 20
        ? Number(spikeMult.toFixed(1))
        : d.anomalySpikeMultiplier,
    portScanUniquePortsThreshold: boundedInt(raw?.portScanUniquePortsThreshold, 2, 10000, d.portScanUniquePortsThreshold, true),
    alertOnIps: raw?.alertOnIps !== false,
    alertOnCriticalLogs: raw?.alertOnCriticalLogs !== false,
    suspiciousBlockThreshold: boundedInt(raw?.suspiciousBlockThreshold, 1, 1_000_000, d.suspiciousBlockThreshold),
    alertWindowMinutes: boundedInt(raw?.alertWindowMinutes, 5, 1440, d.alertWindowMinutes),
    cpuLimitPercent: boundedInt(raw?.cpuLimitPercent, 10, 100, d.cpuLimitPercent, true),
    memoryLimitPercent: boundedInt(raw?.memoryLimitPercent, 10, 100, d.memoryLimitPercent, true),
    silenceMinutes: boundedInt(raw?.silenceMinutes, 1, 1440, d.silenceMinutes, true),
    alertOnVpnDown: raw?.alertOnVpnDown !== false,
    alertOnLicense: raw?.alertOnLicense !== false,
    alertOnConfigChange: raw?.alertOnConfigChange !== false,
    adminLoginFailureThreshold: boundedInt(raw?.adminLoginFailureThreshold, 1, 10000, d.adminLoginFailureThreshold, true),
  };
}

export interface AlertContext {
  nowMs?: number;
  appliance?: ApplianceMetadata;
  /** Volume por hora (últimas ~48h) mantido pelo coletor, independente da janela em memória. */
  hourly?: Array<{ startMs: number; total: number; blocked: number }>;
  lastEventAtMs?: number | null;
  udpRunning?: boolean;
  consecutiveSyncFailures?: number;
  lastSyncError?: string | null;
  configChanges?: ConfigChangeEntry[];
}

const MAX_ALERTS_PER_GROUP = 10;
const MAX_ALERTS_TOTAL = 100;

function shortHash(text: string): string {
  let h = 5381;
  for (let i = 0; i < text.length; i += 1) {
    h = ((h << 5) + h + text.charCodeAt(i)) | 0;
  }
  return (h >>> 0).toString(36);
}

function isAdminLoginFailure(ev: SyslogEvent): boolean {
  return /(admin|administrator|management|web|ssh|cli|user)[^|]{0,40}login[^|]{0,30}(fail|denied|reject)|login\s*(failed|failure|denied)|authentication\s*(failed|failure)|incorrect\s*password|bad\s*password/i.test(
    ev.message
  );
}

function isIpsEvent(ev: SyslogEvent): boolean {
  if (ev.categoryCode === '512') return true;
  return /\b(ips|ids)\b|intrusion|et scan|port\s*scan|exploit|syn\s*flood|ddos|brute\s*force|spoof|botnet|malicious|sql\s*injection/i.test(
    ev.message
  );
}

function isMalwareEvent(ev: SyslogEvent): boolean {
  if (ev.categoryCode === '2048') return true;
  return /anti-?virus|trojan|malware|ransomware|capture\s*atp|spyware|worm|backdoor|virus/i.test(
    ev.message
  );
}

function isCriticalSystemEvent(ev: SyslogEvent): boolean {
  if (ev.priority <= 2) return true;
  if (ev.priority <= 3) {
    return /failover|ha\s*fail|link\s*down|tunnel\s*down|panic|critical|auth.*fail|login.*fail|certificate/i.test(
      ev.message
    );
  }
  return false;
}

function formatTrafficMb(bytes: number): string {
  const mb = bytes / (1024 * 1024);
  return mb >= 100 ? mb.toFixed(0) : mb >= 10 ? mb.toFixed(1) : mb.toFixed(2);
}

const SENSITIVE_PORTS = new Set([21, 22, 23, 445, 1433, 3306, 3389, 5432, 5900]);

export function evaluateOverviewAlerts(
  telemetry: TelemetrySnapshot,
  allSyslogs: SyslogEvent[],
  settings: AlertSettings,
  vendor: FirewallVendor = 'sonicwall',
  ctx: AlertContext = {}
): OverviewAlert[] {
  const alerts: OverviewAlert[] = [];
  const vendorLabel = vendor === 'fortigate' ? 'FortiGate' : 'SonicWall';
  const nowMs = ctx.nowMs ?? Date.now();
  const windowMin = settings.alertWindowMinutes;
  const windowLabel = windowMin >= 120 ? `${Math.round(windowMin / 60)} h` : `${windowMin} min`;

  // Janela deslizante: só os eventos recebidos nos últimos N minutos disparam alertas.
  // Quando a condição deixa a janela, o alerta é resolvido pelo motor persistente.
  const cutoffMs = nowMs - windowMin * 60 * 1000;
  const syslogs: SyslogEvent[] = [];
  for (const ev of allSyslogs) {
    const ms = Date.parse(ev.ingestedAt || '');
    if (!Number.isFinite(ms) || ms >= cutoffMs) syslogs.push(ev);
  }

  // Origens já sinalizadas como varredura não geram um segundo alerta de "bloqueios suspeitos"
  const scanFlaggedIps = new Set<string>();

  // 1. Bandwidth threshold & link-down alerts
  for (const iface of telemetry.interfaces) {
    if (iface.linkStatus === 'down') {
      // Portas internas sem cabo são comuns: só é crítico em WAN.
      const isWan = iface.role !== 'internal';
      alerts.push({
        id: `link-down-${iface.name}`,
        severity: isWan ? 'critical' : 'warning',
        category: 'link-down',
        title: `Interface ${iface.name} (${iface.zone}) fora do ar`,
        description: `O link físico da interface ${iface.name} (${iface.ip}) encontra-se DOWN. Verifique cabeamento, operadora ou failover WAN.`,
        metricValue: 'DOWN',
        interfaceName: iface.name,
      });
      continue;
    }

    const totalMbps = Number((iface.rxMbps + iface.txMbps).toFixed(1));
    const pctExceeded = iface.utilizationPercent >= settings.bandwidthUtilizationLimitPercent;
    const mbpsExceeded =
      settings.bandwidthMbpsLimit > 0 && totalMbps >= settings.bandwidthMbpsLimit;

    if (pctExceeded || mbpsExceeded) {
      const reasons: string[] = [];
      if (pctExceeded) {
        reasons.push(
          `utilização de ${iface.utilizationPercent.toFixed(1)}% (limite: ${settings.bandwidthUtilizationLimitPercent}%)`
        );
      }
      if (mbpsExceeded) {
        reasons.push(
          `vazão total de ${totalMbps} Mbps (limite: ${settings.bandwidthMbpsLimit} Mbps)`
        );
      }

      const isCriticalSaturation =
        iface.utilizationPercent >= Math.min(95, settings.bandwidthUtilizationLimitPercent + 10);

      alerts.push({
        id: `bw-${iface.name}`,
        severity: isCriticalSaturation ? 'critical' : 'warning',
        category: 'bandwidth',
        title: `Uso de banda acima do limite em ${iface.name} (${iface.zone})`,
        description: `Interface ${iface.name} (${iface.ip}) registrou ${reasons.join(' e ')} — Download ${iface.rxMbps.toFixed(1)} Mbps / Upload ${iface.txMbps.toFixed(1)} Mbps (link ${iface.linkSpeedMbps} Mbps).`,
        metricValue: `${iface.utilizationPercent.toFixed(1)}% · ${totalMbps} Mbps`,
        interfaceName: iface.name,
      });
    }
  }

  // 1b. VPN, licenças, recursos do appliance e saúde da coleta
  if (settings.alertOnVpnDown) {
    for (const vpn of telemetry.vpns) {
      if (vpn.status === 'down') {
        alerts.push({
          id: `vpn-down-${vpn.name}`,
          severity: 'warning',
          category: 'vpn',
          title: `Túnel VPN fora do ar: ${vpn.name}`,
          description: `O túnel ${vpn.type === 'ipsec' ? 'IPsec' : 'SSL VPN'} "${vpn.name}" (peer ${vpn.peer}) está DOWN na última coleta do ${vendorLabel}.`,
          metricValue: 'DOWN',
          aiPrompt: `O túnel VPN "${vpn.name}" (peer ${vpn.peer}) do ${vendorLabel} está down. Quais são as causas mais comuns e como diagnosticar pelos logs?`,
        });
      }
    }
  }

  if (settings.alertOnLicense) {
    for (const lic of telemetry.licenses) {
      const expMs = lic.expiresAt ? Date.parse(lic.expiresAt) : Number.NaN;
      const daysLeft = Number.isFinite(expMs) ? Math.floor((expMs - nowMs) / 86400000) : null;
      const expired = lic.status === 'expired' || (daysLeft !== null && daysLeft < 0);
      const expiring = lic.status === 'expiring' || (daysLeft !== null && daysLeft <= 30);
      if (!expired && !expiring) continue;
      alerts.push({
        id: `license-${lic.service}`,
        severity: expired || (daysLeft !== null && daysLeft <= 7) ? 'critical' : 'warning',
        category: 'license',
        title: expired
          ? `Licença expirada: ${lic.service}`
          : `Licença perto do vencimento: ${lic.service}`,
        description: expired
          ? `O serviço ${lic.service} está sem licença válida${lic.expiresAt ? ` (venceu em ${lic.expiresAt})` : ''}. A proteção correspondente pode estar inativa.`
          : `O serviço ${lic.service} vence${daysLeft !== null ? ` em ${daysLeft} dia(s)` : ' em breve'}${lic.expiresAt ? ` (${lic.expiresAt})` : ''}.`,
        metricValue: expired ? 'EXPIRADA' : daysLeft !== null ? `${daysLeft} dia(s)` : 'VENCENDO',
      });
    }
  }

  const ap = ctx.appliance;
  if (ap) {
    if (settings.cpuLimitPercent > 0 && typeof ap.cpuPercent === 'number' && ap.cpuPercent >= settings.cpuLimitPercent) {
      alerts.push({
        id: 'resource-cpu',
        severity: ap.cpuPercent >= 97 ? 'critical' : 'warning',
        category: 'resource',
        title: `CPU do ${vendorLabel} em ${ap.cpuPercent}%`,
        description: `Uso de CPU em ${ap.cpuPercent}% na última coleta (limite: ${settings.cpuLimitPercent}%). CPU saturada causa perda de pacotes e lentidão na inspeção.`,
        metricValue: `${ap.cpuPercent}% CPU`,
      });
    }
    if (settings.memoryLimitPercent > 0 && typeof ap.memoryPercent === 'number' && ap.memoryPercent >= settings.memoryLimitPercent) {
      alerts.push({
        id: 'resource-memory',
        severity: ap.memoryPercent >= 97 ? 'critical' : 'warning',
        category: 'resource',
        title: `Memória do ${vendorLabel} em ${ap.memoryPercent}%`,
        description: `Uso de memória em ${ap.memoryPercent}% na última coleta (limite: ${settings.memoryLimitPercent}%).`,
        metricValue: `${ap.memoryPercent}% RAM`,
      });
    }
    if (
      typeof ap.activeConnections === 'number' &&
      typeof ap.maxConnections === 'number' &&
      ap.maxConnections > 0 &&
      ap.activeConnections / ap.maxConnections >= 0.9
    ) {
      const pct = Math.round((ap.activeConnections / ap.maxConnections) * 100);
      alerts.push({
        id: 'resource-connections',
        severity: pct >= 97 ? 'critical' : 'warning',
        category: 'resource',
        title: `Tabela de conexões em ${pct}% da capacidade`,
        description: `${ap.activeConnections.toLocaleString('pt-BR')} de ${ap.maxConnections.toLocaleString('pt-BR')} conexões em uso. Ao esgotar, novas conexões são recusadas.`,
        metricValue: `${pct}% conexões`,
      });
    }
  }

  if ((ctx.consecutiveSyncFailures ?? 0) >= 3) {
    alerts.push({
      id: 'collector-sync-failed',
      severity: 'critical',
      category: 'collector',
      title: `Sem acesso à API do ${vendorLabel}`,
      description: `${ctx.consecutiveSyncFailures} tentativas seguidas de sincronização falharam. Último erro: ${ctx.lastSyncError || 'desconhecido'}. O firewall pode estar inacessível ou a credencial foi alterada.`,
      metricValue: `${ctx.consecutiveSyncFailures} falhas`,
    });
  }

  if (
    settings.silenceMinutes > 0 &&
    ctx.udpRunning &&
    typeof ctx.lastEventAtMs === 'number' &&
    nowMs - ctx.lastEventAtMs >= settings.silenceMinutes * 60 * 1000
  ) {
    const silentMin = Math.floor((nowMs - ctx.lastEventAtMs) / 60000);
    alerts.push({
      id: 'collector-silent',
      severity: 'critical',
      category: 'collector',
      title: `${vendorLabel} parou de enviar syslogs`,
      description: `Nenhum evento recebido há ${silentMin} minuto(s) (limite: ${settings.silenceMinutes} min). Verifique o firewall, a rota até o coletor e a configuração de syslog.`,
      metricValue: `${silentMin} min sem logs`,
      lastSeenAt: new Date(ctx.lastEventAtMs).toISOString(),
    });
  }

  if (settings.alertOnConfigChange && ctx.configChanges) {
    for (const change of ctx.configChanges) {
      const atMs = Date.parse(change.at);
      if (!Number.isFinite(atMs) || nowMs - atMs > 24 * 60 * 60 * 1000) continue;
      const parts: string[] = [];
      const rulesDelta = change.rulesAdded + change.rulesRemoved + change.rulesModified;
      const natsDelta = change.natsAdded + change.natsRemoved + change.natsModified;
      if (rulesDelta > 0) {
        parts.push(`regras: +${change.rulesAdded} / -${change.rulesRemoved} / ${change.rulesModified} alterada(s)`);
      }
      if (natsDelta > 0) {
        parts.push(`NAT: +${change.natsAdded} / -${change.natsRemoved} / ${change.natsModified} alterada(s)`);
      }
      alerts.push({
        id: `config-change-${change.at}`,
        severity: 'warning',
        category: 'config-change',
        title: `Configuração do ${vendorLabel} foi alterada`,
        description: `Mudança detectada na sincronização de ${change.at} — ${parts.join('; ')}. ${change.details.slice(0, 5).join(' · ')}`,
        metricValue: `${rulesDelta + natsDelta} mudança(s)`,
        lastSeenAt: change.at,
      });
    }
  }

  // 2. Syslog volume limits (janela deslizante)
  if (syslogs.length > 0) {
    let totalBytes = 0;
    let blockedCount = 0;
    let loginFailures = 0;
    let lastLoginFailure: SyslogEvent | null = null;
    const loginFailureSources = new Map<string, number>();
    const bytesByIp = new Map<string, { bytes: number; zone: string; lastSeenAt: string }>();

    for (const ev of syslogs) {
      const isBlocked = ev.action === 'drop' || ev.action === 'deny' || ev.action === 'reset';
      if (isBlocked) blockedCount += 1;

      if (isAdminLoginFailure(ev)) {
        loginFailures += 1;
        if (!lastLoginFailure) lastLoginFailure = ev;
        if (ev.srcIp && ev.srcIp !== '-') {
          loginFailureSources.set(ev.srcIp, (loginFailureSources.get(ev.srcIp) || 0) + 1);
        }
      }

      const evBytes = Math.max(0, Number(ev.bytesSent || 0)) + Math.max(0, Number(ev.bytesRcvd || 0));
      totalBytes += evBytes;
      if (evBytes > 0 && ev.srcIp && ev.srcIp !== '-' && ev.srcIp !== '0.0.0.0') {
        const ipStats = bytesByIp.get(ev.srcIp) || {
          bytes: 0,
          zone: ev.srcZone,
          lastSeenAt: ev.timestamp,
        };
        ipStats.bytes += evBytes;
        if (ev.timestamp > ipStats.lastSeenAt) ipStats.lastSeenAt = ev.timestamp;
        bytesByIp.set(ev.srcIp, ipStats);
      }
    }

    // Taxa por hora: usa os agregados do coletor quando disponíveis (não dependem da janela em memória)
    const hourMs = 60 * 60 * 1000;
    const currentHourStart = Math.floor(nowMs / hourMs) * hourMs;
    const hourly = ctx.hourly || [];
    const lastHourCount = hourly.length > 0
      ? Math.max(
          hourly.find((h) => h.startMs === currentHourStart)?.total ?? 0,
          hourly.find((h) => h.startMs === currentHourStart - hourMs)?.total ?? 0
        )
      : syslogs.length;

    if (settings.hourlyLogVolumeLimit > 0 && lastHourCount >= settings.hourlyLogVolumeLimit) {
      const isSevere = lastHourCount >= Math.ceil(settings.hourlyLogVolumeLimit * 1.5);
      alerts.push({
        id: 'volume-hourly',
        severity: isSevere ? 'critical' : 'warning',
        category: 'traffic-volume',
        title: 'Taxa de logs por hora excedeu o limite',
        description: `O ${vendorLabel} registrou ${lastHourCount.toLocaleString('pt-BR')} evento(s) em uma hora, ultrapassando o limite configurado de ${settings.hourlyLogVolumeLimit.toLocaleString('pt-BR')} logs/hora.`,
        metricValue: `${lastHourCount.toLocaleString('pt-BR')} logs/h`,
        eventCount: lastHourCount,
        lastSeenAt: syslogs[0]?.timestamp,
        aiPrompt: `O ${vendorLabel} atingiu ${lastHourCount} syslogs em uma hora (limite ${settings.hourlyLogVolumeLimit}/h). Analise os logs recentes para identificar se é rajada legítima, loop de roteamento ou ataque.`,
      });
    }

    const totalMb = totalBytes / (1024 * 1024);
    if (settings.syslogTrafficMbLimit > 0 && totalMb >= settings.syslogTrafficMbLimit) {
      const topTalker = [...bytesByIp.entries()].sort((a, b) => b[1].bytes - a[1].bytes)[0];
      const topTalkerDesc = topTalker
        ? ` Maior origem: ${topTalker[0]} (${formatTrafficMb(topTalker[1].bytes)} MB na zona ${topTalker[1].zone}).`
        : '';
      const isSevere = totalMb >= settings.syslogTrafficMbLimit * 1.5;

      alerts.push({
        id: 'volume-bytes-total',
        severity: isSevere ? 'critical' : 'warning',
        category: 'traffic-volume',
        title: `Volume de dados em logs ultrapassou ${settings.syslogTrafficMbLimit} MB`,
        description: `O tráfego contabilizado nos syslogs somou ${formatTrafficMb(totalBytes)} MB nos últimos ${windowLabel} (limite: ${settings.syslogTrafficMbLimit} MB).${topTalkerDesc}`,
        metricValue: `${formatTrafficMb(totalBytes)} MB`,
        sourceIp: topTalker?.[0],
        lastSeenAt: topTalker?.[1].lastSeenAt,
        syslogFilterQuery: topTalker?.[0],
        aiPrompt: `O volume acumulado nos syslogs do ${vendorLabel} atingiu ${formatTrafficMb(totalBytes)} MB em ${windowLabel} (acima de ${settings.syslogTrafficMbLimit} MB).${topTalkerDesc} Avalie se há exfiltração ou tráfego anômalo.`,
      });
    }

    // 3. Anomalias: pico frente à média das horas anteriores
    if (settings.anomalyDetectionEnabled && hourly.length > 0) {
      const previous = hourly.filter(
        (h) => h.startMs < currentHourStart - hourMs && h.startMs >= currentHourStart - 25 * hourMs && h.total > 0
      );
      const lastFullHour = hourly.find((h) => h.startMs === currentHourStart - hourMs)?.total ?? 0;
      const currentPartial = hourly.find((h) => h.startMs === currentHourStart)?.total ?? 0;
      const observed = Math.max(lastFullHour, currentPartial);
      if (previous.length >= 3 && observed >= 100) {
        const avg = previous.reduce((sum, h) => sum + h.total, 0) / previous.length;
        if (avg > 0 && observed >= avg * settings.anomalySpikeMultiplier) {
          const ratio = observed / avg;
          alerts.push({
            id: 'anomaly-spike',
            severity: ratio >= settings.anomalySpikeMultiplier * 1.5 ? 'critical' : 'warning',
            category: 'anomaly',
            title: `Anomalia de pico nos logs (${ratio.toFixed(1)}x a média)`,
            description: `Pico de ${observed.toLocaleString('pt-BR')} evento(s) em uma hora frente à média de ${avg.toFixed(0)} logs/h nas ${previous.length} horas anteriores (critério: ≥ ${settings.anomalySpikeMultiplier}x).`,
            metricValue: `${ratio.toFixed(1)}x média`,
            eventCount: observed,
            lastSeenAt: syslogs[0]?.timestamp,
            aiPrompt: `Detectamos uma anomalia estatística de ${ratio.toFixed(1)}x acima da média horária no ${vendorLabel} (${observed} eventos em uma hora). Investigue a causa raiz nos logs.`,
          });
        }
      }
    }

    if (settings.blockedTrafficRatioLimitPercent > 0 && syslogs.length >= 50) {
      const blockedPct = (blockedCount / syslogs.length) * 100;
      if (blockedPct >= settings.blockedTrafficRatioLimitPercent) {
        alerts.push({
          id: 'anomaly-blocked-ratio',
          severity:
            blockedPct >= Math.min(95, settings.blockedTrafficRatioLimitPercent + 20)
              ? 'critical'
              : 'warning',
          category: 'anomaly',
          title: `Anomalia: taxa elevada de tráfego bloqueado (${blockedPct.toFixed(1)}%)`,
          description: `${blockedCount.toLocaleString('pt-BR')} de ${syslogs.length.toLocaleString('pt-BR')} eventos (${blockedPct.toFixed(1)}%) dos últimos ${windowLabel} foram bloqueados/negados no ${vendorLabel}, superando o limiar de ${settings.blockedTrafficRatioLimitPercent}%.`,
          metricValue: `${blockedPct.toFixed(1)}% bloqueado`,
          eventCount: blockedCount,
          lastSeenAt: syslogs[0]?.timestamp,
          syslogFilterQuery: 'deny',
          aiPrompt: `${blockedPct.toFixed(1)}% dos syslogs recentes no ${vendorLabel} estão sendo bloqueados (${blockedCount}/${syslogs.length}). Isso indica bloqueio indevido de política ou onda de varreduras/ataques?`,
        });
      }
    }

    if (settings.adminLoginFailureThreshold > 0 && loginFailures >= settings.adminLoginFailureThreshold) {
      const topSrc = [...loginFailureSources.entries()].sort((a, b) => b[1] - a[1])[0];
      alerts.push({
        id: 'auth-login-failures',
        severity: loginFailures >= settings.adminLoginFailureThreshold * 4 ? 'critical' : 'warning',
        category: 'auth',
        title: `${loginFailures} falhas de login no ${vendorLabel}`,
        description: `${loginFailures} tentativa(s) de autenticação falharam nos últimos ${windowLabel}${topSrc ? `, principal origem ${topSrc[0]} (${topSrc[1]} tentativa(s))` : ''}. Última mensagem: "${lastLoginFailure?.message ?? ''}"`,
        metricValue: `${loginFailures} falha(s)`,
        sourceIp: topSrc?.[0],
        eventCount: loginFailures,
        lastSeenAt: lastLoginFailure?.timestamp,
        syslogFilterQuery: topSrc?.[0] || 'login',
        aiPrompt: `O ${vendorLabel} registrou ${loginFailures} falhas de login em ${windowLabel}${topSrc ? ` (origem principal ${topSrc[0]})` : ''}. É força bruta contra a gerência? O que devo bloquear ou restringir?`,
      });
    }

    if (settings.anomalyDetectionEnabled && settings.portScanUniquePortsThreshold >= 2) {
      const scanByIp = new Map<
        string,
        { ports: Set<number>; zone: string; count: number; lastSeenAt: string }
      >();

      for (const ev of syslogs) {
        if (!ev.srcIp || ev.srcIp === '-' || ev.srcIp === '0.0.0.0') continue;
        if (ev.dstPort === null) continue;
        const isBlockedOrIps =
          ev.action === 'drop' ||
          ev.action === 'deny' ||
          ev.action === 'reset' ||
          isIpsEvent(ev);
        if (!isBlockedOrIps) continue;

        const entry = scanByIp.get(ev.srcIp) || {
          ports: new Set<number>(),
          zone: ev.srcZone,
          count: 0,
          lastSeenAt: ev.timestamp,
        };
        entry.ports.add(ev.dstPort);
        entry.count += 1;
        if (ev.timestamp > entry.lastSeenAt) entry.lastSeenAt = ev.timestamp;
        scanByIp.set(ev.srcIp, entry);
      }

      const scanners = [...scanByIp.entries()]
        .filter(([, info]) => info.ports.size >= settings.portScanUniquePortsThreshold)
        .sort((a, b) => b[1].ports.size - a[1].ports.size)
        .slice(0, MAX_ALERTS_PER_GROUP);

      for (const [ip, info] of scanners) {
        scanFlaggedIps.add(ip);
        const sortedPorts = [...info.ports].sort((a, b) => a - b);
        const portsLabel = sortedPorts.slice(0, 6).join(', ');
        alerts.push({
          id: `anomaly-scan-${ip}`,
          severity:
            info.ports.size >= settings.portScanUniquePortsThreshold * 3 ? 'critical' : 'warning',
          category: 'anomaly',
          title: `Varredura multi-porta detectada (${ip})`,
          description: `A origem ${ip} (zona ${info.zone}) tentou alcançar ${info.ports.size} portas distintas bloqueadas (${portsLabel}${sortedPorts.length > 6 ? '...' : ''}) em ${info.count} evento(s) nos últimos ${windowLabel} (critério: ≥ ${settings.portScanUniquePortsThreshold} portas).`,
          metricValue: `${info.ports.size} portas únicas`,
          sourceIp: ip,
          eventCount: info.count,
          lastSeenAt: info.lastSeenAt,
          syslogFilterQuery: ip,
          aiPrompt: `O IP ${ip} (${info.zone}) sondou ${info.ports.size} portas distintas bloqueadas (${portsLabel}) no ${vendorLabel}. Avalie a necessidade de bloqueio definitivo ou quarentena.`,
        });
      }
    }
  }

  // 4. IPS / Malicious source alerts
  const ipsFlaggedIps = new Set<string>();
  const malwareFlaggedIds = new Set<string>();

  if (settings.alertOnIps) {
    const ipsGroups = new Map<
      string,
      {
        count: number;
        lastSeenAt: string;
        sampleMsg: string;
        ports: Set<string>;
        zone: string;
      }
    >();

    for (const ev of syslogs) {
      if (!isIpsEvent(ev)) continue;
      const ip = ev.srcIp && ev.srcIp !== '-' ? ev.srcIp : 'Desconhecida';
      ipsFlaggedIps.add(ip);
      const entry = ipsGroups.get(ip) || {
        count: 0,
        lastSeenAt: ev.timestamp,
        sampleMsg: ev.message,
        ports: new Set<string>(),
        zone: ev.srcZone,
      };
      entry.count += 1;
      if (ev.timestamp > entry.lastSeenAt) {
        entry.lastSeenAt = ev.timestamp;
        entry.sampleMsg = ev.message;
      }
      if (ev.dstPort !== null) {
        entry.ports.add(`${ev.protocol}/${ev.dstPort}`);
      }
      ipsGroups.set(ip, entry);
    }

    const topIps = [...ipsGroups.entries()]
      .sort((a, b) => b[1].count - a[1].count)
      .slice(0, MAX_ALERTS_PER_GROUP);
    for (const [ip, info] of topIps) {
      const portInfo =
        info.ports.size > 0 ? ` Portas alvo: ${[...info.ports].slice(0, 4).join(', ')}.` : '';
      alerts.push({
        id: `ips-${ip}`,
        severity: 'critical',
        category: 'ips',
        title: `Alerta IPS de origem maliciosa: ${ip}`,
        description: `${info.count} evento(s) IPS/IDS na zona ${info.zone}.${portInfo} Assinatura: "${info.sampleMsg}"`,
        metricValue: `${info.count} evento(s) IPS`,
        sourceIp: ip,
        eventCount: info.count,
        lastSeenAt: info.lastSeenAt,
        syslogFilterQuery: ip !== 'Desconhecida' ? ip : 'IPS',
        aiPrompt: `Analise o alerta de IPS envolvendo a origem maliciosa ${ip} (zona ${info.zone}, mensagem: "${info.sampleMsg}") e me diga o nível de risco real e quais medidas tomar no ${vendorLabel}.`,
      });
    }
  }

  // 5. Gateway AV / Malware & Critical system logs
  if (settings.alertOnCriticalLogs) {
    const criticalGroups = new Map<string, { ev: SyslogEvent; count: number }>();
    for (const ev of syslogs) {
      if (isMalwareEvent(ev)) {
        malwareFlaggedIds.add(ev.id);
        const target = ev.dstIp !== '-' ? ` → destino ${ev.dstIp}` : '';
        alerts.push({
          id: `malware-${ev.srcIp}-${ev.dstIp}-${ev.messageId}`,
          severity: 'critical',
          category: 'malware',
          title: `Ameaça Malware / Antivírus detectada (${ev.srcIp})`,
          description: `Origem ${ev.srcIp} (${ev.srcZone})${target} (${ev.dstZone}). Mensagem: "${ev.message}"`,
          metricValue: ev.severity.toUpperCase(),
          sourceIp: ev.srcIp !== '-' ? ev.srcIp : undefined,
          eventCount: 1,
          lastSeenAt: ev.timestamp,
          syslogFilterQuery: ev.srcIp !== '-' ? ev.srcIp : ev.message.slice(0, 24),
          aiPrompt: `Explique o alerta de malware/antivírus do ${vendorLabel}: "${ev.message}" com origem ${ev.srcIp} e destino ${ev.dstIp}. O tráfego foi contido ou exige varredura no host?`,
        });
        continue;
      }

      if (!isIpsEvent(ev) && isCriticalSystemEvent(ev)) {
        // Agrupa repetições da mesma mensagem em um único alerta
        const groupId = `crit-${ev.messageId}-${shortHash(ev.message.replace(/\d+/g, '#'))}`;
        const existing = criticalGroups.get(groupId);
        if (existing) {
          existing.count += 1;
        } else {
          criticalGroups.set(groupId, { ev, count: 1 });
        }
      }
    }

    const topCritical = [...criticalGroups.entries()]
      .sort((a, b) => b[1].count - a[1].count)
      .slice(0, MAX_ALERTS_PER_GROUP);
    for (const [groupId, { ev, count }] of topCritical) {
      alerts.push({
        id: groupId,
        severity: 'critical',
        category: 'critical-log',
        title: `Falha crítica registrada no ${vendorLabel} (pri=${ev.priority})`,
        description: `${ev.categoryName}: "${ev.message}" (${ev.srcIp} → ${ev.dstIp})${count > 1 ? ` — ${count} ocorrências nos últimos ${windowLabel}` : ''}`,
        metricValue: count > 1 ? `${count}x ${ev.severity.toUpperCase()}` : ev.severity.toUpperCase(),
        sourceIp: ev.srcIp !== '-' ? ev.srcIp : undefined,
        eventCount: count,
        lastSeenAt: ev.timestamp,
        syslogFilterQuery: ev.srcIp !== '-' ? ev.srcIp : ev.message.slice(0, 24),
        aiPrompt: `Analise esta falha crítica do ${vendorLabel}: [${ev.timestamp}] ${ev.message} (${ev.srcIp} -> ${ev.dstIp}) e recomende a correção.`,
      });
    }

    // 6. Suspicious repeated blocks / sensitive port probing
    const blockGroups = new Map<
      string,
      {
        count: number;
        sensitiveCount: number;
        ports: Set<string>;
        zone: string;
        lastSeenAt: string;
      }
    >();

    for (const ev of syslogs) {
      if (isIpsEvent(ev) || malwareFlaggedIds.has(ev.id)) continue;
      if (ev.action !== 'drop' && ev.action !== 'deny' && ev.action !== 'reset') continue;
      if (!ev.srcIp || ev.srcIp === '-' || ev.srcIp === '0.0.0.0') continue;
      if (ipsFlaggedIps.has(ev.srcIp) || scanFlaggedIps.has(ev.srcIp)) continue;

      const entry = blockGroups.get(ev.srcIp) || {
        count: 0,
        sensitiveCount: 0,
        ports: new Set<string>(),
        zone: ev.srcZone,
        lastSeenAt: ev.timestamp,
      };
      entry.count += 1;
      if (ev.dstPort !== null) {
        entry.ports.add(`${ev.protocol}/${ev.dstPort}`);
        if (SENSITIVE_PORTS.has(ev.dstPort)) {
          entry.sensitiveCount += 1;
        }
      }
      if (ev.timestamp > entry.lastSeenAt) {
        entry.lastSeenAt = ev.timestamp;
      }
      blockGroups.set(ev.srcIp, entry);
    }

    const sensitiveThreshold = Math.max(3, Math.ceil(settings.suspiciousBlockThreshold / 5));
    const suspects = [...blockGroups.entries()]
      .filter(
        ([, info]) =>
          info.count >= settings.suspiciousBlockThreshold || info.sensitiveCount >= sensitiveThreshold
      )
      .sort((a, b) => b[1].count - a[1].count)
      .slice(0, MAX_ALERTS_PER_GROUP);
    for (const [ip, info] of suspects) {
      {
        const portsLabel =
          info.ports.size > 0 ? [...info.ports].slice(0, 5).join(', ') : 'diversas';
        const isHighRepeat = info.count >= settings.suspiciousBlockThreshold * 4;
        alerts.push({
          id: `susp-${ip}`,
          severity: isHighRepeat ? 'critical' : 'warning',
          category: 'suspicious-traffic',
          title: `Logs suspeitos e varredura bloqueada de ${ip}`,
          description: `${info.count} bloqueio(s) nos últimos ${windowLabel} a partir da zona ${info.zone} (${info.sensitiveCount} em portas sensíveis) visando ${portsLabel}.`,
          metricValue: `${info.count} bloqueio(s)`,
          sourceIp: ip,
          eventCount: info.count,
          lastSeenAt: info.lastSeenAt,
          syslogFilterQuery: ip,
          aiPrompt: `O IP ${ip} (zona ${info.zone}) acumulou ${info.count} bloqueios mirando portas ${portsLabel} no ${vendorLabel}. Isso caracteriza port scan, força bruta ou tráfego benigno?`,
        });
      }
    }
  }

  // Deduplicate by ID and sort by severity then category priority
  const deduped = new Map<string, OverviewAlert>();
  for (const a of alerts) {
    if (!deduped.has(a.id)) {
      deduped.set(a.id, a);
    }
  }

  const categoryPriority: Record<OverviewAlert['category'], number> = {
    'link-down': 0,
    collector: 1,
    resource: 2,
    bandwidth: 3,
    vpn: 4,
    license: 5,
    'traffic-volume': 6,
    anomaly: 7,
    auth: 8,
    ips: 9,
    malware: 10,
    'critical-log': 11,
    'config-change': 12,
    'suspicious-traffic': 13,
  };

  return [...deduped.values()]
    .sort((a, b) => {
      if (a.severity !== b.severity) return a.severity === 'critical' ? -1 : 1;
      return categoryPriority[a.category] - categoryPriority[b.category];
    })
    .slice(0, MAX_ALERTS_TOTAL);
}
