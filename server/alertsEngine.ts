import type {
  AlertSettings,
  OverviewAlert,
  SyslogEvent,
  TelemetrySnapshot,
} from './types.ts';

export const DEFAULT_ALERT_SETTINGS: AlertSettings = {
  bandwidthUtilizationLimitPercent: 80,
  bandwidthMbpsLimit: 0,
  alertOnIps: true,
  alertOnCriticalLogs: true,
  suspiciousBlockThreshold: 2,
};

export function normalizeAlertSettings(raw?: Partial<AlertSettings> | null): AlertSettings {
  const pct = Number(raw?.bandwidthUtilizationLimitPercent);
  const mbps = Number(raw?.bandwidthMbpsLimit);
  const blockThresh = Number(raw?.suspiciousBlockThreshold);

  return {
    bandwidthUtilizationLimitPercent:
      Number.isFinite(pct) && pct >= 5 && pct <= 100
        ? Math.round(pct)
        : DEFAULT_ALERT_SETTINGS.bandwidthUtilizationLimitPercent,
    bandwidthMbpsLimit:
      Number.isFinite(mbps) && mbps >= 0 && mbps <= 100000
        ? Math.round(mbps)
        : DEFAULT_ALERT_SETTINGS.bandwidthMbpsLimit,
    alertOnIps: raw?.alertOnIps !== false,
    alertOnCriticalLogs: raw?.alertOnCriticalLogs !== false,
    suspiciousBlockThreshold:
      Number.isFinite(blockThresh) && blockThresh >= 1 && blockThresh <= 100
        ? Math.round(blockThresh)
        : DEFAULT_ALERT_SETTINGS.suspiciousBlockThreshold,
  };
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

const SENSITIVE_PORTS = new Set([21, 22, 23, 445, 1433, 3306, 3389, 5432, 5900]);

export function evaluateOverviewAlerts(
  telemetry: TelemetrySnapshot,
  syslogs: SyslogEvent[],
  settings: AlertSettings
): OverviewAlert[] {
  const alerts: OverviewAlert[] = [];

  // 1. Bandwidth threshold & link-down alerts
  for (const iface of telemetry.interfaces) {
    if (iface.linkStatus === 'down') {
      alerts.push({
        id: `link-down-${iface.name}`,
        severity: 'critical',
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
        iface.utilizationPercent >= Math.min(95, settings.bandwidthUtilizationLimitPercent + 10) ||
        iface.role === 'wan-primary';

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

  // 2. IPS / Malicious source alerts
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

    for (const [ip, info] of ipsGroups.entries()) {
      const portInfo = info.ports.size > 0 ? ` Portas alvo: ${[...info.ports].slice(0, 4).join(', ')}.` : '';
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
        aiPrompt: `Analise o alerta de IPS envolvendo a origem maliciosa ${ip} (zona ${info.zone}, mensagem: "${info.sampleMsg}") e me diga o nível de risco real e quais medidas tomar no SonicWall.`,
      });
    }
  }

  // 3. Gateway AV / Malware & Critical system logs
  if (settings.alertOnCriticalLogs) {
    for (const ev of syslogs) {
      if (isMalwareEvent(ev)) {
        malwareFlaggedIds.add(ev.id);
        const target = ev.dstIp !== '-' ? ` → destino ${ev.dstIp}` : '';
        alerts.push({
          id: `malware-${ev.srcIp}-${ev.dstIp}-${ev.messageId}`,
          severity: 'critical',
          category: 'malware',
          title: `Ameaça Malware / Gateway AV detectada (${ev.srcIp})`,
          description: `Origem ${ev.srcIp} (${ev.srcZone})${target} (${ev.dstZone}). Mensagem: "${ev.message}"`,
          metricValue: ev.severity.toUpperCase(),
          sourceIp: ev.srcIp !== '-' ? ev.srcIp : undefined,
          eventCount: 1,
          lastSeenAt: ev.timestamp,
          syslogFilterQuery: ev.srcIp !== '-' ? ev.srcIp : ev.message.slice(0, 24),
          aiPrompt: `Explique o alerta de malware/antivírus do SonicWall: "${ev.message}" com origem ${ev.srcIp} e destino ${ev.dstIp}. O tráfego foi contido ou exige varredura no host?`,
        });
        continue;
      }

      if (!isIpsEvent(ev) && isCriticalSystemEvent(ev)) {
        alerts.push({
          id: `crit-${ev.id}`,
          severity: 'critical',
          category: 'critical-log',
          title: `Falha crítica registrada no SonicWall (pri=${ev.priority})`,
          description: `${ev.categoryName}: "${ev.message}" (${ev.srcIp} → ${ev.dstIp})`,
          metricValue: ev.severity.toUpperCase(),
          sourceIp: ev.srcIp !== '-' ? ev.srcIp : undefined,
          eventCount: 1,
          lastSeenAt: ev.timestamp,
          syslogFilterQuery: ev.srcIp !== '-' ? ev.srcIp : ev.message.slice(0, 24),
          aiPrompt: `Analise esta falha crítica do SonicWall: [${ev.timestamp}] ${ev.message} (${ev.srcIp} -> ${ev.dstIp}) e recomende a correção.`,
        });
      }
    }

    // 4. Suspicious repeated blocks / sensitive port probing
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
      if (!ev.srcIp || ev.srcIp === '-') continue;
      if (ipsFlaggedIps.has(ev.srcIp)) continue;

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

    for (const [ip, info] of blockGroups.entries()) {
      if (info.count >= settings.suspiciousBlockThreshold || info.sensitiveCount > 0) {
        const portsLabel = info.ports.size > 0 ? [...info.ports].slice(0, 5).join(', ') : 'diversas';
        const isHighRepeat = info.count >= Math.max(5, settings.suspiciousBlockThreshold * 2);
        alerts.push({
          id: `susp-${ip}`,
          severity: isHighRepeat ? 'critical' : 'warning',
          category: 'suspicious-traffic',
          title: `Logs suspeitos e varredura bloqueada de ${ip}`,
          description: `${info.count} bloqueio(s) a partir da zona ${info.zone} visando portas sensíveis/serviços (${portsLabel}).`,
          metricValue: `${info.count} bloqueio(s)`,
          sourceIp: ip,
          eventCount: info.count,
          lastSeenAt: info.lastSeenAt,
          syslogFilterQuery: ip,
          aiPrompt: `O IP ${ip} (zona ${info.zone}) acumulou ${info.count} bloqueios mirando portas ${portsLabel}. Isso caracteriza port scan, força bruta ou tráfego benigno?`,
        });
      }
    }
  }

  // Deduplicate by ID and sort: critical first, then bandwidth/ips/malware/critical-log/suspicious
  const deduped = new Map<string, OverviewAlert>();
  for (const a of alerts) {
    if (!deduped.has(a.id)) {
      deduped.set(a.id, a);
    }
  }

  const categoryPriority: Record<OverviewAlert['category'], number> = {
    'link-down': 0,
    bandwidth: 1,
    ips: 2,
    malware: 3,
    'critical-log': 4,
    'suspicious-traffic': 5,
  };

  return [...deduped.values()]
    .sort((a, b) => {
      if (a.severity !== b.severity) return a.severity === 'critical' ? -1 : 1;
      return categoryPriority[a.category] - categoryPriority[b.category];
    })
    .slice(0, 25);
}
