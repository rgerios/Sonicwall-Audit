import type {
  AlertSettings,
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
  blockedTrafficRatioLimitPercent: 45,
  anomalyDetectionEnabled: true,
  anomalySpikeMultiplier: 2.5,
  portScanUniquePortsThreshold: 3,
  alertOnIps: true,
  alertOnCriticalLogs: true,
  suspiciousBlockThreshold: 2,
};

export function normalizeAlertSettings(raw?: Partial<AlertSettings> | null): AlertSettings {
  const pct = Number(raw?.bandwidthUtilizationLimitPercent);
  const mbps = Number(raw?.bandwidthMbpsLimit);
  const hourlyLogs = Number(raw?.hourlyLogVolumeLimit);
  const trafficMb = Number(raw?.syslogTrafficMbLimit);
  const blockedRatio = Number(raw?.blockedTrafficRatioLimitPercent);
  const spikeMult = Number(raw?.anomalySpikeMultiplier);
  const portScanThresh = Number(raw?.portScanUniquePortsThreshold);
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
    hourlyLogVolumeLimit:
      Number.isFinite(hourlyLogs) && hourlyLogs >= 0 && hourlyLogs <= 500000
        ? Math.round(hourlyLogs)
        : DEFAULT_ALERT_SETTINGS.hourlyLogVolumeLimit,
    syslogTrafficMbLimit:
      Number.isFinite(trafficMb) && trafficMb >= 0 && trafficMb <= 1000000
        ? Number(trafficMb.toFixed(2))
        : DEFAULT_ALERT_SETTINGS.syslogTrafficMbLimit,
    blockedTrafficRatioLimitPercent:
      Number.isFinite(blockedRatio) && (blockedRatio === 0 || (blockedRatio >= 5 && blockedRatio <= 100))
        ? Math.round(blockedRatio)
        : DEFAULT_ALERT_SETTINGS.blockedTrafficRatioLimitPercent,
    anomalyDetectionEnabled: raw?.anomalyDetectionEnabled !== false,
    anomalySpikeMultiplier:
      Number.isFinite(spikeMult) && spikeMult >= 1.2 && spikeMult <= 20
        ? Number(spikeMult.toFixed(1))
        : DEFAULT_ALERT_SETTINGS.anomalySpikeMultiplier,
    portScanUniquePortsThreshold:
      Number.isFinite(portScanThresh) &&
      (portScanThresh === 0 || (portScanThresh >= 2 && portScanThresh <= 100))
        ? Math.round(portScanThresh)
        : DEFAULT_ALERT_SETTINGS.portScanUniquePortsThreshold,
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

function getHourBucketKey(ev: SyslogEvent): { key: string; label: string } {
  const raw = (ev.timestamp || '').trim();
  const match = /^(\d{4}-\d{2}-\d{2})\s+(\d{2})/.exec(raw);
  if (match) {
    return {
      key: `${match[1]} ${match[2]}:00`,
      label: `${match[1].slice(5)} ${match[2]}h`,
    };
  }
  const parsedMs = Date.parse(ev.ingestedAt || raw);
  const d = Number.isFinite(parsedMs) ? new Date(parsedMs) : new Date();
  const pad = (n: number) => String(n).padStart(2, '0');
  const key = `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:00`;
  const label = `${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}h`;
  return { key, label };
}

function formatTrafficMb(bytes: number): string {
  const mb = bytes / (1024 * 1024);
  return mb >= 100 ? mb.toFixed(0) : mb >= 10 ? mb.toFixed(1) : mb.toFixed(2);
}

const SENSITIVE_PORTS = new Set([21, 22, 23, 445, 1433, 3306, 3389, 5432, 5900]);

export function evaluateOverviewAlerts(
  telemetry: TelemetrySnapshot,
  syslogs: SyslogEvent[],
  settings: AlertSettings,
  vendor: FirewallVendor = 'sonicwall'
): OverviewAlert[] {
  const alerts: OverviewAlert[] = [];
  const vendorLabel = vendor === 'fortigate' ? 'FortiGate' : 'SonicWall';

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

  // 2. Syslog Traffic Volume Limits (Hourly log count & transferred MB)
  if (syslogs.length > 0) {
    const hourBuckets = new Map<
      string,
      { count: number; blocked: number; label: string; lastSeenAt: string }
    >();
    let totalBytes = 0;
    const bytesByIp = new Map<string, { bytes: number; zone: string; lastSeenAt: string }>();

    for (const ev of syslogs) {
      const bucketInfo = getHourBucketKey(ev);
      const isBlocked = ev.action === 'drop' || ev.action === 'deny' || ev.action === 'reset';
      const entry = hourBuckets.get(bucketInfo.key) || {
        count: 0,
        blocked: 0,
        label: bucketInfo.label,
        lastSeenAt: ev.timestamp,
      };
      entry.count += 1;
      if (isBlocked) entry.blocked += 1;
      if (ev.timestamp > entry.lastSeenAt) entry.lastSeenAt = ev.timestamp;
      hourBuckets.set(bucketInfo.key, entry);

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

    const sortedHours = [...hourBuckets.entries()].sort((a, b) => b[1].count - a[1].count);
    const peakHour = sortedHours[0];

    if (settings.hourlyLogVolumeLimit > 0 && peakHour && peakHour[1].count >= settings.hourlyLogVolumeLimit) {
      const peakCount = peakHour[1].count;
      const isSevere = peakCount >= Math.ceil(settings.hourlyLogVolumeLimit * 1.5);
      alerts.push({
        id: `volume-hourly-${peakHour[0]}`,
        severity: isSevere ? 'critical' : 'warning',
        category: 'traffic-volume',
        title: `Taxa de logs por hora excedeu o limite (${peakHour[1].label})`,
        description: `O ${vendorLabel} registrou ${peakCount.toLocaleString('pt-BR')} evento(s) na janela de ${peakHour[1].label}, ultrapassando o limite configurado de ${settings.hourlyLogVolumeLimit.toLocaleString('pt-BR')} logs/hora.`,
        metricValue: `${peakCount.toLocaleString('pt-BR')} logs/h`,
        eventCount: peakCount,
        lastSeenAt: peakHour[1].lastSeenAt,
        aiPrompt: `O ${vendorLabel} atingiu ${peakCount} syslogs na janela ${peakHour[1].label} (limite ${settings.hourlyLogVolumeLimit}/h). Analise os logs recentes para identificar se é rajada legítima, loop de roteamento ou ataque.`,
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
        description: `O tráfego contabilizado nos syslogs somou ${formatTrafficMb(totalBytes)} MB na janela ativa (limite: ${settings.syslogTrafficMbLimit} MB).${topTalkerDesc}`,
        metricValue: `${formatTrafficMb(totalBytes)} MB`,
        sourceIp: topTalker?.[0],
        lastSeenAt: topTalker?.[1].lastSeenAt,
        syslogFilterQuery: topTalker?.[0],
        aiPrompt: `O volume acumulado nos syslogs do ${vendorLabel} atingiu ${formatTrafficMb(totalBytes)} MB (acima de ${settings.syslogTrafficMbLimit} MB).${topTalkerDesc} Avalie se há exfiltração ou tráfego anômalo.`,
      });
    }

    // 3. Log Anomaly Detection (Spike, Abnormal Block Ratio, Multi-port Scan)
    if (settings.anomalyDetectionEnabled && sortedHours.length >= 3 && peakHour && peakHour[1].count >= 6) {
      const otherHours = sortedHours.slice(1);
      const otherAvg =
        otherHours.reduce((sum, item) => sum + item[1].count, 0) / Math.max(1, otherHours.length);
      if (otherAvg > 0 && peakHour[1].count >= otherAvg * settings.anomalySpikeMultiplier) {
        const ratio = peakHour[1].count / otherAvg;
        alerts.push({
          id: `anomaly-spike-${peakHour[0]}`,
          severity: ratio >= settings.anomalySpikeMultiplier * 1.5 ? 'critical' : 'warning',
          category: 'anomaly',
          title: `Anomalia de pico nos logs em ${peakHour[1].label} (${ratio.toFixed(1)}x)`,
          description: `Pico estatístico de ${peakHour[1].count.toLocaleString('pt-BR')} evento(s) frente à média horária de ${otherAvg.toFixed(1)} logs/h nas demais janelas (critério: ≥ ${settings.anomalySpikeMultiplier}x).`,
          metricValue: `${ratio.toFixed(1)}x média`,
          eventCount: peakHour[1].count,
          lastSeenAt: peakHour[1].lastSeenAt,
          aiPrompt: `Detectamos uma anomalia estatística de ${ratio.toFixed(1)}x acima da média no ${vendorLabel} em ${peakHour[1].label} (${peakHour[1].count} eventos). Investigue a causa raiz nos logs.`,
        });
      }
    }

    if (settings.blockedTrafficRatioLimitPercent > 0 && syslogs.length >= 8) {
      const blockedCount = syslogs.filter(
        (ev) => ev.action === 'drop' || ev.action === 'deny' || ev.action === 'reset'
      ).length;
      const blockedPct = (blockedCount / syslogs.length) * 100;
      if (blockedPct >= settings.blockedTrafficRatioLimitPercent) {
        alerts.push({
          id: 'anomaly-blocked-ratio',
          severity:
            blockedPct >= Math.min(90, settings.blockedTrafficRatioLimitPercent + 20)
              ? 'critical'
              : 'warning',
          category: 'anomaly',
          title: `Anomalia: taxa elevada de tráfego bloqueado (${blockedPct.toFixed(1)}%)`,
          description: `${blockedCount.toLocaleString('pt-BR')} de ${syslogs.length.toLocaleString('pt-BR')} eventos (${blockedPct.toFixed(1)}%) foram bloqueados/negados no ${vendorLabel}, superando o limiar de ${settings.blockedTrafficRatioLimitPercent}%.`,
          metricValue: `${blockedPct.toFixed(1)}% bloqueado`,
          eventCount: blockedCount,
          lastSeenAt: syslogs[0]?.timestamp,
          syslogFilterQuery: 'deny',
          aiPrompt: `${blockedPct.toFixed(1)}% dos syslogs no ${vendorLabel} estão sendo bloqueados (${blockedCount}/${syslogs.length}). Isso indica bloqueio indevido de política ou onda de varreduras/ataques?`,
        });
      }
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

      for (const [ip, info] of scanByIp.entries()) {
        if (info.ports.size >= settings.portScanUniquePortsThreshold) {
          const sortedPorts = [...info.ports].sort((a, b) => a - b);
          const portsLabel = sortedPorts.slice(0, 6).join(', ');
          alerts.push({
            id: `anomaly-scan-${ip}`,
            severity:
              info.ports.size >= settings.portScanUniquePortsThreshold + 2 ? 'critical' : 'warning',
            category: 'anomaly',
            title: `Anomalia de varredura multi-porta detectada (${ip})`,
            description: `A origem ${ip} (zona ${info.zone}) tentou alcançar ${info.ports.size} portas distintas bloqueadas (${portsLabel}${sortedPorts.length > 6 ? '...' : ''}) em ${info.count} evento(s) (critério: ≥ ${settings.portScanUniquePortsThreshold} portas).`,
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

    for (const [ip, info] of ipsGroups.entries()) {
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
        alerts.push({
          id: `crit-${ev.id}`,
          severity: 'critical',
          category: 'critical-log',
          title: `Falha crítica registrada no ${vendorLabel} (pri=${ev.priority})`,
          description: `${ev.categoryName}: "${ev.message}" (${ev.srcIp} → ${ev.dstIp})`,
          metricValue: ev.severity.toUpperCase(),
          sourceIp: ev.srcIp !== '-' ? ev.srcIp : undefined,
          eventCount: 1,
          lastSeenAt: ev.timestamp,
          syslogFilterQuery: ev.srcIp !== '-' ? ev.srcIp : ev.message.slice(0, 24),
          aiPrompt: `Analise esta falha crítica do ${vendorLabel}: [${ev.timestamp}] ${ev.message} (${ev.srcIp} -> ${ev.dstIp}) e recomende a correção.`,
        });
      }
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
        const portsLabel =
          info.ports.size > 0 ? [...info.ports].slice(0, 5).join(', ') : 'diversas';
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
    bandwidth: 1,
    'traffic-volume': 2,
    anomaly: 3,
    ips: 4,
    malware: 5,
    'critical-log': 6,
    'suspicious-traffic': 7,
  };

  return [...deduped.values()]
    .sort((a, b) => {
      if (a.severity !== b.severity) return a.severity === 'critical' ? -1 : 1;
      return categoryPriority[a.category] - categoryPriority[b.category];
    })
    .slice(0, 30);
}
