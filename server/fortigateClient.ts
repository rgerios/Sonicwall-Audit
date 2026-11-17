import http from 'node:http';
import https from 'node:https';
import {
  asRecord,
  formatUptimeSeconds,
  getTransportAgent,
  pickNumber as pickNum,
  pickString as pickStr,
} from './clientUtils.ts';
import type {
  FirewallRule,
  InterfaceTelemetry,
  NatPolicy,
  SecurityServiceLicense,
  TelemetrySnapshot,
  VpnTunnelStatus,
} from './types.ts';

export interface FortiOsConnectParams {
  host: string;
  port: number;
  protocol: 'https' | 'http';
  token: string;
  vdom?: string;
  ignoreTlsErrors: boolean;
}

export interface FortiOsAuditResult {
  rules: FirewallRule[];
  nats: NatPolicy[];
  model: string;
  firmware: string;
  serialNumber: string;
  uptimeFormatted?: string;
  uptimeSeconds?: number;
  cpuPercent?: number | null;
  memoryPercent?: number | null;
  activeConnections?: number | null;
  maxConnections?: number | null;
  haRole?: string;
  telemetry: TelemetrySnapshot;
}

function asArray(val: unknown): Array<Record<string, unknown>> {
  if (Array.isArray(val)) {
    return val.filter((item): item is Record<string, unknown> => Boolean(item && typeof item === 'object'));
  }
  const rec = asRecord(val);
  if (Array.isArray(rec.results)) {
    return rec.results.filter((item): item is Record<string, unknown> =>
      Boolean(item && typeof item === 'object')
    );
  }
  return [];
}

function joinNames(raw: unknown): string {
  if (Array.isArray(raw)) {
    const names = raw
      .map((item) => {
        if (typeof item === 'string') return item;
        const rec = asRecord(item);
        return pickStr(rec, ['name', 'q_origin_key']);
      })
      .filter(Boolean);
    return names.length > 0 ? names.join(', ') : 'all';
  }
  if (typeof raw === 'string' && raw.trim()) return raw.trim();
  return 'all';
}

async function requestFortiOs(
  baseUrl: string,
  pathWithQuery: string,
  token: string,
  ignoreTlsErrors: boolean
): Promise<{ status: number; data: unknown }> {
  const url = new URL(pathWithQuery, baseUrl);
  const isHttps = url.protocol === 'https:';
  const transport = isHttps ? https : http;
  const agent = getTransportAgent(isHttps, ignoreTlsErrors);

  return new Promise((resolve, reject) => {
    const req = transport.request(
      url,
      {
        method: 'GET',
        headers: {
          Accept: 'application/json',
          Authorization: `Bearer ${token}`,
        },
        agent,
        timeout: 10000,
      },
      (res) => {
        let raw = '';
        res.on('data', (chunk) => {
          raw += chunk.toString();
        });
        res.on('end', () => {
          let parsed: unknown = raw;
          try {
            parsed = raw ? JSON.parse(raw) : {};
          } catch {
            // Keep raw response if not JSON
          }
          resolve({ status: res.statusCode || 500, data: parsed });
        });
      }
    );

    req.on('timeout', () => {
      req.destroy(new Error(`Timeout ao conectar no FortiGate ${url.hostname}:${url.port} (10s)`));
    });
    req.on('error', reject);
    req.end();
  });
}

export async function fetchFortiOsAudit(
  params: FortiOsConnectParams
): Promise<FortiOsAuditResult> {
  const cleanHost = params.host.replace(/^https?:\/\//i, '').replace(/\/+$/, '');
  const baseUrl = `${params.protocol}://${cleanHost}:${params.port}`;
  const vdom = (params.vdom || 'root').trim() || 'root';
  const vdomQuery = `vdom=${encodeURIComponent(vdom)}`;

  const statusRes = await requestFortiOs(
    baseUrl,
    `/api/v2/monitor/system/status?${vdomQuery}`,
    params.token,
    params.ignoreTlsErrors
  );

  if (statusRes.status === 401 || statusRes.status === 403) {
    throw new Error(
      'Token da API FortiOS recusado (401/403). Verifique o REST API Admin Token, perfil de leitura e Trusted Hosts.'
    );
  }
  if (statusRes.status >= 400) {
    throw new Error(`Falha ao consultar FortiOS REST API (HTTP ${statusRes.status}).`);
  }

  const statusRoot = asRecord(statusRes.data);
  const statusResults = asRecord(statusRoot.results || statusRoot);
  const model =
    pickStr(statusResults, ['model_name', 'model', 'platform_type']) || 'FortiGate Appliance';
  const serialNumber =
    pickStr(statusRoot, ['serial']) || pickStr(statusResults, ['serial', 'hostname']) || '-';
  const versionStr = pickStr(statusRoot, ['version']) || pickStr(statusResults, ['version']);
  const buildNum = pickNum(statusRoot, ['build']) ?? pickNum(statusResults, ['build']);
  const firmware = versionStr
    ? `${versionStr}${buildNum ? ` (build ${buildNum})` : ''}`
    : 'FortiOS REST API';

  const uptimeSeconds = pickNum(statusResults, ['uptime', 'system_uptime']) ?? undefined;
  const uptimeFormatted = uptimeSeconds ? formatUptimeSeconds(uptimeSeconds) : undefined;
  const haRole = pickStr(statusResults, ['ha_mode', 'ha_role']) || undefined;

  const [
    resourceRes,
    cmdbPolicyRes,
    monPolicyRes,
    vipRes,
    ippoolRes,
    snatRes,
    ifaceRes,
    vpnRes,
    licenseRes,
  ] = await Promise.allSettled([
    requestFortiOs(
      baseUrl,
      `/api/v2/monitor/system/resource/usage?${vdomQuery}`,
      params.token,
      params.ignoreTlsErrors
    ),
    requestFortiOs(
      baseUrl,
      `/api/v2/cmdb/firewall/policy?${vdomQuery}`,
      params.token,
      params.ignoreTlsErrors
    ),
    requestFortiOs(
      baseUrl,
      `/api/v2/monitor/firewall/policy?${vdomQuery}`,
      params.token,
      params.ignoreTlsErrors
    ),
    requestFortiOs(
      baseUrl,
      `/api/v2/cmdb/firewall/vip?${vdomQuery}`,
      params.token,
      params.ignoreTlsErrors
    ),
    requestFortiOs(
      baseUrl,
      `/api/v2/cmdb/firewall/ippool?${vdomQuery}`,
      params.token,
      params.ignoreTlsErrors
    ),
    requestFortiOs(
      baseUrl,
      `/api/v2/cmdb/firewall/central-snat-map?${vdomQuery}`,
      params.token,
      params.ignoreTlsErrors
    ),
    requestFortiOs(
      baseUrl,
      `/api/v2/monitor/system/interface?${vdomQuery}`,
      params.token,
      params.ignoreTlsErrors
    ),
    requestFortiOs(
      baseUrl,
      `/api/v2/monitor/vpn/ipsec?${vdomQuery}`,
      params.token,
      params.ignoreTlsErrors
    ),
    requestFortiOs(
      baseUrl,
      `/api/v2/monitor/license/status?${vdomQuery}`,
      params.token,
      params.ignoreTlsErrors
    ),
  ]);

  let cpuPercent: number | null = null;
  let memoryPercent: number | null = null;
  let activeConnections: number | null = null;
  let maxConnections: number | null = null;

  if (resourceRes.status === 'fulfilled' && resourceRes.value.status < 400) {
    const resRec = asRecord(asRecord(resourceRes.value.data).results);
    const cpuArr = asArray(resRec.cpu);
    const memArr = asArray(resRec.mem);
    const sessArr = asArray(resRec.session);
    cpuPercent =
      (cpuArr[0] ? pickNum(cpuArr[0], ['current', 'value']) : null) ??
      pickNum(resRec, ['cpu']);
    memoryPercent =
      (memArr[0] ? pickNum(memArr[0], ['current', 'value']) : null) ??
      pickNum(resRec, ['mem']);
    activeConnections =
      (sessArr[0] ? pickNum(sessArr[0], ['current', 'value']) : null) ??
      pickNum(resRec, ['session']);
  }

  // Merge CMDB policies with Monitor hit_count metrics
  const policyStatsMap = new Map<string, { hits: number; lastUsed: string | null }>();
  if (monPolicyRes.status === 'fulfilled' && monPolicyRes.value.status < 400) {
    for (const stat of asArray(monPolicyRes.value.data)) {
      const pid = String(stat.policyid ?? stat.id ?? '');
      if (!pid) continue;
      const hits = pickNum(stat, ['hit_count', 'hits', 'software_bytes', 'bytes']) ?? 0;
      const lastUsedSec = pickNum(stat, ['last_used']);
      const lastUsed =
        lastUsedSec && lastUsedSec > 0
          ? new Date(lastUsedSec * 1000).toISOString().replace('T', ' ').slice(0, 19)
          : null;
      policyStatsMap.set(pid, { hits, lastUsed });
    }
  }

  const rules: FirewallRule[] = [];
  const usedPools = new Set<string>();
  const usedVips = new Set<string>();

  if (cmdbPolicyRes.status === 'fulfilled' && cmdbPolicyRes.value.status < 400) {
    const rawPolicies = asArray(cmdbPolicyRes.value.data);
    rawPolicies.forEach((p, idx) => {
      const pid = String(p.policyid ?? p.id ?? idx + 1);
      const stat = policyStatsMap.get(pid);
      const enabled = pickStr(p, ['status']).toLowerCase() !== 'disable';
      const rawAction = pickStr(p, ['action']).toLowerCase();
      const action: FirewallRule['action'] =
        rawAction === 'accept' ? 'allow' : rawAction === 'deny' ? 'deny' : 'discard';

      const srcAddr = joinNames(p.srcaddr);
      const dstAddr = joinNames(p.dstaddr);
      const dstNames = asArray(p.dstaddr).map((d) => pickStr(d, ['name']));
      dstNames.forEach((n) => usedVips.add(n));
      if (Array.isArray(p.poolname)) {
        asArray(p.poolname).forEach((pl) => {
          const pname = pickStr(pl, ['name']);
          if (pname) usedPools.add(pname);
        });
      }

      const hits = stat?.hits ?? 0;
      rules.push({
        id: pid,
        uuid: pickStr(p, ['uuid']) || undefined,
        name: pickStr(p, ['name']) || `Policy #${pid}`,
        priority: idx + 1,
        fromZone: joinNames(p.srcintf),
        toZone: joinNames(p.dstintf),
        source: srcAddr,
        destination: dstAddr,
        service: joinNames(p.service),
        action,
        enabled,
        applianceHits: hits,
        syslogHits: 0,
        lastHitAt: stat?.lastUsed ?? null,
        comment: pickStr(p, ['comments']),
        status: !enabled ? 'disabled' : hits === 0 ? 'unused' : 'active',
        findingReason: !enabled
          ? 'Política desabilitada no FortiOS.'
          : hits === 0
            ? 'Zero hits no contador do FortiOS.'
            : 'Política ativa com tráfego registrado.',
        sourceOrigin: 'api',
      });
    });
  }

  const nats: NatPolicy[] = [];
  if (vipRes.status === 'fulfilled' && vipRes.value.status < 400) {
    asArray(vipRes.value.data).forEach((vip, idx) => {
      const name = pickStr(vip, ['name']) || `VIP-${idx + 1}`;
      const isReferenced = usedVips.has(name);
      nats.push({
        id: `VIP-${idx + 1}`,
        uuid: pickStr(vip, ['uuid']) || undefined,
        name,
        priority: idx + 1,
        inboundInterface: pickStr(vip, ['extintf']) || 'any',
        outboundInterface: 'internal',
        origSource: 'all',
        transSource: 'Original',
        origDestination: pickStr(vip, ['extip']) || '-',
        transDestination: pickStr(vip, ['mappedip']) || joinNames(vip.mappedip),
        origService: pickStr(vip, ['extport']) || 'any',
        transService: pickStr(vip, ['mappedport']) || 'Original',
        enabled: true,
        applianceHits: isReferenced ? 1 : 0,
        syslogHits: 0,
        lastHitAt: null,
        comment: pickStr(vip, ['comment']),
        status: isReferenced ? 'active' : 'orphaned',
        findingReason: isReferenced
          ? 'VIP referenciado em política ativa.'
          : 'VIP sem referência em nenhuma política de firewall.',
        sourceOrigin: 'api',
      });
    });
  }

  if (ippoolRes.status === 'fulfilled' && ippoolRes.value.status < 400) {
    asArray(ippoolRes.value.data).forEach((pool, idx) => {
      const name = pickStr(pool, ['name']) || `POOL-${idx + 1}`;
      const isReferenced = usedPools.has(name);
      const startIp = pickStr(pool, ['startip']);
      const endIp = pickStr(pool, ['endip']);
      const range = endIp && endIp !== startIp ? `${startIp}-${endIp}` : startIp || '-';
      nats.push({
        id: `POOL-${idx + 1}`,
        name,
        priority: nats.length + 1,
        inboundInterface: 'internal',
        outboundInterface: 'wan',
        origSource: 'LAN',
        transSource: range,
        origDestination: 'all',
        transDestination: 'Original',
        origService: 'ALL',
        transService: 'Original',
        enabled: true,
        applianceHits: isReferenced ? 1 : 0,
        syslogHits: 0,
        lastHitAt: null,
        comment: pickStr(pool, ['comments']),
        status: isReferenced ? 'active' : 'unused',
        findingReason: isReferenced
          ? 'IP Pool referenciado em política SNAT.'
          : 'IP Pool não utilizado em políticas de saída.',
        sourceOrigin: 'api',
      });
    });
  }

  if (snatRes.status === 'fulfilled' && snatRes.value.status < 400) {
    asArray(snatRes.value.data).forEach((snat, idx) => {
      const sid = String(snat.policyid ?? idx + 1);
      const enabled = pickStr(snat, ['status']).toLowerCase() !== 'disable';
      nats.push({
        id: `SNAT-${sid}`,
        name: `Central SNAT #${sid}`,
        priority: nats.length + 1,
        inboundInterface: joinNames(snat.srcintf),
        outboundInterface: joinNames(snat.dstintf),
        origSource: joinNames(snat.orig_addr),
        transSource: joinNames(snat.nat_ippool) || 'Interface IP',
        origDestination: joinNames(snat.dst_addr),
        transDestination: 'Original',
        origService: pickStr(snat, ['protocol']) || 'ALL',
        transService: 'Original',
        enabled,
        applianceHits: 0,
        syslogHits: 0,
        lastHitAt: null,
        comment: pickStr(snat, ['comments']),
        status: !enabled ? 'disabled' : 'unused',
        findingReason: !enabled ? 'Central SNAT desabilitada.' : 'Aguardando correlação via syslog.',
        sourceOrigin: 'api',
      });
    });
  }

  const interfaces: InterfaceTelemetry[] = [];
  if (ifaceRes.status === 'fulfilled' && ifaceRes.value.status < 400) {
    const rawIfaces = asRecord(asRecord(ifaceRes.value.data).results);
    for (const [ifName, rawVal] of Object.entries(rawIfaces)) {
      const rec = asRecord(rawVal);
      if (Object.keys(rec).length === 0) continue;
      const linkUp = rec.link === true || pickStr(rec, ['link']).toLowerCase() === 'up';
      const speed = pickNum(rec, ['speed']) ?? 1000;
      const rxBytes = pickNum(rec, ['rx_bytes']) ?? 0;
      const txBytes = pickNum(rec, ['tx_bytes']) ?? 0;
      const rxRateKbps = (pickNum(rec, ['rx_rate', 'rx_kbps']) ?? 0) / 1000;
      const txRateKbps = (pickNum(rec, ['tx_rate', 'tx_kbps']) ?? 0) / 1000;
      const rxMbps = Number(Math.max(0, rxRateKbps).toFixed(2));
      const txMbps = Number(Math.max(0, txRateKbps).toFixed(2));
      const utilizationPercent =
        speed > 0 ? Number(Math.min(100, ((rxMbps + txMbps) / speed) * 100).toFixed(1)) : 0;

      const lowerName = ifName.toLowerCase();
      interfaces.push({
        name: ifName,
        zone: lowerName.includes('wan') ? 'WAN' : lowerName.includes('dmz') ? 'DMZ' : 'LAN',
        ip: pickStr(rec, ['ip']) || '-',
        linkStatus: linkUp ? 'up' : 'down',
        linkSpeedMbps: speed > 0 ? speed : 1000,
        rxMbps,
        txMbps,
        rxBytes,
        txBytes,
        rxErrors: pickNum(rec, ['rx_errors']) ?? 0,
        txErrors: pickNum(rec, ['tx_errors']) ?? 0,
        utilizationPercent,
        role: lowerName === 'wan1' ? 'wan-primary' : lowerName.includes('wan') ? 'wan-failover' : 'internal',
      });
    }
  }

  const vpns: VpnTunnelStatus[] = [];
  if (vpnRes.status === 'fulfilled' && vpnRes.value.status < 400) {
    for (const tun of asArray(vpnRes.value.data)) {
      const name = pickStr(tun, ['name', 'tun_id']) || 'IPsec Tunnel';
      const proxyId = asArray(tun.proxyid)[0];
      const statusStr = proxyId ? pickStr(proxyId, ['status']).toLowerCase() : 'down';
      vpns.push({
        name,
        type: 'ipsec',
        peer: pickStr(tun, ['rgwy']) || '-',
        status: statusStr === 'up' ? 'up' : 'down',
        rxBytes: pickNum(tun, ['incoming_bytes']) ?? 0,
        txBytes: pickNum(tun, ['outgoing_bytes']) ?? 0,
      });
    }
  }

  const licenses: SecurityServiceLicense[] = [];
  if (licenseRes.status === 'fulfilled' && licenseRes.value.status < 400) {
    const licRec = asRecord(asRecord(licenseRes.value.data).results);
    for (const [svcKey, rawVal] of Object.entries(licRec)) {
      const rec = asRecord(rawVal);
      if (Object.keys(rec).length === 0) continue;
      const statusRaw = pickStr(rec, ['status']).toLowerCase();
      const status: SecurityServiceLicense['status'] =
        statusRaw === 'licensed' || statusRaw === 'valid'
          ? 'active'
          : statusRaw === 'expired'
            ? 'expired'
            : statusRaw === 'warning'
              ? 'expiring'
              : 'unlicensed';
      licenses.push({
        service: svcKey.toUpperCase(),
        status,
        expiresAt: pickStr(rec, ['expires', 'expiry_date']) || null,
      });
    }
  }

  return {
    rules,
    nats,
    model,
    firmware,
    serialNumber,
    uptimeFormatted,
    uptimeSeconds,
    cpuPercent,
    memoryPercent,
    activeConnections,
    maxConnections,
    haRole,
    telemetry: {
      interfaces: interfaces.slice(0, 12),
      vpns,
      licenses: licenses.slice(0, 12),
    },
  };
}
