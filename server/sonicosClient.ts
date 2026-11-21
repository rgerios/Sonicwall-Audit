import https from 'node:https';
import http from 'node:http';
import { appLog } from './appLogger.ts';
import {
  asRecord,
  formatUptimeSeconds,
  getTransportAgent,
  pickNumber,
  pickString,
} from './clientUtils.ts';
import { parseSonicOsJson } from './parsers.ts';
import type {
  FirewallRule,
  InterfaceTelemetry,
  NatPolicy,
  SecurityServiceLicense,
  TelemetrySnapshot,
  VpnTunnelStatus,
} from './types.ts';

export interface SonicOsConnectParams {
  host: string;
  port: number;
  protocol: 'https' | 'http';
  username: string;
  password: string;
  ignoreTlsErrors: boolean;
}

export interface SonicOsAuditResult {
  rules: FirewallRule[];
  nats: NatPolicy[];
  model: string;
  firmware: string;
  serialNumber: string;
  romVersion?: string;
  safemodeVersion?: string;
  uptimeFormatted?: string;
  uptimeSeconds?: number;
  cpuPercent?: number | null;
  memoryPercent?: number | null;
  activeConnections?: number | null;
  maxConnections?: number | null;
  haRole?: string;
  telemetry: TelemetrySnapshot;
}

function extractArray(data: unknown, candidateKeys: string[]): Array<Record<string, unknown>> {
  if (Array.isArray(data)) {
    return data.filter((item): item is Record<string, unknown> => Boolean(item && typeof item === 'object'));
  }
  const rec = asRecord(data);
  for (const key of candidateKeys) {
    const val = rec[key];
    if (Array.isArray(val)) {
      return val.filter((item): item is Record<string, unknown> => Boolean(item && typeof item === 'object'));
    }
    if (val && typeof val === 'object') {
      const nested = asRecord(val);
      for (const subKey of ['ipv4', ...candidateKeys]) {
        const subVal = nested[subKey];
        if (Array.isArray(subVal)) {
          return subVal.filter((item): item is Record<string, unknown> =>
            Boolean(item && typeof item === 'object')
          );
        }
      }
    }
  }
  return [];
}

export function normalizeRateMbps(obj: Record<string, unknown>, direction: 'rx' | 'tx'): number {
  const directionalAlias = direction === 'rx' ? 'ingress_mbps' : 'egress_mbps';
  const mbps = pickNumber(obj, [
    `${direction}_mbps`,
    `${direction}Mbps`,
    `${direction}_rate_mbps`,
    directionalAlias,
  ]);
  if (mbps !== null) return Math.max(0, Number(mbps.toFixed(2)));

  const kbps = pickNumber(obj, [
    `${direction}_kbps`,
    `${direction}Kbps`,
    `${direction}_rate_kbps`,
    `${direction}_kilobits_per_second`,
  ]);
  if (kbps !== null) return Math.max(0, Number((kbps / 1000).toFixed(2)));

  const bps = pickNumber(obj, [
    `${direction}_bps`,
    `${direction}Bps`,
    `${direction}_bits_per_second`,
    `${direction}_throughput`,
  ]);
  if (bps !== null) {
    return Math.max(0, Number((bps / 1_000_000).toFixed(2)));
  }

  // Taxas informadas em bytes/s precisam ser convertidas para bits (x8)
  const bytesPerSec = pickNumber(obj, [`${direction}_bytes_per_second`]);
  if (bytesPerSec !== null) {
    return Math.max(0, Number(((bytesPerSec * 8) / 1_000_000).toFixed(2)));
  }

  return 0;
}

function parseSpeedMbps(rawSpeed: unknown): number {
  if (typeof rawSpeed === 'number' && Number.isFinite(rawSpeed)) {
    return rawSpeed > 0 ? rawSpeed : 1000;
  }
  if (typeof rawSpeed === 'string') {
    const lower = rawSpeed.toLowerCase();
    const num = Number(lower.replace(/[^0-9.]/g, ''));
    if (Number.isFinite(num) && num > 0) {
      if (lower.includes('gbps') || lower.includes('g ')) return num * 1000;
      return num;
    }
  }
  return 1000;
}

// Aprendido no SonicWall Migrator: o appliance responde 429/5xx sob carga e derruba sessões.
const TRANSIENT_STATUS = new Set([429, 500, 502, 503, 504]);
const TRANSIENT_RETRIES = 2;
const TRANSIENT_BACKOFF_MS = 800;
const probeCache = new Map<string, { ep: string | null; method: 'GET' | 'POST'; at: number }>();
const PROBE_DEAD_TTL_MS = 30 * 60 * 1000;
const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

async function requestSonicOs(
  baseUrl: string,
  path: string,
  options: {
    method?: string;
    headers?: Record<string, string>;
    body?: string;
    ignoreTlsErrors: boolean;
  }
): Promise<{ status: number; data: unknown; headers: http.IncomingHttpHeaders }> {
  const url = new URL(path, baseUrl);
  const isHttps = url.protocol === 'https:';
  const transport = isHttps ? https : http;
  const agent = getTransportAgent(isHttps, options.ignoreTlsErrors);

  return new Promise((resolve, reject) => {
    const req = transport.request(
      url,
      {
        method: options.method || 'GET',
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json',
          ...(options.headers || {}),
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
            // Keep raw text if response wasn't JSON
          }
          resolve({
            status: res.statusCode || 500,
            data: parsed,
            headers: res.headers,
          });
        });
      }
    );

    req.on('timeout', () => {
      req.destroy(new Error(`Timeout ao conectar em ${url.hostname}:${url.port} (10s)`));
    });
    req.on('error', (err) => {
      reject(err);
    });

    if (options.body) {
      req.write(options.body);
    }
    req.end();
  });
}

export async function fetchSonicOsAudit(params: SonicOsConnectParams): Promise<SonicOsAuditResult> {
  const cleanHost = params.host.replace(/^https?:\/\//i, '').replace(/\/+$/, '');
  const baseUrl = `${params.protocol}://${cleanHost}:${params.port}`;
  const basicAuth = Buffer.from(`${params.username}:${params.password}`).toString('base64');

  const authHeaders: Record<string, string> = {
    Authorization: `Basic ${basicAuth}`,
  };

  // Authenticate session in SonicOS REST API (Gen 6.5 / Gen 7)
  const basicOnly = { ...authHeaders };
  const doLogin = () =>
    requestSonicOs(baseUrl, '/api/sonicos/auth', {
      method: 'POST',
      headers: basicOnly,
      body: JSON.stringify({ override: false }),
      ignoreTlsErrors: params.ignoreTlsErrors,
    });
  const loginRes = await doLogin();

  if (loginRes.status >= 400) {
    const errRec = asRecord(loginRes.data);
    const statusRec = asRecord(errRec.status);
    const infoArr = Array.isArray(statusRec.info) ? statusRec.info : [];
    const firstInfo = asRecord(infoArr[0]);
    const detail =
      pickString(firstInfo, ['message']) ||
      pickString(errRec, ['message', 'error']) ||
      (typeof loginRes.data === 'string' ? loginRes.data.slice(0, 180) : '');
    throw new Error(
      `Falha na autenticação SonicOS (${loginRes.status})${detail ? `: ${detail}` : ''}. Verifique usuário, senha e se a API REST (SonicOS API) está habilitada no appliance.`
    );
  }

  const applySession = (res: { data: unknown; headers: http.IncomingHttpHeaders }) => {
    const bearerToken = pickString(asRecord(res.data), ['token', 'access_token']);
    const cookies = res.headers['set-cookie'];
    delete authHeaders.Cookie;
    authHeaders.Authorization = basicOnly.Authorization;
    if (cookies && cookies.length > 0) {
      authHeaders.Cookie = cookies.map((c) => c.split(';')[0]).join('; ');
    }
    if (bearerToken) {
      authHeaders.Authorization = `Bearer ${bearerToken}`;
    }
  };
  applySession(loginRes);

  // Sessões da API expiram ou são derrubadas (outro login do mesmo admin) no meio da coleta.
  // Um único re-login compartilhado atende todas as requisições paralelas que receberem 401.
  let reloginInFlight: Promise<boolean> | null = null;
  const relogin = (): Promise<boolean> => {
    reloginInFlight ??= doLogin()
      .then((res) => {
        if (res.status >= 400) return false;
        applySession(res);
        return true;
      })
      .catch(() => false)
      .finally(() => {
        reloginInFlight = null;
      });
    return reloginInFlight;
  };

  const safeGet = async (endpoint: string, method: 'GET' | 'POST' = 'GET') => {
    const empty = { status: 404, data: {}, headers: {} as http.IncomingHttpHeaders };
    let reauthed = false;
    for (let attempt = 0; attempt <= TRANSIENT_RETRIES; attempt += 1) {
      try {
        const res = await requestSonicOs(baseUrl, endpoint, {
          method,
          headers: authHeaders,
          body: method === 'POST' ? '{}' : undefined,
          ignoreTlsErrors: params.ignoreTlsErrors,
        });
        if (res.status === 401 && !reauthed) {
          reauthed = true;
          if (await relogin()) {
            attempt -= 1;
            continue;
          }
        }
        if (TRANSIENT_STATUS.has(res.status) && attempt < TRANSIENT_RETRIES) {
          await sleep(TRANSIENT_BACKOFF_MS * 2 ** attempt);
          continue;
        }
        return res;
      } catch {
        if (attempt < TRANSIENT_RETRIES) {
          await sleep(TRANSIENT_BACKOFF_MS * 2 ** attempt);
          continue;
        }
        return empty;
      }
    }
    return empty;
  };

  try {
    let [
      rulesRes,
      natsRes,
      ruleStatsRes,
      natStatsRes,
      versionRes,
      systemReportRes,
      systemStatusRes,
      cpuRes,
      memRes,
      connRes,
      ifaceCfgRes,
      ifaceStatsRes,
      vpnRes,
      sslVpnRes,
      licensesRes,
    ] = await Promise.all([
      safeGet('/api/sonicos/access-rules/ipv4'),
      safeGet('/api/sonicos/nat-policies/ipv4'),
      safeGet('/api/sonicos/reporting/access-rules'),
      safeGet('/api/sonicos/reporting/nat-policies'),
      safeGet('/api/sonicos/version'),
      safeGet('/api/sonicos/reporting/system'),
      safeGet('/api/sonicos/system/status'),
      safeGet('/api/sonicos/reporting/core-utilization'),
      safeGet('/api/sonicos/reporting/memory-utilization'),
      safeGet('/api/sonicos/reporting/connections'),
      safeGet('/api/sonicos/interfaces/ipv4'),
      safeGet('/api/sonicos/reporting/interfaces'),
      safeGet('/api/sonicos/reporting/vpn/policies'),
      safeGet('/api/sonicos/reporting/ssl-vpn/sessions'),
      safeGet('/api/sonicos/reporting/licenses'),
    ]);

    // Fallbacks para diferenças entre SonicOS 6.5 e SonicOS 7.x
    let rawRulesList = extractArray(rulesRes.data, ['access_rules', 'access_rule', 'policies']);
    if (rulesRes.status >= 400 || rawRulesList.length === 0) {
      const altRules = await safeGet('/api/sonicos/access-rules');
      const altList = extractArray(altRules.data, ['access_rules', 'access_rule', 'policies']);
      if (altRules.status < 400 && altList.length > 0) {
        rulesRes = altRules;
        rawRulesList = altList;
      }
    }

    let rawNatsList = extractArray(natsRes.data, ['nat_policies', 'nat_policy', 'policies']);
    if (natsRes.status >= 400 || rawNatsList.length === 0) {
      const altNats = await safeGet('/api/sonicos/nat-policies');
      const altList = extractArray(altNats.data, ['nat_policies', 'nat_policy', 'policies']);
      if (altNats.status < 400 && altList.length > 0) {
        natsRes = altNats;
        rawNatsList = altList;
      }
    }

    if (ifaceStatsRes.status >= 400 || extractArray(ifaceStatsRes.data, ['interfaces', 'interface', 'interface_statistics']).length === 0) {
      for (const altEp of [
        '/api/sonicos/reporting/interfaces/ipv4',
        '/api/sonicos/reporting/interface-statistics',
      ]) {
        const alt = await safeGet(altEp);
        if (alt.status < 400 && extractArray(alt.data, ['interfaces', 'interface', 'interface_statistics']).length > 0) {
          ifaceStatsRes = alt;
          break;
        }
      }
    }

    // Endpoints de /reporting variam entre versões do SonicOS (a 7.3 responde 400 aos caminhos antigos).
    // Quando o principal falha, testa alternativas (GET e POST) e memoriza a que funcionar por appliance.
    const probeNotes: string[] = [];
    const hasPayload = (r: { status: number; data: unknown }) =>
      r.status < 400 &&
      (Array.isArray(r.data)
        ? r.data.length > 0
        : Object.keys(asRecord(r.data)).some((k) => k !== 'status'));
    const shape = (r: { data: unknown }) =>
      Array.isArray(r.data) ? `array[${r.data.length}]` : `keys=${JSON.stringify(Object.keys(asRecord(r.data)).slice(0, 6))}`;
    const errMsg = (r: { data: unknown }) => {
      const info = asRecord(r.data).status;
      const first = asRecord(Array.isArray(asRecord(info).info) ? (asRecord(info).info as unknown[])[0] : {});
      return pickString(first, ['message']).slice(0, 60);
    };
    const probe = async (
      label: string,
      current: { status: number; data: unknown; headers: http.IncomingHttpHeaders },
      candidates: string[]
    ) => {
      if (hasPayload(current)) return current;
      const cacheKey = `${baseUrl}|${label}`;
      const known = probeCache.get(cacheKey);
      if (known && known.ep === null && Date.now() - known.at < PROBE_DEAD_TTL_MS) return current;
      const tried: string[] = [];
      const order: Array<[string, 'GET' | 'POST']> = known?.ep
        ? [[known.ep, known.method]]
        : candidates.map((ep) => [ep, 'GET'] as [string, 'GET' | 'POST']);
      for (const [ep, method] of order) {
        const alt = await safeGet(ep, method);
        if (hasPayload(alt)) {
          probeCache.set(cacheKey, { ep, method, at: Date.now() });
          probeNotes.push(`${label}=${method} ${ep}`);
          return alt;
        }
        tried.push(`${method} ${ep.replace('/api/sonicos', '')}=${alt.status}${alt.status < 400 ? ` ${shape(alt)}` : errMsg(alt) ? `"${errMsg(alt)}"` : ''}`);
      }
      probeCache.set(cacheKey, { ep: null, method: 'GET', at: Date.now() });
      probeNotes.push(`${label}?[${tried.join('; ')}]`);
      return current;
    };
    const R = '/api/sonicos/reporting';
    {
      // Descoberta: caminhos-base podem listar os endpoints disponíveis (logado uma vez por janela de 30 min)
      const dk = `${baseUrl}|discovery`;
      if (!probeCache.has(dk) || Date.now() - (probeCache.get(dk)?.at ?? 0) > PROBE_DEAD_TTL_MS) {
        probeCache.set(dk, { ep: null, method: 'GET', at: Date.now() });
        if (!hasPayload(cpuRes) || !hasPayload(memRes)) {
          for (const base of [`${R}`, `${R}/system`, `/api/sonicos/system`]) {
            const d = await safeGet(base);
            probeNotes.push(`discovery ${base.replace('/api/sonicos', '')}=${d.status} ${JSON.stringify(d.data).slice(0, 300)}`);
          }
        }
      }
    }
    cpuRes = await probe('cpu', cpuRes, [`${R}/cpu/current`, `${R}/cpu/statistics`, `${R}/cpu-monitor`, `${R}/system/cpu/current`, `${R}/system/cpu/statistics`, `${R}/system/cpu-monitor`]);
    memRes = await probe('mem', memRes, [`${R}/memory/current`, `${R}/memory/statistics`, `${R}/system/memory/current`, `${R}/system/memory/statistics`, `${R}/memory-monitor`]);
    connRes = await probe('conn', connRes, [`${R}/connections/current`, `${R}/connections/statistics`, `${R}/connection-monitor`, `${R}/system/connections/statistics`, `${R}/connections/monitor`]);
    ifaceStatsRes = await probe('ifaces', ifaceStatsRes, [`${R}/interfaces/ipv4/statistics`, `${R}/interfaces/ipv6/statistics`]);
    vpnRes = await probe('vpn', vpnRes, [`${R}/vpn/policies/statistics`, `${R}/vpn/ipv4/statistics`, `${R}/vpn/ipsec/statistics`, `${R}/vpn/sa/statistics`, `${R}/vpn/tunnels`]);
    ruleStatsRes = await probe('ruleHits', ruleStatsRes, [`${R}/access-rules/ipv4/statistics`, `${R}/access-rules/ipv4`, `${R}/access-rules/statistics`, `${R}/access-rules/ipv4/hit-count`]);
    natStatsRes = await probe('natHits', natStatsRes, [`${R}/nat-policies/ipv4/statistics`, `${R}/nat-policies/ipv4`, `${R}/nat-policies/statistics`, `${R}/nat-policies/ipv4/hit-count`]);

    const parsed = parseSonicOsJson(
      {
        access_rules: rawRulesList,
        nat_policies: rawNatsList,
      },
      'api'
    );

    // Merge hit counters from /reporting/* endpoints when available
    const HIT_KEYS = ['hits', 'hit_count', 'hit_counts', 'rule_hit_count', 'count', 'rx_packets', 'packets'];
    const flattenStat = (stat: Record<string, unknown>): Record<string, unknown> => {
      const flat: Record<string, unknown> = { ...stat };
      for (const k of ['access_rule', 'nat_policy', 'policy', 'statistics', 'stats', 'ipv4']) {
        const inner = asRecord(stat[k]);
        if (Object.keys(inner).length > 0) Object.assign(flat, inner);
      }
      return flat;
    };
    const buildHitMap = (data: unknown, keys: string[]) => {
      const map = new Map<string, number>();
      for (const raw of extractArray(data, keys)) {
        const stat = flattenStat(raw);
        // SonicOS 7.3 (access-rules/ipv4): sem campo "hits"; traz usage, rxpackets e txpackets.
        let hits = pickNumber(stat, HIT_KEYS);
        if (hits === null) {
          const usage = pickNumber(stat, ['usage']);
          const pk = (pickNumber(stat, ['rxpackets']) ?? 0) + (pickNumber(stat, ['txpackets']) ?? 0);
          hits = usage !== null ? usage : pk > 0 || 'rxpackets' in stat ? pk : null;
        }
        if (hits === null || !Number.isFinite(hits)) continue;
        for (const id of [stat.uuid, stat.id]) {
          if (id !== undefined && id !== null && String(id)) map.set(String(id), hits);
        }
      }
      return map;
    };
    const ruleStatsMap = buildHitMap(ruleStatsRes.data, ['access_rules', 'access_rule', 'policies', 'statistics']);
    const natStatsMap = buildHitMap(natStatsRes.data, ['nat_policies', 'nat_policy', 'policies', 'statistics']);

    const rules = parsed.rules.map((r) => ({
      ...r,
      applianceHits:
        (r.uuid ? ruleStatsMap.get(r.uuid) : undefined) ?? ruleStatsMap.get(r.id) ?? r.applianceHits,
    }));

    const nats = parsed.nats.map((n) => ({
      ...n,
      applianceHits:
        (n.uuid ? natStatsMap.get(n.uuid) : undefined) ?? natStatsMap.get(n.id) ?? n.applianceHits,
    }));

    // Version & System Status / Uptime
    const ver = asRecord(versionRes.data);
    const sysRaw = asRecord(systemReportRes.data);
    const sysAlt = asRecord(systemStatusRes.data);
    const sysObj = Object.keys(asRecord(sysRaw.system)).length > 0
      ? asRecord(sysRaw.system)
      : Object.keys(sysRaw).length > 0
        ? sysRaw
        : asRecord(sysAlt.system ?? sysAlt);

    const uptimeSecondsRaw = pickNumber(sysObj, ['uptime_seconds', 'up_time_seconds', 'uptime_sec']);
    const uptimeStrRaw = pickString(sysObj, ['up_time', 'uptime', 'system_uptime', 'uptime_string']) ||
      pickString(ver, ['up_time', 'uptime']);
    const uptimeFormatted = uptimeStrRaw || (uptimeSecondsRaw !== null ? formatUptimeSeconds(uptimeSecondsRaw) : undefined);

    const model =
      pickString(ver, ['model', 'appliance_model', 'product_name']) ||
      pickString(sysObj, ['model', 'appliance_model']) ||
      'SonicWall Appliance';
    const firmware =
      pickString(ver, ['firmware_version', 'firmware', 'sonicos_version']) ||
      pickString(sysObj, ['firmware_version', 'firmware']) ||
      'SonicOS API';
    const serialNumber =
      pickString(ver, ['serial_number', 'serial', 'sn']) ||
      pickString(sysObj, ['serial_number', 'serial']) ||
      '-';
    const romVersion = pickString(ver, ['rom_version', 'rom']) || undefined;
    const safemodeVersion = pickString(ver, ['safemode_version', 'safemode']) || undefined;
    const haRole = pickString(sysObj, ['ha_role', 'ha_status', 'high_availability_role']) || undefined;

    // CPU utilization
    const cpuObj = asRecord(cpuRes.data);
    let cpuPercent =
      pickNumber(cpuObj, [
        'total',
        'cpu_utilization',
        'utilization',
        'average',
        'core_utilization',
        'data_plane',
        'control_plane',
      ]) ?? pickNumber(sysObj, ['cpu_utilization', 'cpu_percent', 'cpu']);
    if (cpuPercent === null) {
      const cores = extractArray(cpuRes.data, ['cores', 'core', 'multi_core', 'core_utilization', 'cpu']);
      if (cores.length > 0) {
        const vals = cores
          .map((c) => pickNumber(c, ['utilization', 'percent', 'usage', 'load', 'value', 'cpu_utilization']))
          .filter((v): v is number => v !== null);
        if (vals.length > 0) {
          cpuPercent = Math.round(vals.reduce((a, b) => a + b, 0) / vals.length);
        }
      }
    }
    if (cpuPercent !== null) {
      cpuPercent = Math.min(100, Math.max(0, Math.round(cpuPercent)));
    }

    // Memory utilization
    const memObj = asRecord(memRes.data);
    const memInner = Object.keys(asRecord(memObj.memory)).length > 0 ? asRecord(memObj.memory) : memObj;
    let memoryPercent =
      pickNumber(memInner, [
        'used_percent',
        'memory_utilization',
        'ram_utilization',
        'ram_utilization_percent',
        'current_memory_utilization',
        'current_ram_utilization',
        'utilization',
        'percent',
      ]) ?? pickNumber(sysObj, ['memory_utilization', 'ram_utilization', 'memory_percent']);
    if (memoryPercent === null) {
      const used = pickNumber(memInner, ['used', 'used_bytes', 'used_mb', 'used_ram']);
      const total = pickNumber(memInner, ['total', 'total_bytes', 'total_mb', 'total_ram']);
      if (used !== null && total !== null && total > 0) {
        memoryPercent = Math.round((used / total) * 100);
      }
    }
    if (memoryPercent !== null) {
      memoryPercent = Math.min(100, Math.max(0, Math.round(memoryPercent)));
    }

    // Active / Max connections
    const connObj = asRecord(connRes.data);
    const connInner =
      Object.keys(asRecord(connObj.connections)).length > 0
        ? asRecord(connObj.connections)
        : Object.keys(asRecord(connObj.connection_cache)).length > 0
          ? asRecord(connObj.connection_cache)
          : connObj;
    const activeConnections =
      pickNumber(connInner, [
        'active_connections',
        'current_connections',
        'active',
        'current',
        'count',
        'total',
      ]) ?? pickNumber(sysObj, ['active_connections', 'current_connections']);
    const maxConnections =
      pickNumber(connInner, [
        'max_connections',
        'maximum_connections',
        'peak_connections',
        'max',
        'limit',
      ]) ?? pickNumber(sysObj, ['max_connections', 'maximum_connections']);

    // Interfaces & link consumption
    const ifaceConfigs = extractArray(ifaceCfgRes.data, ['interfaces', 'interface', 'ipv4']);
    const ifaceStats = extractArray(ifaceStatsRes.data, [
      'interfaces',
      'interface',
      'interface_statistics',
      'interface_traffic_statistics',
    ]);

    const ifaceConfigMap = new Map<string, Record<string, unknown>>();
    for (const cfg of ifaceConfigs) {
      const ipv4 = asRecord(cfg.ipv4);
      const innerIface = asRecord(cfg.interface);
      const flatCfg = {
        ...cfg,
        ...(Object.keys(innerIface).length > 0 ? innerIface : {}),
        ...(Object.keys(ipv4).length > 0 ? ipv4 : {}),
      };
      const name = pickString(flatCfg, ['name', 'interface_name', 'interface', 'id']);
      if (name) {
        ifaceConfigMap.set(name.toUpperCase(), flatCfg);
      }
    }

    const ifaceStatMap = new Map<string, Record<string, unknown>>();
    for (const st of ifaceStats) {
      const innerIface = asRecord(st.interface);
      const innerStats = asRecord(st.statistics);
      const innerTraffic = asRecord(st.traffic);
      const flatSt = {
        ...st,
        ...(Object.keys(innerIface).length > 0 ? innerIface : {}),
        ...(Object.keys(innerStats).length > 0 ? innerStats : {}),
        ...(Object.keys(innerTraffic).length > 0 ? innerTraffic : {}),
      };
      const name = pickString(flatSt, ['name', 'interface_name', 'interface', 'id']);
      if (name) {
        ifaceStatMap.set(name.toUpperCase(), flatSt);
      }
    }

    const allIfaceNames = new Set<string>([...ifaceConfigMap.keys(), ...ifaceStatMap.keys()]);
    const interfaces: InterfaceTelemetry[] = [];

    for (const key of allIfaceNames) {
      const cfg = ifaceConfigMap.get(key) || {};
      const st = ifaceStatMap.get(key) || {};
      const merged = { ...cfg, ...st };

      const name = pickString(merged, ['name', 'interface', 'id']) || key;
      const ipv4Static = asRecord(asRecord(asRecord(merged.ip_assignment).mode).static);
      const ip =
        pickString(merged, ['ip', 'ip_address', 'ipv4_address', 'address']) ||
        pickString(ipv4Static, ['ip']) ||
        '-';
      const zone =
        pickString(merged, ['zone', 'security_zone']) ||
        pickString(asRecord(merged.ip_assignment), ['zone']) ||
        '-';

      const statusText = (
        pickString(merged, ['link_status', 'status', 'state', 'link']) || 'up'
      ).toLowerCase();
      const linkStatus: 'up' | 'down' =
        statusText.includes('down') || statusText === 'false' || statusText === 'disabled'
          ? 'down'
          : 'up';

      const linkSpeedMbps = parseSpeedMbps(
        merged.link_speed ?? merged.speed ?? merged.configured_speed ?? 1000
      );
      const rxMbps = normalizeRateMbps(merged, 'rx');
      const txMbps = normalizeRateMbps(merged, 'tx');
      const rxBytes =
        pickNumber(merged, ['rx_bytes', 'in_bytes', 'rx_octets', 'in_octets']) ??
        (pickNumber(merged, ['rx_kilobytes', 'rx_kbytes']) !== null
          ? (pickNumber(merged, ['rx_kilobytes', 'rx_kbytes']) ?? 0) * 1024
          : 0);
      const txBytes =
        pickNumber(merged, ['tx_bytes', 'out_bytes', 'tx_octets', 'out_octets']) ??
        (pickNumber(merged, ['tx_kilobytes', 'tx_kbytes']) !== null
          ? (pickNumber(merged, ['tx_kilobytes', 'tx_kbytes']) ?? 0) * 1024
          : 0);
      const rxErrors = pickNumber(merged, ['rx_errors', 'in_errors']) ?? 0;
      const txErrors = pickNumber(merged, ['tx_errors', 'out_errors']) ?? 0;

      const explicitUtil = pickNumber(merged, ['utilization', 'utilization_percent', 'bandwidth_usage']);
      const peakMbps = Math.max(rxMbps, txMbps);
      const computedUtil =
        linkSpeedMbps > 0 ? Math.min(100, Number(((peakMbps / linkSpeedMbps) * 100).toFixed(1))) : 0;
      const utilizationPercent = explicitUtil !== null ? Math.min(100, Math.max(0, explicitUtil)) : computedUtil;

      const upperZone = zone.toUpperCase();
      const roleRaw = pickString(merged, ['wan_role', 'failover_role', 'role']).toLowerCase();
      let role: InterfaceTelemetry['role'] = 'internal';
      if (upperZone === 'WAN' || name.toUpperCase() === 'X1' || name.toUpperCase() === 'X2') {
        role = roleRaw.includes('failover') || roleRaw.includes('backup') || name.toUpperCase() === 'X2'
          ? 'wan-failover'
          : 'wan-primary';
      }

      interfaces.push({
        name,
        zone,
        ip,
        linkStatus,
        linkSpeedMbps,
        rxMbps,
        txMbps,
        rxBytes,
        txBytes,
        rxErrors,
        txErrors,
        utilizationPercent,
        role,
      });
    }

    interfaces.sort((a, b) => a.name.localeCompare(b.name));

    // VPN Tunnels (IPSec + SSL VPN)
    const vpns: VpnTunnelStatus[] = [];
    const ipsecEntries = extractArray(vpnRes.data, ['vpn_policies', 'policies', 'tunnels', 'sa']);
    for (const vpn of ipsecEntries) {
      const name = pickString(vpn, ['name', 'policy_name', 'tunnel_name']) || 'VPN IPSec';
      const peer = pickString(vpn, ['peer_gateway', 'remote_gateway', 'gateway', 'peer']) || '-';
      const stateText = pickString(vpn, ['status', 'state', 'tunnel_status']).toLowerCase();
      // "inactive" contém "active": avalia primeiro os estados negativos. Sem estado
      // reportado pela API, assume o estado administrativo (habilitada).
      const negative = /down|inactive|disabled|not\s*established|idle|fail/.test(stateText);
      const up =
        !negative &&
        (stateText.includes('up') ||
          stateText.includes('active') ||
          stateText.includes('established') ||
          stateText.includes('connected') ||
          (stateText === '' && vpn.enabled === true));
      vpns.push({
        name,
        type: 'ipsec',
        peer,
        status: up ? 'up' : 'down',
        rxBytes: pickNumber(vpn, ['rx_bytes', 'in_bytes', 'decrypted_bytes']) ?? 0,
        txBytes: pickNumber(vpn, ['tx_bytes', 'out_bytes', 'encrypted_bytes']) ?? 0,
      });
    }

    const sslSessions = extractArray(sslVpnRes.data, ['sessions', 'ssl_vpn_sessions', 'users']);
    if (sslSessions.length > 0) {
      const totalRx = sslSessions.reduce(
        (acc, s) => acc + (pickNumber(s, ['rx_bytes', 'in_bytes']) ?? 0),
        0
      );
      const totalTx = sslSessions.reduce(
        (acc, s) => acc + (pickNumber(s, ['tx_bytes', 'out_bytes']) ?? 0),
        0
      );
      vpns.push({
        name: 'SSL VPN (Usuários Remotos)',
        type: 'sslvpn',
        peer: `${sslSessions.length} sessão(ões) ativa(s)`,
        status: 'up',
        rxBytes: totalRx,
        txBytes: totalTx,
        activeUsers: sslSessions.length,
      });
    }

    // Security Service Licenses
    const licenseRows = extractArray(licensesRes.data, ['licenses', 'services', 'security_services']);
    const licenses: SecurityServiceLicense[] = licenseRows.map((lic) => {
      const service = pickString(lic, ['service', 'name', 'feature']) || 'Serviço de Segurança';
      const rawStatus = pickString(lic, ['status', 'state']).toLowerCase();
      const expiresAt = pickString(lic, ['expiration', 'expires_at', 'expiry_date']) || null;
      let status: SecurityServiceLicense['status'] = 'active';
      if (rawStatus.includes('expir') && !rawStatus.includes('expiring')) {
        status = 'expired';
      } else if (rawStatus.includes('expiring') || rawStatus.includes('warn')) {
        status = 'expiring';
      } else if (rawStatus.includes('unlic') || rawStatus.includes('inactive') || rawStatus.includes('not')) {
        status = 'unlicensed';
      }
      return { service, status, expiresAt };
    });

    const missingParts: string[] = [];
    if (cpuPercent === null) missingParts.push(`cpuKeys=${JSON.stringify(Object.keys(cpuObj).slice(0, 6))}`);
    if (memoryPercent === null) missingParts.push(`memKeys=${JSON.stringify(Object.keys(memObj).slice(0, 6))}`);
    if (activeConnections === null) missingParts.push(`connKeys=${JSON.stringify(Object.keys(connObj).slice(0, 6))}`);
    if (ifaceStats.length === 0) {
      missingParts.push(`ifaceStatKeys=${JSON.stringify(Object.keys(asRecord(ifaceStatsRes.data)).slice(0, 6))}`);
    }
    if (ifaceStats.length > 0) {
      // Amostra crua de uma interface (só contadores) para calibrar unidades dos campos do SonicOS
      const sample = ifaceStats.find((i) => /x1|wan/i.test(JSON.stringify(i).slice(0, 200))) ?? ifaceStats[0];
      missingParts.push(`ifaceSample=${JSON.stringify(sample).slice(0, 700)}`);
    }
    const firstHit = (d: unknown, k: string[]) => extractArray(d, k)[0];
    missingParts.push(`ruleHits=${ruleStatsRes.status}(map=${ruleStatsMap.size})`, `natHits=${natStatsRes.status}(map=${natStatsMap.size})`);
    if (ruleStatsMap.size === 0 && ruleStatsRes.status < 400) {
      const sm = firstHit(ruleStatsRes.data, ['access_rules', 'access_rule', 'policies', 'statistics']);
      missingParts.push(`ruleHitSample=${JSON.stringify(sm ?? ruleStatsRes.data).slice(0, 500)}`);
    }
    const diagSummary = `rules=${rulesRes.status}(${rules.length}), nats=${natsRes.status}(${nats.length}), ver=${versionRes.status}, cpu=${cpuRes.status}(${cpuPercent ?? '-'}%), mem=${memRes.status}(${memoryPercent ?? '-'}%), conn=${connRes.status}(${activeConnections ?? '-'}), ifaces=${ifaceCfgRes.status}/${ifaceStatsRes.status}(${interfaces.length}, stats=${ifaceStats.length}), vpn=${vpnRes.status}(${vpns.length})${missingParts.length ? ` | ${missingParts.join(' ')}` : ''}${probeNotes.length ? ` | probe: ${probeNotes.join(' ')}` : ''}`;
    if (rules.length === 0 && interfaces.length === 0) {
      appLog.warn(
        'sonicwall',
        'sonicos-api',
        `Coleta SonicOS (${cleanHost}:${params.port}) retornou vazia`,
        diagSummary
      );
    } else {
      appLog.info(
        'sonicwall',
        'sonicos-api',
        `Coleta SonicOS (${cleanHost}:${params.port})`,
        diagSummary
      );
    }

    return {
      rules,
      nats,
      model,
      firmware,
      serialNumber,
      romVersion,
      safemodeVersion,
      uptimeFormatted,
      uptimeSeconds: uptimeSecondsRaw ?? undefined,
      cpuPercent,
      memoryPercent,
      activeConnections,
      maxConnections,
      haRole,
      telemetry: {
        interfaces,
        vpns,
        licenses,
      },
    };
  } finally {
    // Gracefully close SonicOS management session so admin slots are not locked
    await requestSonicOs(baseUrl, '/api/sonicos/auth', {
      method: 'DELETE',
      headers: authHeaders,
      ignoreTlsErrors: params.ignoreTlsErrors,
    }).catch(() => undefined);
  }
}
