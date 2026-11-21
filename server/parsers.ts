import crypto from 'node:crypto';
import type {
  FirewallRule,
  NatPolicy,
  SyslogAction,
  SyslogEvent,
  SyslogSeverity,
} from './types.ts';

const SEVERITY_NAMES: SyslogSeverity[] = [
  'emergency',
  'alert',
  'critical',
  'error',
  'warning',
  'notice',
  'info',
  'debug',
];

const CATEGORY_MAP: Record<string, string> = {
  '0': 'Sistema',
  '4': 'Segurança',
  '16': 'VPN / IPSec',
  '32': 'Acesso Firewall',
  '64': 'Rede / Interfaces',
  '128': 'Tráfego / Sessão',
  '256': 'NAT / Roteamento',
  '512': 'IDS / IPS',
  '1024': 'Firewall / Conexão',
  '2048': 'Gateway AV / Anti-Spyware',
  '4096': 'Controle de Aplicação',
};

function splitIpPort(value: string | undefined): { ip: string; port: number | null; zone: string } {
  if (!value) return { ip: '-', port: null, zone: '-' };
  // Format examples: "192.168.10.25:54321:X0" or "8.8.8.8:443:X1" or "10.0.0.5:80"
  const parts = value.split(':');
  const ip = parts[0] || '-';
  const portCandidate = parts[1] ? Number.parseInt(parts[1], 10) : Number.NaN;
  const port = Number.isFinite(portCandidate) ? portCandidate : null;
  const zone = parts[2] || '-';
  return { ip, port, zone };
}

function extractKeyValuePairs(line: string): Record<string, string> {
  const result: Record<string, string> = {};
  const regex = /([a-zA-Z0-9_.-]+)=("([^"]*)"|'([^']*)'|(\S+))/g;
  let match: RegExpExecArray | null = regex.exec(line);
  while (match !== null) {
    const key = match[1];
    const value = match[3] ?? match[4] ?? match[5] ?? '';
    result[key] = value;
    match = regex.exec(line);
  }
  return result;
}

function mapPriorityToSeverity(priRaw: string | undefined, syslogPriHeader: number | null): { priority: number; severity: SyslogSeverity } {
  if (priRaw) {
    const numericPri = Number.parseInt(priRaw, 10);
    if (Number.isFinite(numericPri)) {
      const clamped = Math.max(0, Math.min(7, numericPri));
      return { priority: clamped, severity: SEVERITY_NAMES[clamped] || 'info' };
    }
  }
  if (syslogPriHeader !== null) {
    const sevIdx = syslogPriHeader % 8;
    return { priority: sevIdx, severity: SEVERITY_NAMES[sevIdx] || 'info' };
  }
  return { priority: 6, severity: 'info' };
}

function inferAction(kv: Record<string, string>, rawLine: string): SyslogAction {
  const fwAction = (kv.fw_action || kv.action || '').toLowerCase();
  const msg = (kv.msg || rawLine).toLowerCase();
  const mCode = kv.m || '';

  if (fwAction.includes('drop')) return 'drop';
  if (fwAction.includes('deny') || fwAction.includes('block')) return 'deny';
  if (fwAction.includes('reset')) return 'reset';
  if (fwAction.includes('allow') || fwAction.includes('forward') || fwAction.includes('accept')) {
    return 'allow';
  }

  if (msg.includes('dropped') || msg.includes('packet dropped')) {
    return 'drop';
  }
  if (msg.includes('denied') || msg.includes('blocked')) {
    return 'deny';
  }
  if (msg.includes('tcp reset')) {
    return 'reset';
  }
  if (msg.includes('connection opened') || msg.includes('connection closed')) {
    return 'allow';
  }
  if (mCode === '537') {
    return 'drop';
  }
  if (kv.nat_rule || kv.srcNat || kv.dstNat || msg.includes('nat')) {
    return 'nat';
  }
  return 'system';
}

function normalizeProtocol(protoRaw: string | undefined): string {
  if (!protoRaw) return '-';
  const lower = protoRaw.toLowerCase();
  if (lower.startsWith('tcp')) return 'TCP';
  if (lower.startsWith('udp')) return 'UDP';
  if (lower.startsWith('icmp')) return 'ICMP';
  if (lower === '6') return 'TCP';
  if (lower === '17') return 'UDP';
  if (lower === '1') return 'ICMP';
  return protoRaw.toUpperCase();
}

export function parseSonicWallSyslog(
  rawText: string,
  source: SyslogEvent['source'] = 'upload'
): SyslogEvent[] {
  const lines = rawText
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith('#'));

  const events: SyslogEvent[] = [];

  for (const line of lines) {
    const priHeaderMatch = /^<(\d{1,3})>/.exec(line);
    const syslogPriHeader = priHeaderMatch ? Number.parseInt(priHeaderMatch[1], 10) : null;
    const kv = extractKeyValuePairs(line);

    // Must look like a syslog line (either SonicWall KV or standard rsyslog line)
    if (Object.keys(kv).length === 0 && !priHeaderMatch && !/\d{2}:\d{2}:\d{2}/.test(line)) {
      continue;
    }

    const src = splitIpPort(kv.src);
    const dst = splitIpPort(kv.dst);
    const natSrc = kv.srcNat || kv.nSrc ? splitIpPort(kv.srcNat || kv.nSrc) : null;
    const natDst = kv.dstNat || kv.nDst ? splitIpPort(kv.dstNat || kv.nDst) : null;

    const { priority, severity } = mapPriorityToSeverity(kv.pri, syslogPriHeader);
    const categoryCode = kv.c || '0';
    const categoryName = CATEGORY_MAP[categoryCode] || (categoryCode !== '0' ? `Categoria ${categoryCode}` : 'Sistema');

    const rsyslogTsMatch = /^(?:<\d+>)?([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)/.exec(line);
    const timestamp = kv.time || (rsyslogTsMatch ? rsyslogTsMatch[1] : new Date().toISOString().replace('T', ' ').slice(0, 19));

    const protoRaw = kv.proto || kv.protocol || (kv.src?.includes('/') ? undefined : undefined);
    const protocol = normalizeProtocol(protoRaw ? protoRaw.split('/')[0] : undefined);
    const portFromProto = protoRaw && protoRaw.includes('/') ? Number.parseInt(protoRaw.split('/')[1], 10) : null;

    const action = inferAction(kv, line);

    const ruleMatch = /\brule[=:\s]+"?([^"\s]+)"?/i.exec(line);
    const natRuleMatch = /\bnat_rule[=:\s]+"?([^"\s]+)"?/i.exec(line);

    events.push({
      id: crypto.randomUUID(),
      timestamp,
      firewallHost: kv.fw || kv.host || 'SonicWall',
      serialNumber: kv.sn || '-',
      priority,
      severity,
      categoryCode,
      categoryName,
      messageId: kv.m || '-',
      action,
      srcIp: src.ip,
      srcPort: src.port,
      srcZone: kv.srcZone || src.zone,
      dstIp: dst.ip,
      dstPort: dst.port ?? (Number.isFinite(portFromProto ?? Number.NaN) ? portFromProto : null),
      dstZone: kv.dstZone || dst.zone,
      natSrcIp: natSrc && natSrc.ip !== '-' ? natSrc.ip : null,
      natSrcPort: natSrc ? natSrc.port : null,
      natDstIp: natDst && natDst.ip !== '-' ? natDst.ip : null,
      natDstPort: natDst ? natDst.port : null,
      protocol,
      ruleRef: kv.rule || kv.policy || (ruleMatch ? ruleMatch[1] : null),
      natRuleRef: kv.nat_rule || kv.natPolicy || (natRuleMatch ? natRuleMatch[1] : null),
      bytesSent: Number.parseInt(kv.sent || '0', 10) || 0,
      bytesRcvd: Number.parseInt(kv.rcvd || '0', 10) || 0,
      appName: kv.appName || kv.app || null,
      user: kv.usr || kv.user || null,
      message: kv.msg || kv.note || line.replace(/^<\d+>/, '').slice(0, 220),
      raw: line,
      source,
      ingestedAt: new Date().toISOString(),
    });
  }

  return events;
}

function decodeExpIfBase64(content: string): string {
  // O .exp real é Base64 de pares chave=valor separados por '&' e costuma terminar com '&'
  // ou espaços; o Base64 em si pode ter padding '=' no fim (não é sinal de texto já decodificado).
  const trimmed = content.trim().replace(/[&\s]+$/, '');
  if (/^[A-Za-z0-9+/]+={0,2}$/.test(trimmed.replace(/\s+/g, '')) && trimmed.length >= 8) {
    try {
      const decoded = Buffer.from(trimmed.replace(/\s+/g, ''), 'base64').toString('utf8');
      // Só aceita se o resultado parece mesmo uma lista chave=valor
      if (decoded.includes('=') && /^[\x20-\x7e\r\n\t]+$/.test(decoded)) {
        return decoded;
      }
    } catch {
      return content;
    }
  }
  return content;
}

/** Códigos numéricos de ação do .exp: 2 = permitir; qualquer outro valor bloqueia. */
function parseExpAction(raw: string): FirewallRule['action'] {
  const v = raw.trim().toLowerCase();
  if (v === '2' || v === 'allow' || v === 'permit') return 'allow';
  if (v === 'discard' || v === 'drop') return 'discard';
  return 'deny';
}

export function parseSonicWallExp(content: string): {
  rules: FirewallRule[];
  nats: NatPolicy[];
  model?: string;
  serialNumber?: string;
  firmware?: string;
} {
  const decoded = decodeExpIfBase64(content);
  const kvMap = new Map<string, string>();
  const tokens = decoded.split(/[&\r\n]+/);

  for (const token of tokens) {
    const eqIndex = token.indexOf('=');
    if (eqIndex > 0) {
      const k = token.slice(0, eqIndex).trim();
      const v = decodeURIComponent(token.slice(eqIndex + 1).trim().replace(/\+/g, ' '));
      kvMap.set(k, v);
    }
  }

  const ruleIndices = new Set<string>();
  const natIndices = new Set<string>();

  for (const key of kvMap.keys()) {
    const policyMatch = /^policy(?:Action|SrcZone|DstZone|DstSvc|Name|Enabled|Hits)_(\d+)$/.exec(key);
    if (policyMatch) ruleIndices.add(policyMatch[1]);

    const natMatch = /^natPolicy(?:OrigSrc|TransSrc|OrigDst|TransDst|Name|Enabled|Hits)_(\d+)$/.exec(key);
    if (natMatch) natIndices.add(natMatch[1]);
  }

  const rules: FirewallRule[] = [];
  const sortedRuleIdx = [...ruleIndices].sort((a, b) => Number(a) - Number(b));
  for (const idx of sortedRuleIdx) {
    const action = parseExpAction(kvMap.get(`policyAction_${idx}`) || kvMap.get(`policy_action_${idx}`) || 'allow');
    const enabledVal = kvMap.get(`policyEnabled_${idx}`);
    const enabled = enabledVal === undefined ? true : enabledVal === '1' || enabledVal.toLowerCase() === 'true' || enabledVal.toLowerCase() === 'on';
    const hits = Number.parseInt(kvMap.get(`policyHits_${idx}`) || kvMap.get(`policyHitCount_${idx}`) || '0', 10) || 0;

    rules.push({
      id: `EXP-R-${idx}`,
      name: kvMap.get(`policyName_${idx}`) || `Regra #${idx}`,
      priority: Number.parseInt(kvMap.get(`policyPriority_${idx}`) || idx, 10) || Number(idx),
      fromZone: kvMap.get(`policySrcZone_${idx}`) || 'LAN',
      toZone: kvMap.get(`policyDstZone_${idx}`) || 'WAN',
      source: kvMap.get(`policySrcNet_${idx}`) || 'Any',
      destination: kvMap.get(`policyDstNet_${idx}`) || 'Any',
      // Chave real do SonicOS: policyDstSvc_ (policyService_ fica como fallback)
      service: kvMap.get(`policyDstSvc_${idx}`) || kvMap.get(`policyService_${idx}`) || 'Any',
      action,
      enabled,
      applianceHits: hits,
      syslogHits: 0,
      lastHitAt: null,
      comment: kvMap.get(`policyComment_${idx}`) || '',
      status: 'active',
      findingReason: '',
      sourceOrigin: 'exp',
    });
  }

  const nats: NatPolicy[] = [];
  const sortedNatIdx = [...natIndices].sort((a, b) => Number(a) - Number(b));
  for (const idx of sortedNatIdx) {
    const enabledVal = kvMap.get(`natPolicyEnabled_${idx}`);
    const enabled = enabledVal === undefined ? true : enabledVal === '1' || enabledVal.toLowerCase() === 'true' || enabledVal.toLowerCase() === 'on';
    const hits = Number.parseInt(kvMap.get(`natPolicyHits_${idx}`) || kvMap.get(`natPolicyHitCount_${idx}`) || '0', 10) || 0;

    nats.push({
      id: `EXP-N-${idx}`,
      name: kvMap.get(`natPolicyName_${idx}`) || `NAT #${idx}`,
      priority: Number.parseInt(kvMap.get(`natPolicyPriority_${idx}`) || idx, 10) || Number(idx),
      inboundInterface: kvMap.get(`natPolicyInIf_${idx}`) || 'Any',
      outboundInterface: kvMap.get(`natPolicyOutIf_${idx}`) || 'Any',
      origSource: kvMap.get(`natPolicyOrigSrc_${idx}`) || 'Any',
      transSource: kvMap.get(`natPolicyTransSrc_${idx}`) || 'Original',
      origDestination: kvMap.get(`natPolicyOrigDst_${idx}`) || 'Any',
      transDestination: kvMap.get(`natPolicyTransDst_${idx}`) || 'Original',
      origService: kvMap.get(`natPolicyOrigSvc_${idx}`) || 'Any',
      transService: kvMap.get(`natPolicyTransSvc_${idx}`) || 'Original',
      enabled,
      applianceHits: hits,
      syslogHits: 0,
      lastHitAt: null,
      comment: kvMap.get(`natPolicyComment_${idx}`) || '',
      status: 'active',
      findingReason: '',
      sourceOrigin: 'exp',
    });
  }

  return {
    rules,
    nats,
    model: kvMap.get('model') || kvMap.get('sysModel') || undefined,
    serialNumber: kvMap.get('serialNumber') || kvMap.get('sysSerial') || undefined,
    firmware: kvMap.get('firmwareVersion') || kvMap.get('romVersion') || undefined,
  };
}

function pickStr(obj: Record<string, unknown>, keys: string[], fallback = 'Any'): string {
  for (const k of keys) {
    const val = obj[k];
    if (typeof val === 'string' && val.trim().length > 0) return val;
    if (val && typeof val === 'object' && 'name' in val && typeof (val as Record<string, unknown>).name === 'string') {
      return (val as Record<string, string>).name;
    }
    if (val && typeof val === 'object' && 'any' in val) {
      return 'Any';
    }
  }
  return fallback;
}

export function parseSonicOsJson(rawJson: unknown, origin: 'api' | 'json' = 'json'): {
  rules: FirewallRule[];
  nats: NatPolicy[];
} {
  const data = (rawJson && typeof rawJson === 'object' ? rawJson : {}) as Record<string, unknown>;
  const rawRules = Array.isArray(data.access_rules)
    ? data.access_rules
    : Array.isArray(data.accessRules)
      ? data.accessRules
      : Array.isArray(data.rules)
        ? data.rules
        : [];

  const rawNats = Array.isArray(data.nat_policies)
    ? data.nat_policies
    : Array.isArray(data.natPolicies)
      ? data.natPolicies
      : Array.isArray(data.nats)
        ? data.nats
        : [];

  const rules: FirewallRule[] = rawRules.map((item: unknown, index: number) => {
    const r = (item && typeof item === 'object' ? item : {}) as Record<string, unknown>;
    const ipv4 = (r.ipv4 && typeof r.ipv4 === 'object' ? r.ipv4 : r) as Record<string, unknown>;
    const rawAction = String(ipv4.action || r.action || 'allow').toLowerCase();
    const action: FirewallRule['action'] =
      rawAction === 'deny' ? 'deny' : rawAction === 'discard' || rawAction === 'drop' ? 'discard' : 'allow';

    const hits = Number(ipv4.hits ?? ipv4.hit_count ?? ipv4.applianceHits ?? r.hits ?? 0) || 0;
    const enabled = ipv4.enable !== undefined ? Boolean(ipv4.enable) : r.enabled !== undefined ? Boolean(r.enabled) : true;

    return {
      id: String(ipv4.id || r.id || `R-${index + 1}`),
      uuid: typeof ipv4.uuid === 'string' ? ipv4.uuid : undefined,
      name: pickStr(ipv4, ['name', 'comment'], `Regra ${index + 1}`),
      priority: Number(ipv4.priority ?? r.priority ?? index + 1) || index + 1,
      fromZone: pickStr(ipv4, ['from', 'fromZone'], 'LAN'),
      toZone: pickStr(ipv4, ['to', 'toZone'], 'WAN'),
      source: pickStr(ipv4, ['source', 'src'], 'Any'),
      destination: pickStr(ipv4, ['destination', 'dst'], 'Any'),
      service: pickStr(ipv4, ['service', 'svc'], 'Any'),
      action,
      enabled,
      applianceHits: hits,
      syslogHits: 0,
      lastHitAt: null,
      comment: typeof ipv4.comment === 'string' ? ipv4.comment : '',
      status: 'active',
      findingReason: '',
      sourceOrigin: origin,
    };
  });

  const nats: NatPolicy[] = rawNats.map((item: unknown, index: number) => {
    const n = (item && typeof item === 'object' ? item : {}) as Record<string, unknown>;
    const ipv4 = (n.ipv4 && typeof n.ipv4 === 'object' ? n.ipv4 : n) as Record<string, unknown>;
    const hits = Number(ipv4.hits ?? ipv4.hit_count ?? ipv4.applianceHits ?? n.hits ?? 0) || 0;
    const enabled = ipv4.enable !== undefined ? Boolean(ipv4.enable) : n.enabled !== undefined ? Boolean(n.enabled) : true;

    return {
      id: String(ipv4.id || n.id || `NAT-${index + 1}`),
      uuid: typeof ipv4.uuid === 'string' ? ipv4.uuid : undefined,
      name: pickStr(ipv4, ['name', 'comment'], `NAT ${index + 1}`),
      priority: Number(ipv4.priority ?? n.priority ?? index + 1) || index + 1,
      inboundInterface: pickStr(ipv4, ['inbound', 'inboundInterface'], 'Any'),
      outboundInterface: pickStr(ipv4, ['outbound', 'outboundInterface'], 'Any'),
      origSource: pickStr(ipv4, ['source', 'origSource'], 'Any'),
      transSource: pickStr(ipv4, ['translated_source', 'transSource'], 'Original'),
      origDestination: pickStr(ipv4, ['destination', 'origDestination'], 'Any'),
      transDestination: pickStr(ipv4, ['translated_destination', 'transDestination'], 'Original'),
      origService: pickStr(ipv4, ['service', 'origService'], 'Any'),
      transService: pickStr(ipv4, ['translated_service', 'transService'], 'Original'),
      enabled,
      applianceHits: hits,
      syslogHits: 0,
      lastHitAt: null,
      comment: typeof ipv4.comment === 'string' ? ipv4.comment : '',
      status: 'active',
      findingReason: '',
      sourceOrigin: origin,
    };
  });

  return { rules, nats };
}

function fieldMatches(ruleVal: string, logVal: string | number | null): boolean {
  const normRule = ruleVal.trim().toLowerCase();
  if (!normRule || normRule === 'any' || normRule === '*') return true;
  if (logVal === null || logVal === '-' || logVal === '') return false;
  const normLog = String(logVal).trim().toLowerCase();
  if (normRule === normLog) return true;
  if (normRule.includes(normLog) || normLog.includes(normRule)) return true;

  // Check common SonicWall service names against port numbers
  const port = Number(logVal);
  if (Number.isFinite(port)) {
    const svcPortMap: Record<number, string[]> = {
      22: ['ssh'],
      25: ['smtp'],
      53: ['dns'],
      80: ['http'],
      443: ['https'],
      3389: ['rdp', 'terminal'],
      445: ['smb', 'cifs'],
      500: ['ike', 'ipsec'],
      1194: ['openvpn'],
      8080: ['http-proxy', '8080'],
      8443: ['https-mgmt', '8443'],
    };
    const aliases = svcPortMap[port];
    if (aliases && aliases.some((alias) => normRule.includes(alias))) {
      return true;
    }
  }
  return false;
}

function ruleMatchesEvent(rule: FirewallRule, ev: SyslogEvent): boolean {
  const explicitRuleMatch =
    ev.ruleRef !== null &&
    (ev.ruleRef === rule.id || ev.ruleRef.toLowerCase() === rule.name.toLowerCase());
  if (explicitRuleMatch) return true;

  return (
    ev.action !== 'system' &&
    (rule.fromZone === 'Any' || ev.srcZone === '-' || ev.srcZone.toLowerCase() === rule.fromZone.toLowerCase()) &&
    (rule.toZone === 'Any' || ev.dstZone === '-' || ev.dstZone.toLowerCase() === rule.toZone.toLowerCase()) &&
    fieldMatches(rule.source, ev.srcIp) &&
    fieldMatches(rule.destination, ev.dstIp) &&
    fieldMatches(rule.service, ev.dstPort)
  );
}

function natMatchesEvent(nat: NatPolicy, ev: SyslogEvent): boolean {
  const explicitNatMatch =
    ev.natRuleRef !== null &&
    (ev.natRuleRef === nat.id || ev.natRuleRef.toLowerCase() === nat.name.toLowerCase());
  if (explicitNatMatch) return true;

  return (
    (ev.natDstIp !== null && fieldMatches(nat.transDestination, ev.natDstIp)) ||
    (ev.natSrcIp !== null && fieldMatches(nat.transSource, ev.natSrcIp)) ||
    (nat.origDestination !== 'Any' &&
      fieldMatches(nat.origDestination, ev.dstIp) &&
      fieldMatches(nat.origService, ev.dstPort))
  );
}

/**
 * Soma aos contadores existentes (syslogHits / lastHitAt) apenas os eventos informados.
 * Custo O(políticas × eventos novos), independente do histórico já armazenado.
 */
export function accumulateSyslogHits(
  rules: FirewallRule[],
  nats: NatPolicy[],
  events: SyslogEvent[]
): void {
  if (events.length === 0) return;
  for (const rule of rules) {
    for (const ev of events) {
      if (ruleMatchesEvent(rule, ev)) {
        rule.syslogHits += 1;
        if (!rule.lastHitAt || ev.timestamp > rule.lastHitAt) rule.lastHitAt = ev.timestamp;
      }
    }
  }
  for (const nat of nats) {
    for (const ev of events) {
      if (natMatchesEvent(nat, ev)) {
        nat.syslogHits += 1;
        if (!nat.lastHitAt || ev.timestamp > nat.lastHitAt) nat.lastHitAt = ev.timestamp;
      }
    }
  }
}

/** Copia os contadores de syslog das políticas anteriores para as recém-sincronizadas. */
export function carryOverSyslogHits<T extends { id: string; uuid?: string; syslogHits: number; lastHitAt: string | null }>(
  previous: T[],
  next: T[]
): void {
  const byKey = new Map<string, T>();
  for (const p of previous) {
    byKey.set(p.id, p);
    if (p.uuid) byKey.set(`uuid:${p.uuid}`, p);
  }
  for (const n of next) {
    const old = (n.uuid ? byKey.get(`uuid:${n.uuid}`) : undefined) || byKey.get(n.id);
    if (old) {
      n.syslogHits = old.syslogHits || 0;
      n.lastHitAt = old.lastHitAt ?? null;
    }
  }
}

export interface ClassifyContext {
  /** Início da janela de observação dos syslogs (ISO). */
  observedSince?: string | null;
  /** Uptime do appliance: o contador de hits do firewall zera a cada reboot. */
  uptimeSeconds?: number;
  /**
   * Quando verdadeiro e o appliance entrega contadores (algum > 0), eles são a fonte de verdade para
   * "sem uso". A correlação por syslog é heurística (zona/IP/porta): regras Any→Any e desabilitadas
   * "acertam" milhões de eventos e jamais seriam classificadas como sem uso.
   */
  preferApplianceHits?: boolean;
}

function describeObservation(ctx?: ClassifyContext): string {
  const parts: string[] = [];
  if (ctx?.uptimeSeconds && ctx.uptimeSeconds > 0) {
    const days = ctx.uptimeSeconds / 86400;
    parts.push(
      `contador do appliance cobre ${days >= 1 ? `${Math.floor(days)} dia(s)` : 'menos de 1 dia'} de uptime`
    );
  }
  if (ctx?.observedSince) {
    const ms = Date.parse(ctx.observedSince);
    if (Number.isFinite(ms)) {
      const days = (Date.now() - ms) / 86400000;
      parts.push(
        `syslogs observados há ${days >= 1 ? `${Math.floor(days)} dia(s)` : 'menos de 1 dia'}`
      );
    }
  }
  if (parts.length === 0) return '';
  const shortWindow =
    (ctx?.uptimeSeconds !== undefined && ctx.uptimeSeconds > 0 && ctx.uptimeSeconds < 30 * 86400) ||
    (ctx?.observedSince !== undefined &&
      ctx.observedSince !== null &&
      Date.now() - Date.parse(ctx.observedSince) < 30 * 86400000);
  return ` Janela: ${parts.join('; ')}.${shortWindow ? ' Janela curta (< 30 dias): confirme antes de desabilitar.' : ''}`;
}

/** Recalcula status/achados a partir dos contadores já acumulados (não varre syslogs). */
export function classifyPolicies(
  inputRules: FirewallRule[],
  inputNats: NatPolicy[],
  ctx?: ClassifyContext
): { rules: FirewallRule[]; nats: NatPolicy[] } {
  const sortedRules = [...inputRules].sort((a, b) => a.priority - b.priority);
  const observation = describeObservation(ctx);
  const rulesCounterTrusted = !!ctx?.preferApplianceHits && inputRules.some((r) => r.applianceHits > 0);
  const natsCounterTrusted = !!ctx?.preferApplianceHits && inputNats.some((n) => n.applianceHits > 0);

  const rules: FirewallRule[] = sortedRules.map((rule, idx) => {
    // Sombreada por uma regra anterior mais ampla no mesmo par de zonas
    let shadowedBy: string | undefined;
    let shadowConflict = false;
    for (let j = 0; j < idx; j += 1) {
      const prev = sortedRules[j];
      if (!prev.enabled) continue;
      const sameZone =
        (prev.fromZone === rule.fromZone || prev.fromZone === 'Any') &&
        (prev.toZone === rule.toZone || prev.toZone === 'Any');
      const broaderSrc = prev.source.toLowerCase() === 'any' || prev.source === rule.source;
      const broaderDst = prev.destination.toLowerCase() === 'any' || prev.destination === rule.destination;
      const broaderSvc = prev.service.toLowerCase() === 'any' || prev.service === rule.service;
      if (sameZone && broaderSrc && broaderDst && broaderSvc) {
        shadowedBy = `${prev.id} (${prev.name})`;
        shadowConflict = prev.action !== rule.action;
        break;
      }
    }

    const totalHits = rulesCounterTrusted ? rule.applianceHits : rule.applianceHits + rule.syslogHits;
    const isOverPermissive =
      rule.enabled &&
      rule.action === 'allow' &&
      rule.source.toLowerCase() === 'any' &&
      rule.destination.toLowerCase() === 'any' &&
      rule.service.toLowerCase() === 'any' &&
      (rule.fromZone.toUpperCase() === 'WAN' || rule.toZone.toUpperCase() === 'LAN');

    let status: FirewallRule['status'] = 'active';
    let findingReason = `Tráfego confirmado (${totalHits.toLocaleString('pt-BR')} acertos combinados).`;

    if (!rule.enabled) {
      status = 'disabled';
      findingReason = 'Regra desabilitada na política. Candidata à remoção definitiva após janela de retenção.';
    } else if (shadowedBy) {
      status = 'shadowed';
      findingReason = shadowConflict
        ? `Sombreada pela regra anterior ${shadowedBy}, que tem ação diferente: esta regra nunca é aplicada e o comportamento real é o da regra anterior.`
        : `Sombreada pela regra anterior ${shadowedBy} antes de ser avaliada pelo firewall.`;
    } else if (totalHits === 0) {
      status = 'unused';
      findingReason = rulesCounterTrusted
        ? `Zero acertos no contador do appliance (fonte de verdade).${observation}`
        : `Zero acertos no contador do appliance e zero correspondências nos syslogs analisados.${observation}`;
    } else if (isOverPermissive) {
      status = 'overpermissive';
      findingReason = 'Regra permissiva demais (Any → Any · Any) envolvendo zona sensível.';
    }

    return { ...rule, status, shadowedBy, findingReason };
  });

  const sortedNats = [...inputNats].sort((a, b) => a.priority - b.priority);
  const nats: NatPolicy[] = sortedNats.map((nat) => {
    const totalHits = natsCounterTrusted ? nat.applianceHits : nat.applianceHits + nat.syslogHits;
    const isOrphaned =
      nat.enabled &&
      nat.transDestination !== 'Original' &&
      nat.origDestination !== 'Any' &&
      totalHits === 0 &&
      !rules.some((r) => r.enabled && (r.destination === nat.origDestination || r.destination === nat.transDestination));

    let status: NatPolicy['status'] = 'active';
    let findingReason = `Política NAT em uso (${totalHits.toLocaleString('pt-BR')} traduções observadas).`;

    if (!nat.enabled) {
      status = 'disabled';
      findingReason = 'Política NAT desabilitada. Avaliar remoção para limpar a tabela de tradução.';
    } else if (isOrphaned) {
      status = 'orphaned';
      findingReason = `Zero hits e nenhuma regra de firewall ativa correspondente para o destino traduzido.${observation}`;
    } else if (totalHits === 0) {
      status = 'unused';
      findingReason = `Zero traduções no appliance e nenhuma ocorrência nos syslogs coletados.${observation}`;
    }

    return { ...nat, status, findingReason };
  });

  return { rules, nats };
}

/** Recontagem completa: zera os contadores de syslog, conta todos os eventos e classifica. */
export function correlateTrafficAndRules(
  inputRules: FirewallRule[],
  inputNats: NatPolicy[],
  syslogs: SyslogEvent[],
  ctx?: ClassifyContext
): { rules: FirewallRule[]; nats: NatPolicy[] } {
  const rules = inputRules.map((r) => ({ ...r, syslogHits: 0, lastHitAt: null as string | null }));
  const nats = inputNats.map((n) => ({ ...n, syslogHits: 0, lastHitAt: null as string | null }));
  accumulateSyslogHits(rules, nats, syslogs);
  return classifyPolicies(rules, nats, ctx);
}

/**
 * Formata um identificador para a CLI do SonicOS (convenção validada no SonicWall Migrator):
 * remove aspas e quebras de linha (que quebrariam ou injetariam comandos no script) e
 * coloca entre aspas quando houver espaço ou símbolo.
 */
export function cliName(name: string): string {
  const clean = String(name ?? '').replace(/["\r\n\t]+/g, ' ').trim();
  if (!clean) return '""';
  return /[\s:;.,/()[\]{}*&^%$#@!+=~`|\\]/.test(clean) ? `"${clean}"` : clean;
}

export function generateSonicOsCli(
  rules: FirewallRule[],
  nats: NatPolicy[],
  mode: 'disable' | 'delete'
): string {
  const lines: string[] = [
    '! Script gerado pelo SonicAudit — revisar em ambiente de homologação antes do commit',
    `! Modo selecionado: ${mode === 'disable' ? 'Desabilitar com segurança (reversível)' : 'Remover definitivamente'}`,
    `! Data: ${new Date().toISOString()}`,
    'configure',
  ];

  if (rules.length > 0) {
    lines.push('!');
    lines.push(`! Regras de Firewall (${rules.length})`);
    for (const r of rules) {
      const target = r.uuid
        ? `uuid ${cliName(r.uuid)}`
        : `from ${cliName(r.fromZone)} to ${cliName(r.toZone)} name ${cliName(r.name)}`;
      if (mode === 'disable') {
        lines.push(`access-rule ipv4 ${target}`);
        lines.push('    no enable');
        lines.push('    exit');
      } else {
        lines.push(`no access-rule ipv4 ${target}`);
      }
    }
  }

  if (nats.length > 0) {
    lines.push('!');
    lines.push(`! Políticas NAT (${nats.length})`);
    for (const n of nats) {
      const target = n.uuid ? `uuid ${cliName(n.uuid)}` : `name ${cliName(n.name)}`;
      if (mode === 'disable') {
        lines.push(`nat-policy ipv4 ${target}`);
        lines.push('    no enable');
        lines.push('    exit');
      } else {
        lines.push(`no nat-policy ipv4 ${target}`);
      }
    }
  }

  lines.push('commit');
  lines.push('end');
  return lines.join('\n');
}
