/**
 * Lógica de destinos compartilhada entre servidor e interface: tipos, classificação por
 * domínio/serviço, escopo de IP e resumos (Top 5 e fatos). Sem dependências de Node ou do DOM.
 */
export type DestinationScope = 'public' | 'internal' | 'multicast';

export interface DestinationService {
  name: string;
  count: number;
}

export interface DestinationNode {
  /** Chave estável: FQDN em minúsculas ou o IP. */
  id: string;
  label: string;
  host: string | null;
  hostSource: 'log' | 'rdns' | null;
  ip: string;
  ips: string[];
  /** Domínio registrável (ex.: microsoft.com) quando o FQDN é conhecido. */
  group: string | null;
  scope: DestinationScope;
  category: string;
  connections: number;
  blocked: number;
  bytes: number;
  sources: number;
  /** Quem mais acessa este destino (IPs de origem), do maior para o menor. */
  topSources: Array<{ ip: string; count: number }>;
  services: DestinationService[];
  lastSeen: string | null;
}

export interface DestinationsReport {
  generatedAt: string;
  minutes: number;
  analyzedEvents: number;
  windowSize: number;
  totalConnections: number;
  resolver: { enabled: boolean; resolved: number; pending: number };
  nodes: DestinationNode[];
  omitted: { destinations: number; connections: number };
  /** Filtro por IP de origem aplicado (vazio = todo o tráfego). */
  srcIp?: string;
  /** Filtro por destino (nome/domínio/IP) e os IPs exatos do destino clicado. */
  dst?: string;
  dstIps?: string[];
  /** De onde vieram os eventos: janela em memória ou consulta ao banco (filtro por origem). */
  dataSource?: 'memory' | 'database';
  /** true quando a consulta ao banco atingiu o limite de eventos e há mais dados que o exibido. */
  truncated?: boolean;
}

export type DestinationMetric = 'connections' | 'bytes';

// ---------------------------------------------------------------------------
// Endereços e domínios
// ---------------------------------------------------------------------------

const IPV4 = /^(?:\d{1,3}\.){3}\d{1,3}$/;

export function isIpAddress(value: string): boolean {
  return IPV4.test(value) || (value.includes(':') && /^[0-9a-f:.]+$/i.test(value));
}

export function ipScope(ip: string): DestinationScope {
  if (IPV4.test(ip)) {
    const [a, b] = ip.split('.').map(Number);
    if (a >= 224 && a <= 239) return 'multicast';
    if (ip === '255.255.255.255') return 'multicast';
    if (a === 10 || a === 127 || a === 0) return 'internal';
    if (a === 172 && b >= 16 && b <= 31) return 'internal';
    if (a === 192 && b === 168) return 'internal';
    if (a === 169 && b === 254) return 'internal';
    if (a === 100 && b >= 64 && b <= 127) return 'internal';
    return 'public';
  }
  const lower = ip.toLowerCase();
  if (lower.startsWith('ff')) return 'multicast';
  if (lower === '::1' || lower.startsWith('fe80') || lower.startsWith('fc') || lower.startsWith('fd')) {
    return 'internal';
  }
  return 'public';
}

const SECOND_LEVEL = new Set(['co', 'com', 'org', 'net', 'gov', 'edu', 'ac', 'gob']);

/** Domínio registrável aproximado (sem lista pública de sufixos): last two labels, ou três em xx.com.br. */
export function registrableDomain(host: string): string {
  const labels = host.toLowerCase().replace(/\.$/, '').split('.').filter(Boolean);
  if (labels.length <= 2) return labels.join('.');
  const tld = labels[labels.length - 1];
  const sld = labels[labels.length - 2];
  if (tld.length === 2 && SECOND_LEVEL.has(sld)) return labels.slice(-3).join('.');
  return labels.slice(-2).join('.');
}

/** Primeiro rótulo para exibir dentro de uma bolha (ex.: pki.goog → pki.goog; a.b.microsoft.com → a.b). */
export function shortHostLabel(host: string, group: string | null): string {
  if (group && host !== group && host.endsWith(`.${group}`)) {
    return host.slice(0, host.length - group.length - 1);
  }
  return host;
}

// ---------------------------------------------------------------------------
// Pistas de FQDN e categoria nas linhas de log
// ---------------------------------------------------------------------------

const HOST_KEYS = ['dstname', 'dst_name', 'dsthost', 'hostname', 'dstdomain', 'fqdn', 'domain', 'url'];
const CATEGORY_KEYS = ['appcat', 'catdesc'];

function kvPairs(raw: string): Record<string, string> {
  const out: Record<string, string> = {};
  const re = /([A-Za-z_][\w-]*)=("([^"]*)"|\S+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(raw)) !== null) {
    const key = m[1].toLowerCase();
    if (!(key in out)) out[key] = (m[3] ?? m[2]).trim();
  }
  return out;
}

function cleanHost(value: string): string | null {
  const m = /^(?:[a-z][a-z0-9+.-]*:\/\/)?([^/:?#\s"]+)/i.exec(value.trim());
  if (!m) return null;
  const host = m[1].toLowerCase().replace(/\.$/, '');
  if (!host.includes('.') || isIpAddress(host)) return null;
  if (!/^[a-z0-9_]([a-z0-9._-]*[a-z0-9])?$/.test(host)) return null;
  return host;
}

export function extractDestinationHints(raw: string): { host: string | null; appCategory: string | null } {
  if (!raw) return { host: null, appCategory: null };
  const kv = kvPairs(raw);
  let host: string | null = null;
  for (const key of HOST_KEYS) {
    if (kv[key]) {
      host = cleanHost(kv[key]);
      if (host) break;
    }
  }
  let appCategory: string | null = null;
  for (const key of CATEGORY_KEYS) {
    if (kv[key]) {
      appCategory = kv[key];
      break;
    }
  }
  return { host, appCategory };
}

// ---------------------------------------------------------------------------
// Serviços e categorias
// ---------------------------------------------------------------------------

const PORT_SERVICES: Record<number, string> = {
  20: 'FTP', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 67: 'DHCP', 68: 'DHCP',
  80: 'HTTP', 110: 'POP3', 123: 'NTP', 137: 'NetBIOS', 138: 'NetBIOS', 139: 'NetBIOS', 143: 'IMAP',
  161: 'SNMP', 162: 'SNMP', 389: 'LDAP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS', 500: 'IPsec',
  514: 'Syslog', 587: 'SMTP', 636: 'LDAPS', 853: 'DoT', 993: 'IMAPS', 995: 'POP3S', 1194: 'OpenVPN',
  1433: 'MSSQL', 1521: 'Oracle', 3306: 'MySQL', 3389: 'RDP', 4500: 'IPsec', 5060: 'SIP', 5061: 'SIP',
  5353: 'mDNS', 5432: 'PostgreSQL', 5900: 'VNC', 8080: 'HTTP-alt', 8443: 'HTTPS-alt', 27017: 'MongoDB',
};

export function serviceLabel(protocol: string, port: number | null, appName: string | null): string {
  if (appName && appName.trim() && appName !== '-') return appName.trim();
  if (port !== null && PORT_SERVICES[port]) return PORT_SERVICES[port];
  const proto = (protocol || '').split('/').pop()?.toUpperCase() || '';
  if (port !== null) return proto ? `${proto}/${port}` : String(port);
  return proto || 'Outro';
}

type CategoryRule = { category: string; test: RegExp };

const DOMAIN_RULES: CategoryRule[] = [
  { category: 'Segurança online', test: /(digicert|ocsp|crl\.|pki\.goog|letsencrypt|sectigo|globalsign|verisign|entrust|bitdefender|fortinet|fortiguard|sonicwall|kaspersky|virustotal|symantec|threatpulse|crowdstrike|sophos)/ },
  { category: 'Software e atualizações', test: /(microsoft\.|windowsupdate|msftconnecttest|msedge|office\.|office365|live\.com|apple\.com|mzstatic|ubuntu\.com|debian\.org|adobe\.|oracle\.com|java\.com|mozilla)/ },
  { category: 'Comunicação', test: /(whatsapp|zoom\.us|slack\.|skype|telegram|webex|discord|teams\.)/ },
  { category: 'Acesso remoto', test: /(anydesk|teamviewer|rustdesk|logmein|splashtop)/ },
  { category: 'Mídia e entretenimento', test: /(youtube|googlevideo|netflix|spotify|twitch|tiktok|vimeo)/ },
  { category: 'Redes sociais', test: /(facebook|fbcdn|instagram|linkedin|twitter|twimg|x\.com|pinterest|reddit)/ },
  { category: 'E-mail', test: /(gmail|outlook\.com|protonmail|zoho)/ },
  { category: 'Publicidade e telemetria', test: /(doubleclick|googlesyndication|googleadservices|scorecardresearch|demdex|adnxs|hotjar|segment\.io|datadoghq|sentry\.io)/ },
  { category: 'Nuvem e hospedagem', test: /(amazonaws|azure|cloudapp|cloudflare|akamai|fastly|googleusercontent|cloudfront|digitalocean|linode|hetzner|ovh|gstatic|appspot|herokuapp|vercel)/ },
  { category: 'DNS e infraestrutura', test: /(dns\.google|one\.one\.one\.one|quad9|opendns|ntp\.org|pool\.ntp)/ },
  { category: 'Busca e web', test: /(google\.com|bing\.com|duckduckgo|yahoo\.com)/ },
];

const SERVICE_CATEGORIES: Array<{ category: string; services: string[] }> = [
  { category: 'DNS e infraestrutura', services: ['DNS', 'DoT', 'NTP', 'DHCP', 'mDNS', 'NetBIOS'] },
  { category: 'E-mail', services: ['SMTP', 'SMTPS', 'IMAP', 'IMAPS', 'POP3', 'POP3S'] },
  { category: 'Acesso remoto', services: ['SSH', 'RDP', 'Telnet', 'VNC'] },
  { category: 'Arquivos e diretório', services: ['SMB', 'FTP', 'LDAP', 'LDAPS'] },
  { category: 'Bancos de dados', services: ['MSSQL', 'MySQL', 'PostgreSQL', 'Oracle', 'MongoDB'] },
  { category: 'Gerenciamento', services: ['SNMP', 'Syslog'] },
  { category: 'VPN', services: ['IPsec', 'OpenVPN'] },
  { category: 'Voz e vídeo', services: ['SIP'] },
  { category: 'Web', services: ['HTTP', 'HTTPS', 'HTTP-alt', 'HTTPS-alt'] },
];

const APPCAT_MAP: Array<[RegExp, string]> = [
  [/update/i, 'Software e atualizações'],
  [/(cloud|storage|backup)/i, 'Nuvem e hospedagem'],
  [/(video|audio|streaming|game)/i, 'Mídia e entretenimento'],
  [/social/i, 'Redes sociais'],
  [/(collab|voip|im\b|chat)/i, 'Comunicação'],
  [/(remote)/i, 'Acesso remoto'],
  [/(email|mail)/i, 'E-mail'],
  [/(network\.service|infra)/i, 'DNS e infraestrutura'],
  [/(security|malware|botnet)/i, 'Segurança online'],
  [/(advert|tracking)/i, 'Publicidade e telemetria'],
  [/(web|browser|client)/i, 'Web'],
];

export function classifyDestination(input: {
  host: string | null;
  service: string;
  appCategory: string | null;
  scope: DestinationScope;
}): string {
  const host = input.host?.toLowerCase() ?? '';
  if (host) {
    for (const rule of DOMAIN_RULES) if (rule.test.test(host)) return rule.category;
  }
  if (input.scope === 'multicast') return 'Multicast e descoberta';
  if (input.appCategory) {
    for (const [re, category] of APPCAT_MAP) if (re.test(input.appCategory)) return category;
  }
  const svc = input.service.split(/[./\s]/)[0];
  for (const entry of SERVICE_CATEGORIES) {
    if (entry.services.some((s) => s.toLowerCase() === svc.toLowerCase())) return entry.category;
  }
  if (input.scope === 'internal') return 'Rede interna';
  return 'Outros';
}

// ---------------------------------------------------------------------------
// Resumos para a interface
// ---------------------------------------------------------------------------

export function nodeValue(node: DestinationNode, metric: DestinationMetric): number {
  return metric === 'bytes' ? node.bytes : node.connections;
}

export interface DestinationsSummary {
  total: number;
  top: Array<{ node: DestinationNode; value: number; share: number }>;
  categories: Array<{ category: string; value: number; share: number }>;
  facts: string[];
}

export function summarizeDestinations(
  nodes: DestinationNode[],
  metric: DestinationMetric,
  extra?: { omittedValue?: number }
): DestinationsSummary {
  const sorted = [...nodes].sort((a, b) => nodeValue(b, metric) - nodeValue(a, metric));
  const total = sorted.reduce((s, n) => s + nodeValue(n, metric), 0) + (extra?.omittedValue ?? 0);
  const share = (v: number) => (total > 0 ? v / total : 0);

  const top = sorted.slice(0, 5).map((node) => ({
    node,
    value: nodeValue(node, metric),
    share: share(nodeValue(node, metric)),
  }));

  const byCategory = new Map<string, number>();
  for (const n of sorted) byCategory.set(n.category, (byCategory.get(n.category) ?? 0) + nodeValue(n, metric));
  const categories = [...byCategory.entries()]
    .map(([category, value]) => ({ category, value, share: share(value) }))
    .sort((a, b) => b.value - a.value)
    .slice(0, 5);

  const facts: string[] = [];
  if (total > 0 && sorted.length > 0) {
    const top10 = sorted.slice(0, 10).reduce((s, n) => s + nodeValue(n, metric), 0);
    const unit = metric === 'bytes' ? 'do volume' : 'das conexões';
    facts.push(`${(share(top10) * 100).toFixed(1)}% ${unit} vão para os ${Math.min(10, sorted.length)} principais destinos.`);
    const outside = sorted.slice(50).reduce((s, n) => s + nodeValue(n, metric), 0) + (extra?.omittedValue ?? 0);
    if (outside > 0) {
      facts.push(`${(share(outside) * 100).toFixed(1)}% ${unit} vão para destinos fora dos 50 maiores.`);
    }
    const connTotal = nodes.reduce((s, n) => s + n.connections, 0);
    const blocked = nodes.reduce((s, n) => s + n.blocked, 0);
    if (connTotal > 0 && blocked > 0) {
      facts.push(`${((blocked / connTotal) * 100).toFixed(1)}% das conexões observadas foram bloqueadas.`);
    }
  }
  return { total, top, categories, facts };
}

export function formatCompact(value: number): string {
  if (value >= 1e9) return `${(value / 1e9).toFixed(value >= 1e10 ? 0 : 1)}B`;
  if (value >= 1e6) return `${(value / 1e6).toFixed(value >= 1e7 ? 0 : 1)}M`;
  if (value >= 1e3) return `${(value / 1e3).toFixed(value >= 1e4 ? 0 : 1)}K`;
  return String(Math.round(value));
}

export function formatBytes(value: number): string {
  if (value >= 1024 ** 3) return `${(value / 1024 ** 3).toFixed(1)} GB`;
  if (value >= 1024 ** 2) return `${(value / 1024 ** 2).toFixed(1)} MB`;
  if (value >= 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${value} B`;
}
