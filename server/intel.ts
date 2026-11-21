import fs from 'node:fs/promises';
import path from 'node:path';
import zlib from 'node:zlib';

/**
 * Inteligência de IP 100% OFFLINE: país (GeoIP), ASN/organização e reputação (blacklist, botnet, Tor).
 * As bases são baixadas para o disco (volume de dados) e consultadas em memória: nenhum IP do cliente
 * sai do servidor. Só o download das bases (listas públicas) usa a internet.
 *
 * Fontes públicas e gratuitas:
 *  - DB-IP Lite (CC BY 4.0): país e ASN por faixa de IPv4 (atualizado mensalmente)
 *  - FireHOL Level 1 e Spamhaus DROP: redes de blacklist
 *  - abuse.ch Feodo Tracker: servidores C2 de botnets
 *  - Tor Project: nós de saída Tor
 * Somente IPv4 por enquanto (IPv6 aparece sem classificação).
 */

export type ThreatCategory = 'blacklist' | 'botnet' | 'tor';

export interface IntelSourceStatus {
  id: string;
  label: string;
  kind: 'geo' | 'asn' | 'list';
  category?: ThreatCategory;
  updatedAt: string | null;
  entries: number;
  error: string | null;
}

export interface IntelStatus {
  updating: boolean;
  lastCheckAt: string | null;
  autoUpdate: boolean;
  ready: boolean;
  sources: IntelSourceStatus[];
}

export interface IntelLookup {
  country: string | null;
  asn: number | null;
  asnOrg: string | null;
  threats: Array<{ list: string; category: ThreatCategory }>;
}

interface RangeIndex {
  starts: Uint32Array;
  ends: Uint32Array;
  values: Array<string | number> | Uint32Array;
}

const EMPTY: RangeIndex = { starts: new Uint32Array(0), ends: new Uint32Array(0), values: [] };

interface ListDef {
  id: string;
  label: string;
  category: ThreatCategory;
  url: string;
}

const LISTS: ListDef[] = [
  {
    id: 'firehol_level1',
    label: 'FireHOL Level 1',
    category: 'blacklist',
    url: 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset',
  },
  { id: 'spamhaus_drop', label: 'Spamhaus DROP', category: 'blacklist', url: 'https://www.spamhaus.org/drop/drop_v4.json' },
  {
    id: 'feodo',
    label: 'abuse.ch Feodo (botnet C2)',
    category: 'botnet',
    url: 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt',
  },
  { id: 'tor_exit', label: 'Tor (nós de saída)', category: 'tor', url: 'https://check.torproject.org/torbulkexitlist' },
];

const LIST_MAX_AGE_MS = 24 * 3600_000;
const DBIP_MAX_AGE_MS = 30 * 24 * 3600_000;
const MAX_DOWNLOAD_BYTES = 200 * 1024 * 1024;

export function ipv4ToInt(ip: string): number | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip.trim());
  if (!m) return null;
  const parts = [m[1], m[2], m[3], m[4]].map(Number);
  if (parts.some((p) => p > 255)) return null;
  return ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
}

function splitCsv(line: string): string[] {
  const out: string[] = [];
  let cur = '';
  let quoted = false;
  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i];
    if (ch === '"') {
      if (quoted && line[i + 1] === '"') {
        cur += '"';
        i += 1;
      } else quoted = !quoted;
    } else if (ch === ',' && !quoted) {
      out.push(cur);
      cur = '';
    } else cur += ch;
  }
  out.push(cur);
  return out;
}

function lookupRange(idx: RangeIndex, n: number): number {
  let lo = 0;
  let hi = idx.starts.length - 1;
  let found = -1;
  while (lo <= hi) {
    const mid = (lo + hi) >>> 1;
    if (idx.starts[mid] <= n) {
      found = mid;
      lo = mid + 1;
    } else hi = mid - 1;
  }
  return found >= 0 && n <= idx.ends[found] ? found : -1;
}

/** Faixas de um CSV do DB-IP (start,end,valor...). Só IPv4; já vem ordenado. */
export function parseDbIpCsv(text: string, kind: 'geo' | 'asn'): RangeIndex {
  const starts: number[] = [];
  const ends: number[] = [];
  const values: Array<string | number> = [];
  const orgs: string[] = [];
  const orgIdx = new Map<string, number>();
  const asnValues: number[] = [];
  for (const line of text.split('\n')) {
    if (!line || line.includes(':')) continue; // pula IPv6
    const f = splitCsv(line.replace(/\r$/, ''));
    if (f.length < 3) continue;
    const s = ipv4ToInt(f[0]);
    const e = ipv4ToInt(f[1]);
    if (s === null || e === null) continue;
    starts.push(s);
    ends.push(e);
    if (kind === 'geo') {
      values.push(f[2].toUpperCase());
    } else {
      const asn = Number(f[2]);
      if (!Number.isFinite(asn) || asn <= 0) {
        starts.pop();
        ends.pop();
        continue;
      }
      asnValues.push(asn);
      const org = (f[3] ?? '').trim();
      let id = orgIdx.get(org);
      if (id === undefined) {
        id = orgs.length;
        orgs.push(org);
        orgIdx.set(org, id);
      }
      values.push(id);
    }
  }
  const idx: RangeIndex = { starts: Uint32Array.from(starts), ends: Uint32Array.from(ends), values };
  if (kind === 'asn') {
    (idx as RangeIndex & { asns: Uint32Array; orgs: string[] }).asns = Uint32Array.from(asnValues);
    (idx as RangeIndex & { asns: Uint32Array; orgs: string[] }).orgs = orgs;
  }
  return idx;
}

/** Lista de CIDRs/IPs (um por linha, # ou ; comentam; também aceita JSON por linha com "cidr"). */
export function parseCidrList(text: string): RangeIndex {
  const ranges: Array<[number, number]> = [];
  for (const rawLine of text.split('\n')) {
    let line = rawLine.trim();
    if (!line) continue;
    if (line.startsWith('{')) {
      try {
        const cidr = (JSON.parse(line) as { cidr?: string }).cidr;
        if (!cidr) continue;
        line = cidr;
      } catch {
        continue;
      }
    }
    line = line.split(/[#;]/)[0].trim();
    if (!line) continue;
    const token = line.split(/[\s,]/)[0];
    const [addr, bitsRaw] = token.split('/');
    const base = ipv4ToInt(addr);
    if (base === null) continue;
    const bits = bitsRaw === undefined ? 32 : Number(bitsRaw);
    if (!Number.isInteger(bits) || bits < 0 || bits > 32) continue;
    const size = bits === 0 ? 2 ** 32 : 2 ** (32 - bits);
    const start = Math.floor(base / size) * size;
    ranges.push([start, start + size - 1]);
  }
  ranges.sort((a, b) => a[0] - b[0]);
  const merged: Array<[number, number]> = [];
  for (const r of ranges) {
    const last = merged[merged.length - 1];
    if (last && r[0] <= last[1] + 1) last[1] = Math.max(last[1], r[1]);
    else merged.push([r[0], r[1]]);
  }
  return {
    starts: Uint32Array.from(merged.map((r) => r[0])),
    ends: Uint32Array.from(merged.map((r) => r[1])),
    values: [],
  };
}

type AsnIndex = RangeIndex & { asns?: Uint32Array; orgs?: string[] };

interface Meta {
  sources: Record<string, { updatedAt: string | null; error: string | null }>;
  lastCheckAt: string | null;
}

export interface Intel {
  lookup(ip: string): IntelLookup;
  status(): IntelStatus;
  update(): Promise<IntelStatus>;
  start(): Promise<void>;
  stop(): void;
}

export function createIntel(dataDir: string, options: { autoUpdate?: boolean } = {}): Intel {
  const dir = path.join(dataDir, 'intel');
  const autoUpdate = options.autoUpdate ?? process.env.INTEL_AUTO_UPDATE !== 'false';
  let geo: RangeIndex = EMPTY;
  let asn: AsnIndex = EMPTY;
  const lists = new Map<string, RangeIndex>();
  let meta: Meta = { sources: {}, lastCheckAt: null };
  let updating = false;
  let timer: NodeJS.Timeout | null = null;

  const file = (name: string) => path.join(dir, name);

  async function readMeta() {
    try {
      meta = JSON.parse(await fs.readFile(file('meta.json'), 'utf8')) as Meta;
    } catch {
      meta = { sources: {}, lastCheckAt: null };
    }
  }
  const writeMeta = () => fs.writeFile(file('meta.json'), JSON.stringify(meta, null, 2)).catch(() => undefined);

  async function loadFromDisk() {
    const readGz = async (name: string) => zlib.gunzipSync(await fs.readFile(file(name))).toString('utf8');
    try {
      geo = parseDbIpCsv(await readGz('country.csv.gz'), 'geo');
    } catch {
      /* ainda não baixado */
    }
    try {
      asn = parseDbIpCsv(await readGz('asn.csv.gz'), 'asn');
    } catch {
      /* ainda não baixado */
    }
    for (const def of LISTS) {
      try {
        lists.set(def.id, parseCidrList(await fs.readFile(file(`${def.id}.txt`), 'utf8')));
      } catch {
        /* ainda não baixado */
      }
    }
  }

  async function download(url: string): Promise<Buffer> {
    const res = await fetch(url, {
      headers: { 'User-Agent': 'fw-audit-intel/1.0' },
      signal: AbortSignal.timeout(180_000),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const buf = Buffer.from(await res.arrayBuffer());
    if (buf.length > MAX_DOWNLOAD_BYTES) throw new Error('arquivo grande demais');
    return buf;
  }

  async function atomicWrite(name: string, data: Buffer | string) {
    const tmp = file(`${name}.tmp`);
    await fs.writeFile(tmp, data);
    await fs.rename(tmp, file(name));
  }

  const stamp = (id: string, error: string | null, ok: boolean) => {
    const prev = meta.sources[id];
    meta.sources[id] = { updatedAt: ok ? new Date().toISOString() : (prev?.updatedAt ?? null), error };
  };

  async function updateDbIp(kind: 'geo' | 'asn') {
    const id = kind === 'geo' ? 'dbip_country' : 'dbip_asn';
    const slug = kind === 'geo' ? 'dbip-country-lite' : 'dbip-asn-lite';
    const now = new Date();
    const candidates = [0, 1, 2].map((back) => {
      const d = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - back, 1));
      return `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, '0')}`;
    });
    let lastErr = 'indisponível';
    for (const ym of candidates) {
      try {
        const gz = await download(`https://download.db-ip.com/free/${slug}-${ym}.csv.gz`);
        const parsed = parseDbIpCsv(zlib.gunzipSync(gz).toString('utf8'), kind);
        if (parsed.starts.length < 1000) throw new Error('base inválida');
        await atomicWrite(kind === 'geo' ? 'country.csv.gz' : 'asn.csv.gz', gz);
        if (kind === 'geo') geo = parsed;
        else asn = parsed;
        stamp(id, null, true);
        return;
      } catch (err) {
        lastErr = err instanceof Error ? err.message : String(err);
      }
    }
    stamp(id, lastErr, false);
  }

  async function updateList(def: ListDef) {
    try {
      const text = (await download(def.url)).toString('utf8');
      const parsed = parseCidrList(text);
      if (parsed.starts.length === 0) throw new Error('lista vazia');
      await atomicWrite(`${def.id}.txt`, text);
      lists.set(def.id, parsed);
      stamp(def.id, null, true);
    } catch (err) {
      stamp(def.id, err instanceof Error ? err.message : String(err), false);
    }
  }

  async function runUpdate(only?: 'due'): Promise<void> {
    if (updating) return;
    updating = true;
    try {
      await fs.mkdir(dir, { recursive: true });
      const age = (id: string) => {
        const t = meta.sources[id]?.updatedAt;
        return t ? Date.now() - Date.parse(t) : Infinity;
      };
      const due = (id: string, max: number) => only !== 'due' || age(id) > max;
      if (due('dbip_country', DBIP_MAX_AGE_MS)) await updateDbIp('geo');
      if (due('dbip_asn', DBIP_MAX_AGE_MS)) await updateDbIp('asn');
      for (const def of LISTS) if (due(def.id, LIST_MAX_AGE_MS)) await updateList(def);
      meta.lastCheckAt = new Date().toISOString();
      await writeMeta();
    } finally {
      updating = false;
    }
  }

  const status = (): IntelStatus => {
    const src = (
      id: string,
      label: string,
      kind: IntelSourceStatus['kind'],
      entries: number,
      category?: ThreatCategory
    ): IntelSourceStatus => ({
      id,
      label,
      kind,
      category,
      updatedAt: meta.sources[id]?.updatedAt ?? null,
      entries,
      error: meta.sources[id]?.error ?? null,
    });
    return {
      updating,
      lastCheckAt: meta.lastCheckAt,
      autoUpdate,
      ready: geo.starts.length > 0,
      sources: [
        src('dbip_country', 'DB-IP Lite · País', 'geo', geo.starts.length),
        src('dbip_asn', 'DB-IP Lite · ASN', 'asn', asn.starts.length),
        ...LISTS.map((d) => src(d.id, d.label, 'list', lists.get(d.id)?.starts.length ?? 0, d.category)),
      ],
    };
  };

  return {
    lookup(ip: string): IntelLookup {
      const n = ipv4ToInt(ip);
      if (n === null) return { country: null, asn: null, asnOrg: null, threats: [] };
      const g = lookupRange(geo, n);
      const country = g >= 0 ? String(geo.values[g]) : null;
      const a = lookupRange(asn, n);
      const asnNumber = a >= 0 && asn.asns ? asn.asns[a] : null;
      const asnOrg = a >= 0 && asn.orgs ? (asn.orgs[Number(asn.values[a])] ?? null) : null;
      const threats: IntelLookup['threats'] = [];
      for (const def of LISTS) {
        const idx = lists.get(def.id);
        if (idx && lookupRange(idx, n) >= 0) threats.push({ list: def.label, category: def.category });
      }
      return {
        country: country && country !== 'ZZ' ? country : null,
        asn: asnNumber,
        asnOrg: asnOrg || null,
        threats,
      };
    },
    status,
    async update() {
      await runUpdate();
      return status();
    },
    async start() {
      await fs.mkdir(dir, { recursive: true }).catch(() => undefined);
      await readMeta();
      await loadFromDisk();
      if (!autoUpdate) return;
      // Primeira vez (ou base vencida): baixa em segundo plano, sem atrasar a subida do servidor
      setTimeout(() => void runUpdate('due').catch(() => undefined), 15_000).unref();
      timer = setInterval(() => void runUpdate('due').catch(() => undefined), 3600_000);
      timer.unref();
    },
    stop() {
      if (timer) clearInterval(timer);
    },
  };
}
