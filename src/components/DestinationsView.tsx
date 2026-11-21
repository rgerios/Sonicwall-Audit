import { useCallback, useEffect, useMemo, useState } from 'react';
import { Flame, Radar, RotateCcw, Search, X } from 'lucide-react';
import type {
  DestinationMetric,
  DestinationNode,
  DestinationsReport,
  FirewallVendor,
  SourceNode,
  SourcesReport,
} from '../types.ts';
import { formatBytes, formatCompact, nodeValue, summarizeDestinations } from '../../shared/destinations.ts';
import { sourceValue, summarizeSources } from '../../shared/sources.ts';
import { vendorApiUrl } from '../utils/vendorApi.ts';
import { BubbleStage, type BubbleItem } from './BubbleStage.tsx';

interface DestinationsViewProps {
  vendor: FirewallVendor;
  refreshToken: number;
  onInvestigate: (query: string) => void;
  onGoToConnect: () => void;
}

type View = 'destinations' | 'sources';
type Scope = 'all' | 'public' | 'internal';
/** Filtro por destino: o rótulo aparece no chip; texto e IPs vão para o servidor. */
interface DstFilter {
  label: string;
  text: string;
  ips: string[];
}

const RANGES: Array<{ label: string; minutes: number }> = [
  { label: '15 min', minutes: 15 },
  { label: '1 h', minutes: 60 },
  { label: '6 h', minutes: 360 },
  { label: '24 h', minutes: 1440 },
  { label: 'Tudo', minutes: 0 },
];

const MAX_BUBBLES = 60;
const CATEGORY_COLORS = ['#2563eb', '#db2777', '#059669', '#d97706', '#7c3aed', '#0891b2', '#dc2626', '#4d7c0f', '#c026d3', '#475569'];

function categoryColor(category: string): string {
  let h = 0;
  for (let i = 0; i < category.length; i += 1) h = (h * 31 + category.charCodeAt(i)) >>> 0;
  return CATEGORY_COLORS[h % CATEGORY_COLORS.length];
}

function matchesDestQuery(node: DestinationNode, query: string): boolean {
  const q = query.trim().toLowerCase();
  if (!q) return true;
  return (
    node.label.toLowerCase().includes(q) ||
    (node.group ?? '').toLowerCase().includes(q) ||
    node.category.toLowerCase().includes(q) ||
    node.ips.some((ip) => ip.includes(q))
  );
}

function matchesSourceQuery(node: SourceNode, query: string): boolean {
  const q = query.trim().toLowerCase();
  if (!q) return true;
  return (
    node.ip.includes(q) ||
    (node.user ?? '').toLowerCase().includes(q) ||
    node.zone.toLowerCase().includes(q) ||
    (node.group ?? '').includes(q) ||
    node.topDestinations.some((d) => d.label.toLowerCase().includes(q))
  );
}

const scopeMatches = (scope: Scope, nodeScope: 'public' | 'internal' | 'multicast') =>
  scope === 'all' || (scope === 'public' ? nodeScope === 'public' : nodeScope !== 'public');

function segmentButton(active: boolean): string {
  return `px-2.5 py-1.5 text-xs font-medium rounded whitespace-nowrap ${
    active ? 'bg-white text-[var(--fw-heading)] shadow-xs' : 'text-[var(--fw-text-body)]'
  }`;
}

export function DestinationsView({ vendor, refreshToken, onInvestigate, onGoToConnect }: DestinationsViewProps) {
  const [view, setView] = useState<View>('destinations');
  const [destReport, setDestReport] = useState<DestinationsReport | null>(null);
  const [srcReport, setSrcReport] = useState<SourcesReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [minutes, setMinutes] = useState(60);
  const [metric, setMetric] = useState<DestinationMetric>('connections');
  const [scope, setScope] = useState<Scope>('all');
  const [category, setCategory] = useState('all');
  const [heat, setHeat] = useState(true);
  const [query, setQuery] = useState('');
  const [hovered, setHovered] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [resetSignal, setResetSignal] = useState(0);
  // Filtros enviados ao servidor: origem (IP/prefixo) e destino (nome, domínio ou IP)
  const [srcIpInput, setSrcIpInput] = useState('');
  const [srcIp, setSrcIp] = useState('');
  const [dstInput, setDstInput] = useState('');
  const [dst, setDst] = useState<DstFilter | null>(null);

  const load = useCallback(
    async (signal?: AbortSignal) => {
      try {
        const params = new URLSearchParams({ minutes: String(minutes) });
        if (srcIp) params.set('srcIp', srcIp);
        if (dst?.text) params.set('dst', dst.text);
        if (dst?.ips.length) params.set('dstIps', dst.ips.join(','));
        const res = await fetch(vendorApiUrl(vendor, `/${view}?${params.toString()}`), { signal });
        if (!res.ok) {
          const data = (await res.json().catch(() => ({}))) as { error?: string };
          throw new Error(data.error || `HTTP ${res.status}`);
        }
        if (view === 'destinations') setDestReport((await res.json()) as DestinationsReport);
        else setSrcReport((await res.json()) as SourcesReport);
        setError(null);
      } catch (err) {
        if (err instanceof DOMException && err.name === 'AbortError') return;
        setError(
          err instanceof Error && err.message && !/^HTTP \d+$/.test(err.message)
            ? err.message
            : 'Não foi possível carregar os dados.'
        );
      } finally {
        setLoading(false);
      }
    },
    [vendor, view, minutes, srcIp, dst]
  );

  useEffect(() => {
    setLoading(true);
    const controller = new AbortController();
    void load(controller.signal);
    // Atualiza sozinho: os nomes do DNS reverso chegam em segundo plano
    const timer = setInterval(() => {
      if (document.visibilityState === 'visible') void load(controller.signal);
    }, 10000);
    return () => {
      controller.abort();
      clearInterval(timer);
    };
  }, [load, refreshToken]);

  useEffect(() => {
    setSelectedId(null);
    setCategory('all');
    setSrcIp('');
    setSrcIpInput('');
    setDst(null);
    setDstInput('');
    setQuery('');
    setDestReport(null);
    setSrcReport(null);
  }, [vendor]);

  // ---------- ações de filtro (inclusive os filtros cruzados entre as abas) ----------
  const applySource = (ip: string) => {
    setSrcIpInput(ip);
    setSrcIp(ip.trim().toLowerCase());
    setSelectedId(null);
  };
  const applyDestination = (next: DstFilter | null) => {
    setDst(next);
    setDstInput(next?.label ?? '');
    setSelectedId(null);
  };
  const destinationFilterFor = (n: DestinationNode): DstFilter =>
    n.host ? { label: n.host, text: n.host, ips: n.ips } : { label: n.ip, text: '', ips: [n.ip] };

  const submitFilters = (e: React.FormEvent) => {
    e.preventDefault();
    applySource(srcIpInput);
    const typed = dstInput.trim().toLowerCase();
    // Se o texto não mudou, mantém os IPs exatos do destino já escolhido por clique
    if (dst && typed === dst.label.toLowerCase()) return;
    applyDestination(typed ? { label: typed, text: typed, ips: [] } : null);
  };

  const switchView = (next: View) => {
    if (next === view) return;
    setView(next);
    setSelectedId(null);
    setHovered(null);
    setLoading(true);
  };

  const resetAll = () => {
    setResetSignal((n) => n + 1);
    setSelectedId(null);
    setCategory('all');
    setScope('all');
    setHovered(null);
    setSrcIp('');
    setSrcIpInput('');
    setDst(null);
    setDstInput('');
    setQuery('');
  };

  // ---------- dados da aba Destinos ----------
  const destNodes = destReport?.nodes ?? [];
  const destFiltered = useMemo(
    () =>
      destNodes.filter(
        (n) =>
          scopeMatches(scope, n.scope) &&
          (category === 'all' || n.category === category) &&
          matchesDestQuery(n, query)
      ),
    [destNodes, scope, category, query]
  );
  const destVisible = useMemo(
    () => [...destFiltered].sort((a, b) => nodeValue(b, metric) - nodeValue(a, metric)).slice(0, MAX_BUBBLES),
    [destFiltered, metric]
  );
  const destSummary = useMemo(
    () =>
      summarizeDestinations(destFiltered, metric, {
        omittedValue:
          scope === 'all' && category === 'all' && !query.trim() && destReport && metric === 'connections'
            ? destReport.omitted.connections
            : 0,
      }),
    [destFiltered, metric, scope, category, query, destReport]
  );
  const destById = useMemo(() => new Map(destVisible.map((n) => [n.id, n])), [destVisible]);

  // ---------- dados da aba Origens ----------
  const srcNodes = srcReport?.nodes ?? [];
  const srcFiltered = useMemo(
    () =>
      srcNodes.filter(
        (n) =>
          scopeMatches(scope, n.scope) &&
          (category === 'all' || n.categories.some((c) => c.name === category)) &&
          matchesSourceQuery(n, query)
      ),
    [srcNodes, scope, category, query]
  );
  const srcVisible = useMemo(
    () => [...srcFiltered].sort((a, b) => sourceValue(b, metric) - sourceValue(a, metric)).slice(0, MAX_BUBBLES),
    [srcFiltered, metric]
  );
  const srcSummary = useMemo(
    () =>
      summarizeSources(srcFiltered, metric, {
        omittedValue:
          scope === 'all' && category === 'all' && !query.trim() && srcReport && metric === 'connections'
            ? srcReport.omitted.connections
            : 0,
      }),
    [srcFiltered, metric, scope, category, query, srcReport]
  );
  const srcById = useMemo(() => new Map(srcVisible.map((n) => [n.id, n])), [srcVisible]);

  const categories = useMemo(() => {
    const set = new Set<string>();
    if (view === 'destinations') for (const n of destNodes) set.add(n.category);
    else for (const n of srcNodes) for (const c of n.categories) set.add(c.name);
    return [...set].sort();
  }, [view, destNodes, srcNodes]);

  const unit = metric === 'bytes' ? 'bytes' : 'conexões';
  const destItems: BubbleItem[] = useMemo(
    () =>
      destVisible.map((n) => ({
        id: n.id,
        label: n.host ?? n.ip,
        valueText: metric === 'bytes' ? formatBytes(n.bytes) : formatCompact(n.connections),
        value: nodeValue(n, metric),
        group: n.group,
        blockedShare: n.connections > 0 ? n.blocked / n.connections : 0,
        ring: categoryColor(n.category),
        aria: `${n.label}: ${formatCompact(nodeValue(n, metric))} ${unit}, categoria ${n.category}`,
      })),
    [destVisible, metric, unit]
  );
  const srcItems: BubbleItem[] = useMemo(
    () =>
      srcVisible.map((n) => ({
        id: n.id,
        label: n.ip,
        valueText: metric === 'bytes' ? formatBytes(n.bytes) : formatCompact(n.connections),
        value: sourceValue(n, metric),
        group: n.group,
        blockedShare: n.connections > 0 ? n.blocked / n.connections : 0,
        ring: categoryColor(n.categories[0]?.name ?? n.zone),
        aria: `${n.ip}: ${formatCompact(sourceValue(n, metric))} ${unit}, ${n.destinations} destinos`,
      })),
    [srcVisible, metric, unit]
  );

  const report = view === 'destinations' ? destReport : srcReport;
  const hasData = (report?.nodes.length ?? 0) > 0;
  const filtersActive = Boolean(srcIp || dst);
  const selectedDest = view === 'destinations' && selectedId ? (destById.get(selectedId) ?? destNodes.find((n) => n.id === selectedId) ?? null) : null;
  const selectedSrc = view === 'sources' && selectedId ? (srcById.get(selectedId) ?? srcNodes.find((n) => n.id === selectedId) ?? null) : null;

  if (!loading && !hasData && !error && !filtersActive && !destReport?.nodes.length && !srcReport?.nodes.length) {
    return (
      <div className="bg-white border border-[var(--fw-border)] rounded-lg p-10 max-w-2xl">
        <h2 className="text-lg font-semibold text-[var(--fw-heading)] flex items-center gap-2">
          <Radar className="w-5 h-5 text-[var(--fw-accent)]" aria-hidden="true" />
          Nenhum tráfego observado ainda
        </h2>
        <p className="text-xs text-[var(--fw-text-muted)] mt-2 leading-relaxed">
          O radar é montado a partir dos syslogs de tráfego recebidos. Envie logs do firewall para a porta
          UDP deste servidor, importe um arquivo de log ou carregue a amostra de demonstração.
        </p>
        <button
          type="button"
          onClick={onGoToConnect}
          className="mt-5 px-4 py-2 text-xs font-medium text-white bg-[var(--fw-accent)] rounded-md hover:bg-[var(--fw-accent-hover)]"
        >
          Ir para Conexão e Importação
        </button>
      </div>
    );
  }

  // ---------- tooltips ----------
  const renderDestTooltip = (id: string) => {
    if (id.startsWith('group:')) {
      const group = id.slice(6);
      const members = destVisible.filter((n) => n.group === group);
      const sum = (f: (n: DestinationNode) => number) => members.reduce((s, n) => s + f(n), 0);
      return (
        <>
          <p className="font-semibold text-[var(--fw-heading)]">{group}</p>
          <p className="mt-0.5 text-[var(--fw-text-muted)]">{members.length} destinos neste domínio</p>
          <dl className="mt-2 grid grid-cols-2 gap-x-3 gap-y-1 tabular-nums">
            <dt className="text-[var(--fw-text-muted)]">Conexões</dt>
            <dd className="text-right font-medium">{sum((n) => n.connections).toLocaleString('pt-BR')}</dd>
            <dt className="text-[var(--fw-text-muted)]">Volume</dt>
            <dd className="text-right font-medium">{formatBytes(sum((n) => n.bytes))}</dd>
            <dt className="text-[var(--fw-text-muted)]">Bloqueadas</dt>
            <dd className="text-right font-medium">{sum((n) => n.blocked).toLocaleString('pt-BR')}</dd>
          </dl>
        </>
      );
    }
    const n = destById.get(id);
    if (!n) return null;
    return (
      <>
        <p className="font-semibold text-[var(--fw-heading)] break-all">{n.label}</p>
        <p className="mt-0.5 flex items-center gap-1.5 text-[var(--fw-text-muted)]">
          <span className="inline-block w-2 h-2 rounded-full" style={{ background: categoryColor(n.category) }} />
          {n.category}
          {n.hostSource === 'rdns' && <span className="ml-1 opacity-70">· nome por DNS reverso</span>}
        </p>
        <dl className="mt-2 grid grid-cols-2 gap-x-3 gap-y-1 tabular-nums">
          <dt className="text-[var(--fw-text-muted)]">Conexões</dt>
          <dd className="text-right font-medium">{n.connections.toLocaleString('pt-BR')}</dd>
          <dt className="text-[var(--fw-text-muted)]">Volume</dt>
          <dd className="text-right font-medium">{formatBytes(n.bytes)}</dd>
          <dt className="text-[var(--fw-text-muted)]">Bloqueadas</dt>
          <dd className="text-right font-medium">{n.blocked.toLocaleString('pt-BR')}</dd>
          <dt className="text-[var(--fw-text-muted)]">Origens</dt>
          <dd className="text-right font-medium">{n.sources.toLocaleString('pt-BR')}</dd>
        </dl>
        {n.services.length > 0 && (
          <p className="mt-2 text-[11px] text-[var(--fw-text-body)]">
            {n.services.slice(0, 3).map((s) => `${s.name} (${s.count})`).join(' · ')}
          </p>
        )}
        {n.topSources.length > 0 && (
          <p className="mt-1.5 text-[11px] text-[var(--fw-text-body)]">
            Origens:{' '}
            <span className="font-mono">{n.topSources.slice(0, 3).map((o) => `${o.ip} (${o.count})`).join(' · ')}</span>
            {n.sources > 3 ? ` +${n.sources - 3}` : ''}
          </p>
        )}
        <p className="mt-1.5 font-mono text-[10px] text-[var(--fw-text-subtle)] break-all">{n.ips.join(', ')}</p>
        <p className="mt-1.5 text-[10px] text-[var(--fw-text-subtle)]">Clique para fixar e ver as ações</p>
      </>
    );
  };

  const renderSrcTooltip = (id: string) => {
    if (id.startsWith('group:')) {
      const group = id.slice(6);
      const members = srcVisible.filter((n) => n.group === group);
      const sum = (f: (n: SourceNode) => number) => members.reduce((s, n) => s + f(n), 0);
      return (
        <>
          <p className="font-semibold text-[var(--fw-heading)] font-mono">{group}</p>
          <p className="mt-0.5 text-[var(--fw-text-muted)]">{members.length} origens nesta sub-rede</p>
          <dl className="mt-2 grid grid-cols-2 gap-x-3 gap-y-1 tabular-nums">
            <dt className="text-[var(--fw-text-muted)]">Conexões</dt>
            <dd className="text-right font-medium">{sum((n) => n.connections).toLocaleString('pt-BR')}</dd>
            <dt className="text-[var(--fw-text-muted)]">Volume</dt>
            <dd className="text-right font-medium">{formatBytes(sum((n) => n.bytes))}</dd>
            <dt className="text-[var(--fw-text-muted)]">Bloqueadas</dt>
            <dd className="text-right font-medium">{sum((n) => n.blocked).toLocaleString('pt-BR')}</dd>
          </dl>
        </>
      );
    }
    const n = srcById.get(id);
    if (!n) return null;
    return (
      <>
        <p className="font-semibold text-[var(--fw-heading)] font-mono">{n.ip}</p>
        <p className="mt-0.5 text-[var(--fw-text-muted)]">
          {n.user ? `${n.user} · ` : ''}zona {n.zone}
        </p>
        <dl className="mt-2 grid grid-cols-2 gap-x-3 gap-y-1 tabular-nums">
          <dt className="text-[var(--fw-text-muted)]">Conexões</dt>
          <dd className="text-right font-medium">{n.connections.toLocaleString('pt-BR')}</dd>
          <dt className="text-[var(--fw-text-muted)]">Volume</dt>
          <dd className="text-right font-medium">{formatBytes(n.bytes)}</dd>
          <dt className="text-[var(--fw-text-muted)]">Bloqueadas</dt>
          <dd className="text-right font-medium">{n.blocked.toLocaleString('pt-BR')}</dd>
          <dt className="text-[var(--fw-text-muted)]">Destinos</dt>
          <dd className="text-right font-medium">{n.destinations.toLocaleString('pt-BR')}</dd>
        </dl>
        {n.topDestinations.length > 0 && (
          <p className="mt-2 text-[11px] text-[var(--fw-text-body)]">
            Mais acessa:{' '}
            <span className="font-mono">{n.topDestinations.slice(0, 3).map((d) => `${d.label} (${d.count})`).join(' · ')}</span>
          </p>
        )}
        {n.categories.length > 0 && (
          <p className="mt-1.5 text-[11px] text-[var(--fw-text-muted)]">{n.categories.map((c) => c.name).slice(0, 3).join(' · ')}</p>
        )}
        <p className="mt-1.5 text-[10px] text-[var(--fw-text-subtle)]">Clique para fixar e ver as ações</p>
      </>
    );
  };

  const title =
    view === 'destinations'
      ? `Top ${destVisible.length} destinos contatados ${srcIp ? `por ${srcIp}` : 'pela sua rede'}`
      : `Top ${srcVisible.length} consumidores${dst ? ` de ${dst.label}` : ''}`;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <div className="inline-flex p-1 bg-[var(--fw-surface-alt)] rounded-lg" role="tablist" aria-label="Visão do radar">
          {(
            [
              { id: 'destinations', label: 'Destinos', hint: 'para onde vai' },
              { id: 'sources', label: 'Origens', hint: 'quem consome' },
            ] as const
          ).map((tab) => (
            <button
              key={tab.id}
              type="button"
              role="tab"
              aria-selected={view === tab.id}
              onClick={() => switchView(tab.id)}
              className={`px-4 py-2 text-sm font-semibold rounded-md transition-colors ${
                view === tab.id ? 'bg-white text-[var(--fw-heading)] shadow-xs' : 'text-[var(--fw-text-muted)] hover:text-[var(--fw-heading)]'
              }`}
            >
              {tab.label}
              <span className="ml-2 text-[11px] font-normal text-[var(--fw-text-subtle)] hidden sm:inline">{tab.hint}</span>
            </button>
          ))}
        </div>
      </div>

      <div className="bg-white border border-[var(--fw-border)] rounded-lg p-3 flex flex-wrap items-center gap-3">
        <div className="flex items-center gap-1 p-1 bg-[var(--fw-surface-alt)] rounded-md" role="group" aria-label="Período">
          {RANGES.map((r) => (
            <button key={r.minutes} type="button" onClick={() => setMinutes(r.minutes)} aria-pressed={minutes === r.minutes} className={segmentButton(minutes === r.minutes)}>
              {r.label}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-1 p-1 bg-[var(--fw-surface-alt)] rounded-md" role="group" aria-label="Métrica">
          {(
            [
              { id: 'connections', label: 'Conexões' },
              { id: 'bytes', label: 'Volume' },
            ] as const
          ).map((m) => (
            <button key={m.id} type="button" onClick={() => setMetric(m.id)} aria-pressed={metric === m.id} className={segmentButton(metric === m.id)}>
              {m.label}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-1 p-1 bg-[var(--fw-surface-alt)] rounded-md" role="group" aria-label="Escopo">
          {(
            [
              { id: 'all', label: 'Todos' },
              { id: 'public', label: 'Internet' },
              { id: 'internal', label: 'Internos' },
            ] as const
          ).map((s) => (
            <button key={s.id} type="button" onClick={() => setScope(s.id)} aria-pressed={scope === s.id} className={segmentButton(scope === s.id)}>
              {s.label}
            </button>
          ))}
        </div>

        <label className="flex items-center gap-2 text-xs text-[var(--fw-text-muted)]">
          Categorias relacionadas:
          <select
            value={category}
            onChange={(e) => setCategory(e.target.value)}
            className="px-2 py-1.5 text-xs border border-[var(--fw-border-strong)] rounded-md bg-[var(--fw-bg-input)] text-[var(--fw-text-body)]"
          >
            <option value="all">Todas</option>
            {categories.map((c) => (
              <option key={c} value={c}>
                {c}
              </option>
            ))}
          </select>
        </label>

        <button
          type="button"
          onClick={() => setHeat((v) => !v)}
          aria-pressed={heat}
          title="Colore as bolhas pelo tamanho: grandes quentes (vermelho), pequenas frias (azul)"
          className={`inline-flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-medium rounded-md border ${
            heat ? 'border-orange-300 bg-orange-50 text-orange-800' : 'border-[var(--fw-border-strong)] bg-white text-[var(--fw-text-body)]'
          }`}
        >
          <Flame className="w-3.5 h-3.5" aria-hidden="true" /> Mapa de calor
        </button>

        <button
          type="button"
          onClick={resetAll}
          className="ml-auto inline-flex items-center gap-1.5 text-xs font-medium text-[var(--fw-accent-mid)] hover:underline"
        >
          <RotateCcw className="w-3.5 h-3.5" aria-hidden="true" /> Redefinir tudo
        </button>
      </div>

      <form className="bg-white border border-[var(--fw-border)] rounded-lg p-3 flex flex-wrap items-center gap-3" onSubmit={submitFilters}>
        <label className="flex items-center gap-2 text-xs text-[var(--fw-text-muted)]">
          IP de origem
          <input
            type="text"
            inputMode="decimal"
            value={srcIpInput}
            onChange={(e) => setSrcIpInput(e.target.value)}
            placeholder="ex.: 10.20.4.45 ou 10.20.4."
            aria-label="Filtrar pelo IP de origem"
            className="w-52 px-3 py-1.5 text-xs font-mono border border-[var(--fw-border-strong)] rounded-md bg-[var(--fw-bg-input)] text-[var(--fw-text-body)] focus:outline-none focus:ring-2 focus:ring-[var(--fw-accent-mid)]"
          />
        </label>
        <label className="flex items-center gap-2 text-xs text-[var(--fw-text-muted)]">
          Destino
          <input
            type="text"
            value={dstInput}
            onChange={(e) => setDstInput(e.target.value)}
            placeholder="nome, domínio ou IP"
            aria-label="Filtrar pelo destino (nome, domínio ou IP)"
            className="w-52 px-3 py-1.5 text-xs font-mono border border-[var(--fw-border-strong)] rounded-md bg-[var(--fw-bg-input)] text-[var(--fw-text-body)] focus:outline-none focus:ring-2 focus:ring-[var(--fw-accent-mid)]"
          />
        </label>
        <button
          type="submit"
          className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-white bg-[var(--fw-accent)] rounded-md hover:bg-[var(--fw-accent-hover)]"
        >
          <Search className="w-3.5 h-3.5" aria-hidden="true" />
          Aplicar
        </button>
        {srcIp && (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs rounded-full bg-[var(--fw-surface-alt)] text-[var(--fw-heading)]">
            Origem: <span className="font-mono">{srcIp}</span>
            <button type="button" onClick={() => applySource('')} aria-label="Remover filtro de origem" className="text-[var(--fw-text-subtle)] hover:text-[var(--fw-heading)]">
              <X className="w-3.5 h-3.5" aria-hidden="true" />
            </button>
          </span>
        )}
        {dst && (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs rounded-full bg-[var(--fw-surface-alt)] text-[var(--fw-heading)]">
            Destino: <span className="font-mono">{dst.label}</span>
            <button type="button" onClick={() => applyDestination(null)} aria-label="Remover filtro de destino" className="text-[var(--fw-text-subtle)] hover:text-[var(--fw-heading)]">
              <X className="w-3.5 h-3.5" aria-hidden="true" />
            </button>
          </span>
        )}

        <label className="flex items-center gap-2 text-xs text-[var(--fw-text-muted)] md:ml-auto">
          Buscar na tela
          <input
            type="search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder={view === 'destinations' ? 'nome, domínio, IP ou categoria' : 'IP, usuário, zona ou destino'}
            aria-label="Buscar entre as bolhas exibidas"
            className="w-56 px-3 py-1.5 text-xs border border-[var(--fw-border-strong)] rounded-md bg-[var(--fw-bg-input)] text-[var(--fw-text-body)] focus:outline-none focus:ring-2 focus:ring-[var(--fw-accent-mid)]"
          />
        </label>
      </form>

      <div className="grid grid-cols-1 xl:grid-cols-[minmax(0,1fr)_340px] gap-4 items-start">
        <section className="bg-white border border-[var(--fw-border)] rounded-lg p-4" aria-label={view === 'destinations' ? 'Radar de destinos' : 'Radar de origens'}>
          <div className="flex flex-wrap items-baseline justify-between gap-2 mb-3">
            <h2 className="text-sm font-semibold text-[var(--fw-heading)]">{title}</h2>
            <p className="text-[11px] text-[var(--fw-text-muted)] tabular-nums">
              {report ? `${report.analyzedEvents.toLocaleString('pt-BR')} eventos analisados` : ''}
              {view === 'destinations' && destReport && destReport.omitted.destinations > 0 && scope === 'all' && category === 'all' && !query.trim()
                ? ` · +${destReport.omitted.destinations.toLocaleString('pt-BR')} destinos menores`
                : ''}
              {view === 'sources' && srcReport && srcReport.omitted.sources > 0 && scope === 'all' && category === 'all' && !query.trim()
                ? ` · +${srcReport.omitted.sources.toLocaleString('pt-BR')} origens menores`
                : ''}
            </p>
          </div>

          <BubbleStage
            items={view === 'destinations' ? destItems : srcItems}
            heat={heat}
            hoveredId={hovered}
            selectedId={selectedId}
            onHover={setHovered}
            onSelect={setSelectedId}
            renderTooltip={view === 'destinations' ? renderDestTooltip : renderSrcTooltip}
            groupTitle={(group, members) => (view === 'destinations' ? `${group} · ${members} destinos` : `${group} · ${members} origens`)}
            loading={loading}
            emptyText={view === 'destinations' ? 'Nenhum destino corresponde aos filtros atuais.' : 'Nenhuma origem corresponde aos filtros atuais.'}
            ariaLabel={view === 'destinations' ? 'Bolhas de destinos agrupadas por domínio' : 'Bolhas de origens agrupadas por sub-rede'}
            resetSignal={resetSignal}
            legendCold="menos"
            legendHot="mais"
          />

          <p className="mt-2 text-[11px] text-[var(--fw-text-muted)]">
            Tamanho{heat ? ' e cor' : ''} = {metric === 'bytes' ? 'volume de dados' : 'número de conexões'}
            {heat ? ' (grande e quente = mais; pequeno e frio = menos)' : ''}. Ponto vermelho = houve bloqueios. As bolhas fogem do mouse e
            voltam; arraste o fundo para mover e use +/− para zoom.{' '}
            {view === 'destinations'
              ? destReport?.resolver.enabled
                ? `Nomes por DNS reverso: ${destReport.resolver.resolved} resolvidos${destReport.resolver.pending ? `, ${destReport.resolver.pending} em andamento` : ''}.`
                : 'DNS reverso desativado: destinos sem FQDN no log aparecem como IP.'
              : 'Agrupadas por sub-rede (/24).'}
          </p>
          {report && (report.srcIp || report.dst) && (
            <p className="mt-1 text-[11px] text-[var(--fw-text-muted)]">
              Filtrado{report.srcIp ? <> por origem <span className="font-mono">{report.srcIp}</span></> : null}
              {report.srcIp && report.dst ? ' e' : ''}
              {report.dst || (report.dstIps && report.dstIps.length) ? <> por destino <span className="font-mono">{report.dst || report.dstIps?.join(', ')}</span></> : null} (
              {report.dataSource === 'database' ? 'consulta ao banco de dados' : 'janela em memória'}).
              {report.truncated ? ' Limite de 20.000 eventos atingido: há mais tráfego além do exibido; restrinja o período.' : ''}
            </p>
          )}
          {error && (
            <p role="alert" className="mt-1 text-[11px] text-red-700">
              {error}
            </p>
          )}
        </section>

        <aside className="space-y-4">
          {view === 'destinations' ? (
            <>
              <section className="bg-white border border-[var(--fw-border)] rounded-lg p-4">
                <h3 className="text-sm font-semibold text-[var(--fw-heading)] mb-3">Top 5 destinos</h3>
                <table className="w-full text-xs">
                  <thead>
                    <tr className="text-left text-[var(--fw-text-muted)] bg-[var(--fw-surface)]">
                      <th className="py-2 px-3 font-medium">Destino</th>
                      <th className="py-2 px-3 font-medium text-right">{metric === 'bytes' ? 'Volume' : 'Conexões'}</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[var(--fw-border-soft)]">
                    {destSummary.top.map(({ node, value, share }) => (
                      <tr key={node.id} className="hover:bg-[var(--fw-bg)] cursor-pointer" onClick={() => setSelectedId(node.id)} onPointerEnter={() => setHovered(node.id)} onPointerLeave={() => setHovered(null)}>
                        <td className="py-2.5 px-3">
                          <span className="block font-medium text-[var(--fw-text-body)] truncate max-w-[170px]" title={node.label}>{node.label}</span>
                          <span className="block text-[10px] text-[var(--fw-text-muted)]">{node.category}</span>
                        </td>
                        <td className="py-2.5 px-3 text-right tabular-nums">
                          <span className="font-medium">{metric === 'bytes' ? formatBytes(value) : value.toLocaleString('pt-BR')}</span>
                          <span className="block text-[10px] text-[var(--fw-text-muted)]">{(share * 100).toFixed(1)}%</span>
                        </td>
                      </tr>
                    ))}
                    {destSummary.top.length === 0 && (
                      <tr><td colSpan={2} className="py-4 px-3 text-center text-[var(--fw-text-muted)]">Sem dados.</td></tr>
                    )}
                  </tbody>
                </table>
              </section>

              <section className="bg-white border border-[var(--fw-border)] rounded-lg p-4">
                <h3 className="text-sm font-semibold text-[var(--fw-heading)] mb-3">Top 5 categorias</h3>
                <table className="w-full text-xs">
                  <thead>
                    <tr className="text-left text-[var(--fw-text-muted)] bg-[var(--fw-surface)]">
                      <th className="py-2 px-3 font-medium">Categoria</th>
                      <th className="py-2 px-3 font-medium text-right">%</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[var(--fw-border-soft)]">
                    {destSummary.categories.map((c) => (
                      <tr key={c.category} className="hover:bg-[var(--fw-bg)] cursor-pointer" onClick={() => setCategory(c.category)}>
                        <td className="py-2.5 px-3">
                          <span className="inline-block w-2 h-2 rounded-full mr-2" style={{ background: categoryColor(c.category) }} />
                          {c.category}
                        </td>
                        <td className="py-2.5 px-3 text-right tabular-nums">{(c.share * 100).toFixed(2)}%</td>
                      </tr>
                    ))}
                    {destSummary.categories.length === 0 && (
                      <tr><td colSpan={2} className="py-4 px-3 text-center text-[var(--fw-text-muted)]">Sem dados.</td></tr>
                    )}
                  </tbody>
                </table>
              </section>

              <FactsBox facts={destSummary.facts} total={destSummary.total} unit={unit} />

              {selectedDest && (
                <SelectedDestinationCard
                  node={selectedDest}
                  onClose={() => setSelectedId(null)}
                  onInvestigate={onInvestigate}
                  onFilterSource={applySource}
                  onFilterDestination={() => applyDestination(destinationFilterFor(selectedDest))}
                  onShowSources={() => {
                    applySource('');
                    applyDestination(destinationFilterFor(selectedDest));
                    switchView('sources');
                  }}
                />
              )}
            </>
          ) : (
            <>
              <section className="bg-white border border-[var(--fw-border)] rounded-lg p-4">
                <h3 className="text-sm font-semibold text-[var(--fw-heading)] mb-3">Top 5 consumidores</h3>
                <table className="w-full text-xs">
                  <thead>
                    <tr className="text-left text-[var(--fw-text-muted)] bg-[var(--fw-surface)]">
                      <th className="py-2 px-3 font-medium">Origem</th>
                      <th className="py-2 px-3 font-medium text-right">{metric === 'bytes' ? 'Volume' : 'Conexões'}</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[var(--fw-border-soft)]">
                    {srcSummary.top.map(({ node, value, share }) => (
                      <tr key={node.id} className="hover:bg-[var(--fw-bg)] cursor-pointer" onClick={() => setSelectedId(node.id)} onPointerEnter={() => setHovered(node.id)} onPointerLeave={() => setHovered(null)}>
                        <td className="py-2.5 px-3">
                          <span className="block font-mono font-medium text-[var(--fw-text-body)]">{node.ip}</span>
                          <span className="block text-[10px] text-[var(--fw-text-muted)]">{node.user ? `${node.user} · ` : ''}{node.destinations} destinos</span>
                        </td>
                        <td className="py-2.5 px-3 text-right tabular-nums">
                          <span className="font-medium">{metric === 'bytes' ? formatBytes(value) : value.toLocaleString('pt-BR')}</span>
                          <span className="block text-[10px] text-[var(--fw-text-muted)]">{(share * 100).toFixed(1)}%</span>
                        </td>
                      </tr>
                    ))}
                    {srcSummary.top.length === 0 && (
                      <tr><td colSpan={2} className="py-4 px-3 text-center text-[var(--fw-text-muted)]">Sem dados.</td></tr>
                    )}
                  </tbody>
                </table>
              </section>

              <section className="bg-white border border-[var(--fw-border)] rounded-lg p-4">
                <h3 className="text-sm font-semibold text-[var(--fw-heading)] mb-3">O que mais acessam</h3>
                <table className="w-full text-xs">
                  <thead>
                    <tr className="text-left text-[var(--fw-text-muted)] bg-[var(--fw-surface)]">
                      <th className="py-2 px-3 font-medium">Categoria de destino</th>
                      <th className="py-2 px-3 font-medium text-right">%</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[var(--fw-border-soft)]">
                    {srcSummary.categories.map((c) => (
                      <tr key={c.category} className="hover:bg-[var(--fw-bg)] cursor-pointer" onClick={() => setCategory(c.category)}>
                        <td className="py-2.5 px-3">
                          <span className="inline-block w-2 h-2 rounded-full mr-2" style={{ background: categoryColor(c.category) }} />
                          {c.category}
                        </td>
                        <td className="py-2.5 px-3 text-right tabular-nums">{(c.share * 100).toFixed(2)}%</td>
                      </tr>
                    ))}
                    {srcSummary.categories.length === 0 && (
                      <tr><td colSpan={2} className="py-4 px-3 text-center text-[var(--fw-text-muted)]">Sem dados.</td></tr>
                    )}
                  </tbody>
                </table>
              </section>

              <FactsBox facts={srcSummary.facts} total={srcSummary.total} unit={unit} />

              {selectedSrc && (
                <SelectedSourceCard
                  node={selectedSrc}
                  onClose={() => setSelectedId(null)}
                  onInvestigate={onInvestigate}
                  onShowDestinations={() => {
                    applyDestination(null);
                    applySource(selectedSrc.ip);
                    switchView('destinations');
                  }}
                  onFilterDestination={(label) => applyDestination({ label, text: /^[0-9a-f:.]+$/.test(label) ? '' : label, ips: /^[0-9a-f:.]+$/.test(label) ? [label] : [] })}
                />
              )}
            </>
          )}
        </aside>
      </div>
    </div>
  );
}

function FactsBox({ facts, total, unit }: { facts: string[]; total: number; unit: string }) {
  if (facts.length === 0) return null;
  return (
    <section className="rounded-lg border border-amber-300 bg-amber-50 p-4 text-amber-900">
      <h3 className="text-sm font-semibold mb-2">Fatos sobre a distribuição</h3>
      <ul className="space-y-2 text-xs leading-relaxed">
        {facts.map((f) => (
          <li key={f} className="border-t border-amber-300/70 pt-2 first:border-0 first:pt-0">
            {f}
          </li>
        ))}
      </ul>
      <p className="mt-2 text-[10px] opacity-70">
        Base: {total.toLocaleString('pt-BR')} {unit} analisadas.
      </p>
    </section>
  );
}

const actionButton =
  'inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium rounded-md border border-[var(--fw-border-strong)] bg-white text-[var(--fw-text-body)] hover:bg-[var(--fw-surface)]';
const primaryButton =
  'inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-white bg-[var(--fw-accent)] rounded-md hover:bg-[var(--fw-accent-hover)]';

function SelectedDestinationCard({
  node,
  onClose,
  onInvestigate,
  onFilterSource,
  onFilterDestination,
  onShowSources,
}: {
  node: DestinationNode;
  onClose: () => void;
  onInvestigate: (query: string) => void;
  onFilterSource: (ip: string) => void;
  onFilterDestination: () => void;
  onShowSources: () => void;
}) {
  return (
    <section className="bg-white border border-[var(--fw-border-strong)] rounded-lg p-4 text-xs">
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <h3 className="text-sm font-semibold text-[var(--fw-heading)] break-all">{node.label}</h3>
          <p className="text-[var(--fw-text-muted)]">{node.category}</p>
        </div>
        <button type="button" onClick={onClose} className="text-[var(--fw-text-subtle)] hover:text-[var(--fw-heading)]" aria-label="Fechar detalhes">
          ✕
        </button>
      </div>
      <dl className="mt-3 grid grid-cols-2 gap-x-3 gap-y-1 tabular-nums">
        <dt className="text-[var(--fw-text-muted)]">Conexões</dt>
        <dd className="text-right font-medium">{node.connections.toLocaleString('pt-BR')}</dd>
        <dt className="text-[var(--fw-text-muted)]">Bloqueadas</dt>
        <dd className="text-right font-medium">{node.blocked.toLocaleString('pt-BR')}</dd>
        <dt className="text-[var(--fw-text-muted)]">Volume</dt>
        <dd className="text-right font-medium">{formatBytes(node.bytes)}</dd>
        <dt className="text-[var(--fw-text-muted)]">Origens distintas</dt>
        <dd className="text-right font-medium">{node.sources.toLocaleString('pt-BR')}</dd>
      </dl>
      <div className="mt-3 flex flex-wrap gap-1.5">
        {node.services.map((s) => (
          <span key={s.name} className="px-2 py-0.5 rounded-full bg-[var(--fw-surface-alt)] text-[var(--fw-text-body)]">
            {s.name} · {s.count}
          </span>
        ))}
      </div>
      {node.topSources.length > 0 && (
        <div className="mt-3">
          <p className="text-[var(--fw-text-muted)]">Quem acessa ({node.sources.toLocaleString('pt-BR')} {node.sources === 1 ? 'origem' : 'origens'})</p>
          <div className="mt-1.5 flex flex-wrap gap-1.5">
            {node.topSources.map((o) => (
              <button key={o.ip} type="button" onClick={() => onFilterSource(o.ip)} title="Ver todos os destinos desta origem" className="px-2 py-0.5 rounded-full font-mono bg-[var(--fw-surface-alt)] text-[var(--fw-text-body)] hover:bg-[var(--fw-surface-chip)]">
                {o.ip} · {o.count}
              </button>
            ))}
          </div>
        </div>
      )}
      <p className="mt-3 font-mono text-[10px] text-[var(--fw-text-subtle)] break-all">{node.ips.join(', ')}</p>
      <div className="mt-3 flex flex-wrap gap-2">
        <button type="button" onClick={onFilterDestination} className={primaryButton}>
          Filtrar por este destino
        </button>
        <button type="button" onClick={onShowSources} className={actionButton}>
          Ver quem acessa (Origens)
        </button>
        <button type="button" onClick={() => onInvestigate(node.ip || node.label)} className={actionButton}>
          <Search className="w-3.5 h-3.5" aria-hidden="true" />
          Ver logs
        </button>
      </div>
    </section>
  );
}

function SelectedSourceCard({
  node,
  onClose,
  onInvestigate,
  onShowDestinations,
  onFilterDestination,
}: {
  node: SourceNode;
  onClose: () => void;
  onInvestigate: (query: string) => void;
  onShowDestinations: () => void;
  onFilterDestination: (label: string) => void;
}) {
  return (
    <section className="bg-white border border-[var(--fw-border-strong)] rounded-lg p-4 text-xs">
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <h3 className="text-sm font-semibold text-[var(--fw-heading)] font-mono break-all">{node.ip}</h3>
          <p className="text-[var(--fw-text-muted)]">
            {node.user ? `${node.user} · ` : ''}zona {node.zone}
            {node.group ? ` · ${node.group}` : ''}
          </p>
        </div>
        <button type="button" onClick={onClose} className="text-[var(--fw-text-subtle)] hover:text-[var(--fw-heading)]" aria-label="Fechar detalhes">
          ✕
        </button>
      </div>
      <dl className="mt-3 grid grid-cols-2 gap-x-3 gap-y-1 tabular-nums">
        <dt className="text-[var(--fw-text-muted)]">Conexões</dt>
        <dd className="text-right font-medium">{node.connections.toLocaleString('pt-BR')}</dd>
        <dt className="text-[var(--fw-text-muted)]">Bloqueadas</dt>
        <dd className="text-right font-medium">{node.blocked.toLocaleString('pt-BR')}</dd>
        <dt className="text-[var(--fw-text-muted)]">Volume</dt>
        <dd className="text-right font-medium">{formatBytes(node.bytes)}</dd>
        <dt className="text-[var(--fw-text-muted)]">Destinos distintos</dt>
        <dd className="text-right font-medium">{node.destinations.toLocaleString('pt-BR')}</dd>
      </dl>
      <div className="mt-3 flex flex-wrap gap-1.5">
        {node.services.map((s) => (
          <span key={s.name} className="px-2 py-0.5 rounded-full bg-[var(--fw-surface-alt)] text-[var(--fw-text-body)]">
            {s.name} · {s.count}
          </span>
        ))}
      </div>
      {node.topDestinations.length > 0 && (
        <div className="mt-3">
          <p className="text-[var(--fw-text-muted)]">Mais acessa (clique para ver quem mais acessa)</p>
          <div className="mt-1.5 flex flex-wrap gap-1.5">
            {node.topDestinations.map((d) => (
              <button key={d.label} type="button" onClick={() => onFilterDestination(d.label)} className="px-2 py-0.5 rounded-full font-mono bg-[var(--fw-surface-alt)] text-[var(--fw-text-body)] hover:bg-[var(--fw-surface-chip)]">
                {d.label} · {d.count}
              </button>
            ))}
          </div>
        </div>
      )}
      <div className="mt-3 flex flex-wrap gap-2">
        <button type="button" onClick={onShowDestinations} className={primaryButton}>
          Ver destinos desta origem
        </button>
        <button type="button" onClick={() => onInvestigate(node.ip)} className={actionButton}>
          <Search className="w-3.5 h-3.5" aria-hidden="true" />
          Ver logs
        </button>
      </div>
    </section>
  );
}
