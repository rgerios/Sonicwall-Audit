import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Minus, Plus, Radar, RotateCcw, Search, X } from 'lucide-react';
import type { DestinationMetric, DestinationNode, DestinationsReport, FirewallVendor } from '../types.ts';
import {
  formatBytes,
  formatCompact,
  nodeValue,
  shortHostLabel,
  summarizeDestinations,
} from '../../shared/destinations.ts';
import { layoutBubbles } from '../utils/bubblePack.ts';
import { vendorApiUrl } from '../utils/vendorApi.ts';

interface DestinationsViewProps {
  vendor: FirewallVendor;
  refreshToken: number;
  onInvestigate: (query: string) => void;
  onGoToConnect: () => void;
}

type Scope = 'all' | 'public' | 'internal';

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

function truncate(text: string, max: number): string {
  if (max < 3) return '';
  return text.length <= max ? text : `${text.slice(0, Math.max(1, max - 1))}…`;
}

export function DestinationsView({ vendor, refreshToken, onInvestigate, onGoToConnect }: DestinationsViewProps) {
  const [report, setReport] = useState<DestinationsReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [minutes, setMinutes] = useState(60);
  const [metric, setMetric] = useState<DestinationMetric>('connections');
  const [scope, setScope] = useState<Scope>('all');
  const [category, setCategory] = useState('all');
  const [hovered, setHovered] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [tip, setTip] = useState<{ x: number; y: number } | null>(null);
  const [stageAspect, setStageAspect] = useState(1.55);
  // Filtro por IP de origem (consulta o servidor) e filtro de destinos (instantâneo, só na tela)
  const [srcIpInput, setSrcIpInput] = useState('');
  const [srcIp, setSrcIp] = useState('');
  const [destQuery, setDestQuery] = useState('');

  const stageRef = useRef<HTMLDivElement | null>(null);
  const svgRef = useRef<SVGSVGElement | null>(null);
  const dragRef = useRef<{ x: number; y: number; px: number; py: number; scale: number } | null>(null);

  const hasStage = (report?.nodes.length ?? 0) > 0;

  useEffect(() => {
    const el = stageRef.current;
    if (!el || typeof ResizeObserver === 'undefined') return;
    const ro = new ResizeObserver(([entry]) => {
      const { width, height } = entry.contentRect;
      if (width > 0 && height > 0) setStageAspect(Math.round((width / height) * 10) / 10);
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, [hasStage]);

  const load = useCallback(
    async (signal?: AbortSignal) => {
      try {
        const params = new URLSearchParams({ minutes: String(minutes) });
        if (srcIp) params.set('srcIp', srcIp);
        const res = await fetch(vendorApiUrl(vendor, `/destinations?${params.toString()}`), { signal });
        if (!res.ok) {
          const data = (await res.json().catch(() => ({}))) as { error?: string };
          throw new Error(data.error || `HTTP ${res.status}`);
        }
        setReport((await res.json()) as DestinationsReport);
        setError(null);
      } catch (err) {
        if (err instanceof DOMException && err.name === 'AbortError') return;
        setError(err instanceof Error && err.message && !/^HTTP \d+$/.test(err.message) ? err.message : 'Não foi possível carregar os destinos.');
      } finally {
        setLoading(false);
      }
    },
    [vendor, minutes, srcIp]
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
    setDestQuery('');
  }, [vendor]);

  const allNodes = report?.nodes ?? [];
  const categories = useMemo(() => [...new Set(allNodes.map((n) => n.category))].sort(), [allNodes]);

  const filtered = useMemo(
    () =>
      allNodes.filter(
        (n) =>
          (scope === 'all' || (scope === 'public' ? n.scope === 'public' : n.scope !== 'public')) &&
          (category === 'all' || n.category === category) &&
          matchesDestQuery(n, destQuery)
      ),
    [allNodes, scope, category, destQuery]
  );

  const visible = useMemo(
    () => [...filtered].sort((a, b) => nodeValue(b, metric) - nodeValue(a, metric)).slice(0, MAX_BUBBLES),
    [filtered, metric]
  );

  const noFilter = scope === 'all' && category === 'all' && !destQuery.trim();
  const summary = useMemo(
    () =>
      summarizeDestinations(filtered, metric, {
        omittedValue: noFilter && report ? (metric === 'connections' ? report.omitted.connections : 0) : 0,
      }),
    [filtered, metric, noFilter, report]
  );

  const layout = useMemo(
    () =>
      layoutBubbles(
        visible.map((n) => ({ id: n.id, value: nodeValue(n, metric), group: n.group })),
        { aspect: stageAspect }
      ),
    [visible, metric, stageAspect]
  );

  const byId = useMemo(() => new Map(visible.map((n) => [n.id, n])), [visible]);
  const selected = selectedId ? (byId.get(selectedId) ?? allNodes.find((n) => n.id === selectedId) ?? null) : null;
  const hoveredNode = hovered && !hovered.startsWith('group:') ? byId.get(hovered) : null;
  const hoveredGroup = hovered?.startsWith('group:') ? hovered.slice(6) : null;

  const groupTotals = useMemo(() => {
    const map = new Map<string, { connections: number; bytes: number; members: number; blocked: number }>();
    for (const n of visible) {
      if (!n.group || !layout.groups.has(n.group)) continue;
      const g = map.get(n.group) ?? { connections: 0, bytes: 0, members: 0, blocked: 0 };
      g.connections += n.connections;
      g.bytes += n.bytes;
      g.blocked += n.blocked;
      g.members += 1;
      map.set(n.group, g);
    }
    return map;
  }, [visible, layout]);

  const resetGraph = () => {
    setZoom(1);
    setPan({ x: 0, y: 0 });
    setSelectedId(null);
    setCategory('all');
    setScope('all');
    setHovered(null);
    setSrcIp('');
    setSrcIpInput('');
    setDestQuery('');
  };

  const applySource = (ip: string) => {
    setSrcIpInput(ip);
    setSrcIp(ip.trim().toLowerCase());
    setSelectedId(null);
  };

  const onStagePointerMove = (e: React.PointerEvent) => {
    const rect = stageRef.current?.getBoundingClientRect();
    if (rect) setTip({ x: e.clientX - rect.left, y: e.clientY - rect.top });
    const drag = dragRef.current;
    if (drag) {
      setPan({ x: drag.px + (e.clientX - drag.x) / drag.scale, y: drag.py + (e.clientY - drag.y) / drag.scale });
    }
  };

  const onBackgroundPointerDown = (e: React.PointerEvent) => {
    if (e.button !== 0 || (e.target as Element).closest('.dest-bubble, .dest-group')) return;
    const ctm = svgRef.current?.getScreenCTM();
    dragRef.current = { x: e.clientX, y: e.clientY, px: pan.x, py: pan.y, scale: (ctm?.a ?? 1) * zoom };
    (e.currentTarget as Element).setPointerCapture?.(e.pointerId);
  };
  const endDrag = () => {
    dragRef.current = null;
  };

  const b = layout.bounds;
  const pad = 24;
  const vbW = Math.max(1, b.maxX - b.minX + pad * 2);
  const vbH = Math.max(1, b.maxY - b.minY + pad * 2);
  const cx = (b.minX + b.maxX) / 2;
  const cy = (b.minY + b.maxY) / 2;
  const hasData = allNodes.length > 0;
  const dimOthers = hovered !== null;

  if (!loading && !hasData && !error) {
    return (
      <div className="bg-white border border-[var(--fw-border)] rounded-lg p-10 max-w-2xl">
        <h2 className="text-lg font-semibold text-[var(--fw-heading)] flex items-center gap-2">
          <Radar className="w-5 h-5 text-[var(--fw-accent)]" aria-hidden="true" />
          Nenhum destino observado ainda
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

  const tipNode = hoveredNode ?? null;
  const tipGroup = hoveredGroup ? groupTotals.get(hoveredGroup) : null;
  const total = summary.total;

  return (
    <div className="space-y-4">
      <div className="bg-white border border-[var(--fw-border)] rounded-lg p-3 flex flex-wrap items-center gap-3">
        <div className="flex items-center gap-1 p-1 bg-[var(--fw-surface-alt)] rounded-md" role="group" aria-label="Período">
          {RANGES.map((r) => (
            <button
              key={r.minutes}
              type="button"
              onClick={() => setMinutes(r.minutes)}
              aria-pressed={minutes === r.minutes}
              className={`px-2.5 py-1.5 text-xs font-medium rounded whitespace-nowrap ${
                minutes === r.minutes ? 'bg-white text-[var(--fw-heading)] shadow-xs' : 'text-[var(--fw-text-body)]'
              }`}
            >
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
            <button
              key={m.id}
              type="button"
              onClick={() => setMetric(m.id)}
              aria-pressed={metric === m.id}
              className={`px-2.5 py-1.5 text-xs font-medium rounded whitespace-nowrap ${
                metric === m.id ? 'bg-white text-[var(--fw-heading)] shadow-xs' : 'text-[var(--fw-text-body)]'
              }`}
            >
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
            <button
              key={s.id}
              type="button"
              onClick={() => setScope(s.id)}
              aria-pressed={scope === s.id}
              className={`px-2.5 py-1.5 text-xs font-medium rounded whitespace-nowrap ${
                scope === s.id ? 'bg-white text-[var(--fw-heading)] shadow-xs' : 'text-[var(--fw-text-body)]'
              }`}
            >
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
          onClick={resetGraph}
          className="ml-auto inline-flex items-center gap-1.5 text-xs font-medium text-[var(--fw-accent-mid)] hover:underline"
        >
          <RotateCcw className="w-3.5 h-3.5" aria-hidden="true" /> Redefinir gráfico
        </button>
      </div>

      <form
        className="bg-white border border-[var(--fw-border)] rounded-lg p-3 flex flex-wrap items-center gap-3"
        onSubmit={(e) => {
          e.preventDefault();
          applySource(srcIpInput);
        }}
      >
        <label className="flex items-center gap-2 text-xs text-[var(--fw-text-muted)]">
          IP de origem
          <input
            type="text"
            inputMode="decimal"
            value={srcIpInput}
            onChange={(e) => setSrcIpInput(e.target.value)}
            placeholder="ex.: 10.20.4.45 ou 10.20.4."
            aria-label="Filtrar destinos pelo IP de origem"
            className="w-56 px-3 py-1.5 text-xs font-mono border border-[var(--fw-border-strong)] rounded-md bg-[var(--fw-bg-input)] text-[var(--fw-text-body)] focus:outline-none focus:ring-2 focus:ring-[var(--fw-accent-mid)]"
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
            <button
              type="button"
              onClick={() => applySource('')}
              aria-label="Remover filtro de origem"
              className="text-[var(--fw-text-subtle)] hover:text-[var(--fw-heading)]"
            >
              <X className="w-3.5 h-3.5" aria-hidden="true" />
            </button>
          </span>
        )}

        <label className="flex items-center gap-2 text-xs text-[var(--fw-text-muted)] md:ml-auto">
          Filtrar destinos
          <input
            type="search"
            value={destQuery}
            onChange={(e) => setDestQuery(e.target.value)}
            placeholder="nome, domínio, IP ou categoria"
            aria-label="Filtrar destinos por nome, domínio, IP ou categoria"
            className="w-64 px-3 py-1.5 text-xs border border-[var(--fw-border-strong)] rounded-md bg-[var(--fw-bg-input)] text-[var(--fw-text-body)] focus:outline-none focus:ring-2 focus:ring-[var(--fw-accent-mid)]"
          />
        </label>
      </form>

      <div className="grid grid-cols-1 xl:grid-cols-[minmax(0,1fr)_340px] gap-4 items-start">
        <section className="bg-white border border-[var(--fw-border)] rounded-lg p-4" aria-label="Radar de destinos">
          <div className="flex flex-wrap items-baseline justify-between gap-2 mb-3">
            <h2 className="text-sm font-semibold text-[var(--fw-heading)]">
              Top {visible.length} destinos contatados {srcIp ? `por ${srcIp}` : 'pela sua rede'}
            </h2>
            <p className="text-[11px] text-[var(--fw-text-muted)] tabular-nums">
              {report ? `${report.analyzedEvents.toLocaleString('pt-BR')} eventos analisados` : ''}
              {report && report.omitted.destinations > 0 && noFilter
                ? ` · +${report.omitted.destinations.toLocaleString('pt-BR')} destinos menores`
                : ''}
            </p>
          </div>

          <div
            ref={stageRef}
            className="relative h-[440px] sm:h-[560px] rounded-md bg-[var(--fw-surface-soft)] overflow-hidden touch-none select-none cursor-grab active:cursor-grabbing"
            onPointerMove={onStagePointerMove}
            onPointerLeave={() => {
              setHovered(null);
              setTip(null);
              endDrag();
            }}
            onPointerDown={onBackgroundPointerDown}
            onPointerUp={endDrag}
            onPointerCancel={endDrag}
          >
            {loading && !report ? (
              <div className="absolute inset-0 grid place-items-center text-xs text-[var(--fw-text-muted)]">
                Carregando destinos…
              </div>
            ) : visible.length === 0 ? (
              <div className="absolute inset-0 grid place-items-center text-xs text-[var(--fw-text-muted)] px-6 text-center">
                Nenhum destino corresponde aos filtros atuais.
              </div>
            ) : (
              <svg
                ref={svgRef}
                viewBox={`${b.minX - pad} ${b.minY - pad} ${vbW} ${vbH}`}
                preserveAspectRatio="xMidYMid meet"
                className={`dest-svg w-full h-full ${dimOthers ? 'has-hover' : ''}`}
                role="group"
                aria-label="Bolhas de destinos agrupadas por domínio"
              >
                <g transform={`translate(${cx + pan.x} ${cy + pan.y}) scale(${zoom}) translate(${-cx} ${-cy})`}>
                  {[...layout.groups.entries()].map(([group, g]) => {
                    const id = `group:${group}`;
                    const gt = groupTotals.get(group);
                    return (
                      <g
                        key={id}
                        className={`dest-group ${hovered === id ? 'is-hover' : ''}`}
                        onPointerEnter={() => setHovered(id)}
                        onPointerLeave={() => setHovered((h) => (h === id ? null : h))}
                      >
                        <circle cx={g.x} cy={g.y} r={g.r} className="dest-group-disc" />
                        <text x={g.x} y={g.y + g.r - 9} textAnchor="middle" className="dest-group-label">
                          {truncate(group, Math.floor(g.r / 3.4))}
                        </text>
                        <title>{`${group} · ${gt?.members ?? 0} destinos`}</title>
                      </g>
                    );
                  })}

                  {visible.map((n, index) => {
                    const p = layout.nodes.get(n.id);
                    if (!p) return null;
                    const inGroup = n.group && layout.groups.has(n.group);
                    const label = n.host ? shortHostLabel(n.host, inGroup ? n.group : null) : n.ip;
                    const fs = Math.max(8, Math.min(15, p.r * 0.27));
                    const chars = Math.floor((p.r * 1.7) / (fs * 0.56));
                    const showLabel = p.r >= 17;
                    const color = categoryColor(n.category);
                    const blockedShare = n.connections > 0 ? n.blocked / n.connections : 0;
                    const isHover = hovered === n.id || (hoveredGroup !== null && n.group === hoveredGroup);
                    const isSelected = selectedId === n.id;
                    return (
                      <g
                        key={n.id}
                        className={`dest-bubble ${isHover ? 'is-hover' : ''} ${isSelected ? 'is-selected' : ''}`}
                        style={{ ['--bob-delay' as string]: `${(index * 0.37) % 5}s`, ['--bob-dur' as string]: `${5 + (index % 5)}s` }}
                        tabIndex={0}
                        role="button"
                        aria-label={`${n.label}: ${formatCompact(nodeValue(n, metric))} ${metric === 'bytes' ? 'bytes' : 'conexões'}, categoria ${n.category}`}
                        onPointerEnter={() => setHovered(n.id)}
                        onPointerLeave={() => setHovered((h) => (h === n.id ? null : h))}
                        onFocus={() => setHovered(n.id)}
                        onBlur={() => setHovered((h) => (h === n.id ? null : h))}
                        onClick={() => setSelectedId((cur) => (cur === n.id ? null : n.id))}
                        onKeyDown={(e) => {
                          if (e.key === 'Enter' || e.key === ' ') {
                            e.preventDefault();
                            setSelectedId((cur) => (cur === n.id ? null : n.id));
                          }
                        }}
                      >
                        <g className="dest-bubble-inner">
                          <circle
                            cx={p.x}
                            cy={p.y}
                            r={p.r}
                            className="dest-disc"
                            style={{ ['--ring' as string]: color }}
                          />
                          {blockedShare > 0 && (
                            <circle cx={p.x + p.r * 0.72} cy={p.y - p.r * 0.72} r={Math.max(3, p.r * 0.1)} className="dest-blocked-dot" />
                          )}
                          {showLabel && (
                            <>
                              <text x={p.x} y={p.y - fs * 0.15} textAnchor="middle" fontSize={fs} className="dest-label">
                                {truncate(label, chars)}
                              </text>
                              <text x={p.x} y={p.y + fs * 1.05} textAnchor="middle" fontSize={fs * 0.85} className="dest-count">
                                {metric === 'bytes' ? formatBytes(n.bytes) : formatCompact(n.connections)}
                              </text>
                            </>
                          )}
                        </g>
                      </g>
                    );
                  })}
                </g>
              </svg>
            )}

            <div className="absolute right-3 bottom-3 flex items-center gap-1.5">
              <button
                type="button"
                aria-label="Aproximar"
                onPointerDown={(e) => e.stopPropagation()}
                onClick={() => setZoom((z) => Math.min(3, +(z + 0.25).toFixed(2)))}
                className="w-8 h-8 grid place-items-center bg-white border border-[var(--fw-border-strong)] rounded-md hover:bg-[var(--fw-surface)]"
              >
                <Plus className="w-4 h-4" aria-hidden="true" />
              </button>
              <button
                type="button"
                aria-label="Afastar"
                onPointerDown={(e) => e.stopPropagation()}
                onClick={() => setZoom((z) => Math.max(0.5, +(z - 0.25).toFixed(2)))}
                className="w-8 h-8 grid place-items-center bg-white border border-[var(--fw-border-strong)] rounded-md hover:bg-[var(--fw-surface)]"
              >
                <Minus className="w-4 h-4" aria-hidden="true" />
              </button>
            </div>

            {tip && (tipNode || tipGroup) && (
              <div
                role="tooltip"
                className="pointer-events-none absolute z-10 w-64 rounded-lg border border-[var(--fw-border-strong)] bg-white p-3 text-xs shadow-xl"
                style={{
                  left: Math.min(tip.x + 16, (stageRef.current?.clientWidth ?? 800) - 268),
                  top: Math.min(tip.y + 16, (stageRef.current?.clientHeight ?? 560) - 190),
                }}
              >
                {tipNode ? (
                  <>
                    <p className="font-semibold text-[var(--fw-heading)] break-all">{tipNode.label}</p>
                    <p className="mt-0.5 flex items-center gap-1.5 text-[var(--fw-text-muted)]">
                      <span className="inline-block w-2 h-2 rounded-full" style={{ background: categoryColor(tipNode.category) }} />
                      {tipNode.category}
                      {tipNode.hostSource === 'rdns' && <span className="ml-1 opacity-70">· nome por DNS reverso</span>}
                    </p>
                    <dl className="mt-2 grid grid-cols-2 gap-x-3 gap-y-1 tabular-nums">
                      <dt className="text-[var(--fw-text-muted)]">Conexões</dt>
                      <dd className="text-right font-medium">{tipNode.connections.toLocaleString('pt-BR')}</dd>
                      <dt className="text-[var(--fw-text-muted)]">Volume</dt>
                      <dd className="text-right font-medium">{formatBytes(tipNode.bytes)}</dd>
                      <dt className="text-[var(--fw-text-muted)]">Bloqueadas</dt>
                      <dd className="text-right font-medium">{tipNode.blocked.toLocaleString('pt-BR')}</dd>
                      <dt className="text-[var(--fw-text-muted)]">Origens</dt>
                      <dd className="text-right font-medium">{tipNode.sources.toLocaleString('pt-BR')}</dd>
                    </dl>
                    {tipNode.services.length > 0 && (
                      <p className="mt-2 text-[11px] text-[var(--fw-text-body)]">
                        {tipNode.services.slice(0, 3).map((s) => `${s.name} (${s.count})`).join(' · ')}
                      </p>
                    )}
                    {tipNode.topSources.length > 0 && (
                      <p className="mt-1.5 text-[11px] text-[var(--fw-text-body)]">
                        Origens:{' '}
                        <span className="font-mono">
                          {tipNode.topSources.slice(0, 3).map((o) => `${o.ip} (${o.count})`).join(' · ')}
                        </span>
                        {tipNode.sources > 3 ? ` +${tipNode.sources - 3}` : ''}
                      </p>
                    )}
                    <p className="mt-1.5 font-mono text-[10px] text-[var(--fw-text-subtle)] break-all">{tipNode.ips.join(', ')}</p>
                    <p className="mt-1.5 text-[10px] text-[var(--fw-text-subtle)]">Clique para fixar os detalhes</p>
                  </>
                ) : tipGroup ? (
                  <>
                    <p className="font-semibold text-[var(--fw-heading)]">{hoveredGroup}</p>
                    <p className="mt-0.5 text-[var(--fw-text-muted)]">{tipGroup.members} destinos neste domínio</p>
                    <dl className="mt-2 grid grid-cols-2 gap-x-3 gap-y-1 tabular-nums">
                      <dt className="text-[var(--fw-text-muted)]">Conexões</dt>
                      <dd className="text-right font-medium">{tipGroup.connections.toLocaleString('pt-BR')}</dd>
                      <dt className="text-[var(--fw-text-muted)]">Volume</dt>
                      <dd className="text-right font-medium">{formatBytes(tipGroup.bytes)}</dd>
                      <dt className="text-[var(--fw-text-muted)]">Bloqueadas</dt>
                      <dd className="text-right font-medium">{tipGroup.blocked.toLocaleString('pt-BR')}</dd>
                    </dl>
                  </>
                ) : null}
              </div>
            )}
          </div>

          <p className="mt-2 text-[11px] text-[var(--fw-text-muted)]">
            Tamanho = {metric === 'bytes' ? 'volume de dados' : 'número de conexões'}. Ponto vermelho = houve bloqueios.
            Arraste para mover e use +/− para zoom.{' '}
            {report?.resolver.enabled
              ? `Nomes por DNS reverso: ${report.resolver.resolved} resolvidos${report.resolver.pending ? `, ${report.resolver.pending} em andamento` : ''}.`
              : 'DNS reverso desativado: destinos sem FQDN no log aparecem como IP.'}
          </p>
          {report?.srcIp && (
            <p className="mt-1 text-[11px] text-[var(--fw-text-muted)]">
              Só o tráfego com origem <span className="font-mono">{report.srcIp}</span> (
              {report.dataSource === 'database' ? 'consulta ao banco de dados' : 'janela em memória'}).
              {report.truncated ? ' Limite de 20.000 eventos atingido: há mais tráfego além do exibido; restrinja o período.' : ''}
            </p>
          )}
          {error && <p role="alert" className="mt-1 text-[11px] text-red-700">{error}</p>}
        </section>

        <aside className="space-y-4">
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
                {summary.top.map(({ node, value, share }) => (
                  <tr
                    key={node.id}
                    className="hover:bg-[var(--fw-bg)] cursor-pointer"
                    onClick={() => setSelectedId(node.id)}
                    onPointerEnter={() => setHovered(node.id)}
                    onPointerLeave={() => setHovered(null)}
                  >
                    <td className="py-2.5 px-3">
                      <span className="block font-medium text-[var(--fw-text-body)] truncate max-w-[170px]" title={node.label}>
                        {node.label}
                      </span>
                      <span className="block text-[10px] text-[var(--fw-text-muted)]">{node.category}</span>
                    </td>
                    <td className="py-2.5 px-3 text-right tabular-nums">
                      <span className="font-medium">{metric === 'bytes' ? formatBytes(value) : value.toLocaleString('pt-BR')}</span>
                      <span className="block text-[10px] text-[var(--fw-text-muted)]">{(share * 100).toFixed(1)}%</span>
                    </td>
                  </tr>
                ))}
                {summary.top.length === 0 && (
                  <tr>
                    <td colSpan={2} className="py-4 px-3 text-center text-[var(--fw-text-muted)]">
                      Sem dados.
                    </td>
                  </tr>
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
                {summary.categories.map((c) => (
                  <tr key={c.category} className="hover:bg-[var(--fw-bg)] cursor-pointer" onClick={() => setCategory(c.category)}>
                    <td className="py-2.5 px-3">
                      <span className="inline-block w-2 h-2 rounded-full mr-2" style={{ background: categoryColor(c.category) }} />
                      {c.category}
                    </td>
                    <td className="py-2.5 px-3 text-right tabular-nums">{(c.share * 100).toFixed(2)}%</td>
                  </tr>
                ))}
                {summary.categories.length === 0 && (
                  <tr>
                    <td colSpan={2} className="py-4 px-3 text-center text-[var(--fw-text-muted)]">
                      Sem dados.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </section>

          {summary.facts.length > 0 && (
            <section className="rounded-lg border border-amber-300 bg-amber-50 p-4 text-amber-900">
              <h3 className="text-sm font-semibold mb-2">Fatos sobre a distribuição</h3>
              <ul className="space-y-2 text-xs leading-relaxed">
                {summary.facts.map((f) => (
                  <li key={f} className="border-t border-amber-300/70 pt-2 first:border-0 first:pt-0">
                    {f}
                  </li>
                ))}
              </ul>
              <p className="mt-2 text-[10px] opacity-70">
                Base: {total.toLocaleString('pt-BR')} {metric === 'bytes' ? 'bytes' : 'conexões'} analisadas.
              </p>
            </section>
          )}

          {selected && <SelectedCard node={selected} onClose={() => setSelectedId(null)} onInvestigate={onInvestigate} onFilterSource={applySource} />}
        </aside>
      </div>
    </div>
  );
}

function SelectedCard({
  node,
  onClose,
  onInvestigate,
  onFilterSource,
}: {
  node: DestinationNode;
  onClose: () => void;
  onInvestigate: (query: string) => void;
  onFilterSource: (ip: string) => void;
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
          <p className="text-[var(--fw-text-muted)]">
            Quem acessa ({node.sources.toLocaleString('pt-BR')} {node.sources === 1 ? 'origem' : 'origens'})
          </p>
          <div className="mt-1.5 flex flex-wrap gap-1.5">
            {node.topSources.map((o) => (
              <button
                key={o.ip}
                type="button"
                onClick={() => onFilterSource(o.ip)}
                title="Ver todos os destinos desta origem"
                className="px-2 py-0.5 rounded-full font-mono bg-[var(--fw-surface-alt)] text-[var(--fw-text-body)] hover:bg-[var(--fw-surface-chip)]"
              >
                {o.ip} · {o.count}
              </button>
            ))}
          </div>
        </div>
      )}
      <p className="mt-3 font-mono text-[10px] text-[var(--fw-text-subtle)] break-all">{node.ips.join(', ')}</p>
      <button
        type="button"
        onClick={() => onInvestigate(node.ip || node.label)}
        className="mt-3 inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-white bg-[var(--fw-accent)] rounded-md hover:bg-[var(--fw-accent-hover)]"
      >
        <Search className="w-3.5 h-3.5" aria-hidden="true" />
        Ver logs deste destino
      </button>
    </section>
  );
}
