import { useEffect, useMemo, useRef, useState } from 'react';
import { Minus, Plus } from 'lucide-react';
import { createBody, stepBodies, type Body, type Pointer } from '../effects/bubblePhysics.ts';
import { layoutBubbles, MAX_RADIUS, MIN_RADIUS } from '../utils/bubblePack.ts';
import { heatGradientCss, heatStyle } from '../utils/heat.ts';
import { shortHostLabel } from '../../shared/destinations.ts';

export interface BubbleItem {
  id: string;
  label: string;
  /** Texto curto dentro da bolha (ex.: "26K" ou "1,2 MB"). */
  valueText: string;
  /** Valor que define o tamanho. */
  value: number;
  group: string | null;
  /** Fração (0 a 1) de conexões bloqueadas; > 0 mostra o ponto vermelho. */
  blockedShare: number;
  /** Cor do anel no modo "por categoria". */
  ring: string;
  aria: string;
}

interface BubbleStageProps {
  items: BubbleItem[];
  /** Mapa de calor: grande = quente, pequeno = frio. Desligado, usa a cor da categoria. */
  heat: boolean;
  hoveredId: string | null;
  selectedId: string | null;
  onHover: (id: string | null) => void;
  onSelect: (id: string | null) => void;
  /** Conteúdo do cartão ao passar o mouse; id pode ser "group:<nome>". */
  renderTooltip: (id: string) => React.ReactNode;
  groupTitle: (group: string, members: number) => string;
  loading: boolean;
  emptyText: string;
  ariaLabel: string;
  /** Incrementar volta o zoom, o deslocamento e a seleção ao início. */
  resetSignal: number;
  legendCold: string;
  legendHot: string;
}

function truncate(text: string, max: number): string {
  if (max < 3) return '';
  return text.length <= max ? text : `${text.slice(0, Math.max(1, max - 1))}…`;
}

const reducedMotion = () =>
  typeof window !== 'undefined' && window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;

export function BubbleStage(props: BubbleStageProps) {
  const {
    items, heat, hoveredId, selectedId, onHover, onSelect, renderTooltip, groupTitle,
    loading, emptyText, ariaLabel, resetSignal, legendCold, legendHot,
  } = props;

  const stageRef = useRef<HTMLDivElement | null>(null);
  const svgRef = useRef<SVGSVGElement | null>(null);
  const dragRef = useRef<{ x: number; y: number; px: number; py: number; scale: number } | null>(null);
  const nodeEls = useRef(new Map<string, SVGGElement>());
  const pointerRef = useRef<Pointer>({ x: 0, y: 0, active: false });
  const viewRef = useRef({ cx: 0, cy: 0, zoom: 1, panX: 0, panY: 0 });

  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [tip, setTip] = useState<{ x: number; y: number } | null>(null);
  const [aspect, setAspect] = useState(1.55);

  const hasItems = items.length > 0;

  useEffect(() => {
    const el = stageRef.current;
    if (!el || typeof ResizeObserver === 'undefined') return;
    const ro = new ResizeObserver(([entry]) => {
      const { width, height } = entry.contentRect;
      if (width > 0 && height > 0) setAspect(Math.round((width / height) * 10) / 10);
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, [hasItems]);

  useEffect(() => {
    setZoom(1);
    setPan({ x: 0, y: 0 });
  }, [resetSignal]);

  const layout = useMemo(
    () => layoutBubbles(items.map((n) => ({ id: n.id, value: n.value, group: n.group })), { aspect }),
    [items, aspect]
  );

  const groupTotals = useMemo(() => {
    const map = new Map<string, number>();
    for (const n of items) {
      if (n.group && layout.groups.has(n.group)) map.set(n.group, (map.get(n.group) ?? 0) + 1);
    }
    return map;
  }, [items, layout]);

  const b = layout.bounds;
  const pad = 24;
  const vbW = Math.max(1, b.maxX - b.minX + pad * 2);
  const vbH = Math.max(1, b.maxY - b.minY + pad * 2);
  const cx = (b.minX + b.maxX) / 2;
  const cy = (b.minY + b.maxY) / 2;
  viewRef.current = { cx, cy, zoom, panX: pan.x, panY: pan.y };

  // Física: o ponteiro empurra as bolhas e a mola as devolve. Roda direto no DOM (sem re-render).
  const bodies = useMemo<Body[]>(() => {
    const out: Body[] = [];
    for (const n of items) {
      const p = layout.nodes.get(n.id);
      if (!p) continue;
      const g = n.group ? layout.groups.get(n.group) : undefined;
      out.push(createBody(n.id, p.x, p.y, p.r, g ? { x: g.x, y: g.y, r: g.r } : undefined));
    }
    return out;
  }, [items, layout]);

  useEffect(() => {
    if (bodies.length === 0 || reducedMotion()) return;
    let raf = 0;
    let last = performance.now();
    const tick = (t: number) => {
      raf = requestAnimationFrame(tick);
      const dt = (t - last) / 1000;
      last = t;
      if (document.hidden) return;
      stepBodies(bodies, pointerRef.current, dt, t);
      for (const body of bodies) {
        nodeEls.current.get(body.id)?.setAttribute('transform', `translate(${body.ox.toFixed(2)} ${body.oy.toFixed(2)})`);
      }
    };
    raf = requestAnimationFrame(tick);
    return () => {
      cancelAnimationFrame(raf);
      pointerRef.current.active = false;
      for (const body of bodies) nodeEls.current.get(body.id)?.removeAttribute('transform');
    };
  }, [bodies]);

  /** Posição do ponteiro nas coordenadas do layout (desfaz viewBox, deslocamento e zoom). */
  const toLayout = (clientX: number, clientY: number): { x: number; y: number } | null => {
    const svg = svgRef.current;
    const ctm = svg?.getScreenCTM();
    if (!svg || !ctm) return null;
    const pt = svg.createSVGPoint();
    pt.x = clientX;
    pt.y = clientY;
    const v = pt.matrixTransform(ctm.inverse());
    const view = viewRef.current;
    return {
      x: (v.x - (view.cx + view.panX)) / view.zoom + view.cx,
      y: (v.y - (view.cy + view.panY)) / view.zoom + view.cy,
    };
  };

  const onStagePointerMove = (e: React.PointerEvent) => {
    const rect = stageRef.current?.getBoundingClientRect();
    if (rect) setTip({ x: e.clientX - rect.left, y: e.clientY - rect.top });
    const drag = dragRef.current;
    if (drag) {
      setPan({ x: drag.px + (e.clientX - drag.x) / drag.scale, y: drag.py + (e.clientY - drag.y) / drag.scale });
      pointerRef.current.active = false;
      return;
    }
    const p = toLayout(e.clientX, e.clientY);
    if (p) pointerRef.current = { x: p.x, y: p.y, active: true };
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

  const hoveredGroup = hoveredId?.startsWith('group:') ? hoveredId.slice(6) : null;
  const dimOthers = hoveredId !== null;
  const tipOpen = tip !== null && hoveredId !== null;

  return (
    <div
      ref={stageRef}
      className="relative h-[440px] sm:h-[560px] rounded-md bg-[var(--fw-surface-soft)] overflow-hidden touch-none select-none cursor-grab active:cursor-grabbing"
      onPointerMove={onStagePointerMove}
      onPointerLeave={() => {
        onHover(null);
        setTip(null);
        pointerRef.current.active = false;
        endDrag();
      }}
      onPointerDown={onBackgroundPointerDown}
      onPointerUp={endDrag}
      onPointerCancel={endDrag}
    >
      {loading && !hasItems ? (
        <div className="absolute inset-0 grid place-items-center text-xs text-[var(--fw-text-muted)]">Carregando…</div>
      ) : !hasItems ? (
        <div className="absolute inset-0 grid place-items-center text-xs text-[var(--fw-text-muted)] px-6 text-center">
          {emptyText}
        </div>
      ) : (
        <svg
          ref={svgRef}
          viewBox={`${b.minX - pad} ${b.minY - pad} ${vbW} ${vbH}`}
          preserveAspectRatio="xMidYMid meet"
          className={`dest-svg w-full h-full ${dimOthers ? 'has-hover' : ''}`}
          role="group"
          aria-label={ariaLabel}
        >
          <g transform={`translate(${cx + pan.x} ${cy + pan.y}) scale(${zoom}) translate(${-cx} ${-cy})`}>
            {[...layout.groups.entries()].map(([group, g]) => {
              const id = `group:${group}`;
              return (
                <g
                  key={id}
                  className={`dest-group ${hoveredId === id ? 'is-hover' : ''}`}
                  onPointerEnter={() => onHover(id)}
                  onPointerLeave={() => onHover(null)}
                >
                  <circle cx={g.x} cy={g.y} r={g.r} className="dest-group-disc" />
                  <text x={g.x} y={g.y + g.r - 9} textAnchor="middle" className="dest-group-label">
                    {truncate(group, Math.floor(g.r / 3.4))}
                  </text>
                  <title>{groupTitle(group, groupTotals.get(group) ?? 0)}</title>
                </g>
              );
            })}

            {items.map((n, index) => {
              const p = layout.nodes.get(n.id);
              if (!p) return null;
              const inGroup = n.group !== null && layout.groups.has(n.group);
              const label = inGroup && n.group ? shortHostLabel(n.label, n.group) : n.label;
              const fs = Math.max(8, Math.min(15, p.r * 0.27));
              const chars = Math.floor((p.r * 1.7) / (fs * 0.56));
              const t = (p.r - MIN_RADIUS) / (MAX_RADIUS - MIN_RADIUS);
              const h = heatStyle(t);
              const isHover = hoveredId === n.id || (hoveredGroup !== null && n.group === hoveredGroup);
              const vars: Record<string, string | number> = {
                '--bob-delay': `${(index * 0.37) % 5}s`,
                '--bob-dur': `${5 + (index % 5)}s`,
                '--ring': heat ? h.stroke : n.ring,
              };
              if (heat) {
                vars['--disc-fill'] = h.fill;
                vars['--disc-stroke'] = h.stroke;
                vars['--disc-w'] = h.strokeWidth;
                vars['--glow'] = h.glow;
                vars['--glow-r'] = `${h.glowRadius}px`;
              }
              return (
                <g
                  key={n.id}
                  ref={(el) => {
                    if (el) nodeEls.current.set(n.id, el);
                    else nodeEls.current.delete(n.id);
                  }}
                >
                  <g
                    className={`dest-bubble ${heat ? 'is-heat' : ''} ${isHover ? 'is-hover' : ''} ${selectedId === n.id ? 'is-selected' : ''}`}
                    style={vars as React.CSSProperties}
                    tabIndex={0}
                    role="button"
                    aria-label={n.aria}
                    onPointerEnter={() => onHover(n.id)}
                    onPointerLeave={() => onHover(null)}
                    onFocus={() => onHover(n.id)}
                    onBlur={() => onHover(null)}
                    // Seleciona no pointerdown: a física empurra a bolha para longe do cursor, então o
                    // pointerup raramente cai no mesmo elemento e o "click" nunca disparava.
                    onPointerDown={(e) => {
                      if (e.button !== 0) return;
                      e.stopPropagation();
                      onSelect(selectedId === n.id ? null : n.id);
                    }}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault();
                        onSelect(selectedId === n.id ? null : n.id);
                      }
                    }}
                  >
                    <g className="dest-bubble-inner">
                      <circle cx={p.x} cy={p.y} r={p.r} className="dest-disc" />
                      {n.blockedShare > 0 && (
                        <circle cx={p.x + p.r * 0.72} cy={p.y - p.r * 0.72} r={Math.max(3, p.r * 0.1)} className="dest-blocked-dot" />
                      )}
                      {p.r >= 17 && (
                        <>
                          <text x={p.x} y={p.y - fs * 0.15} textAnchor="middle" fontSize={fs} className="dest-label">
                            {truncate(label, chars)}
                          </text>
                          <text x={p.x} y={p.y + fs * 1.05} textAnchor="middle" fontSize={fs * 0.85} className="dest-count">
                            {n.valueText}
                          </text>
                        </>
                      )}
                    </g>
                  </g>
                </g>
              );
            })}
          </g>
        </svg>
      )}

      {hasItems && heat && (
        <div className="absolute left-3 bottom-3 flex items-center gap-2 text-[10px] text-[var(--fw-text-muted)] pointer-events-none">
          <span>{legendCold}</span>
          <span className="inline-block h-2 w-24 rounded-full" style={{ background: heatGradientCss() }} aria-hidden="true" />
          <span>{legendHot}</span>
        </div>
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

      {tipOpen && tip && hoveredId && (
        <div
          role="tooltip"
          className="pointer-events-none absolute z-10 w-64 rounded-lg border border-[var(--fw-border-strong)] bg-white p-3 text-xs shadow-xl"
          style={{
            left: Math.min(tip.x + 16, (stageRef.current?.clientWidth ?? 800) - 268),
            top: Math.min(tip.y + 16, (stageRef.current?.clientHeight ?? 560) - 200),
          }}
        >
          {renderTooltip(hoveredId)}
        </div>
      )}
    </div>
  );
}
