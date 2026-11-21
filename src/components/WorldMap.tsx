import { useEffect, useMemo, useRef, useState } from 'react';
import type { BehaviorCountry, BehaviorFlow } from '../types.ts';
import { heatHue } from '../utils/heat.ts';
import { MAP_H, MAP_W, countryName, flagEmoji, getWorldGeo } from '../utils/worldGeo.ts';

export type MapMode = 'realtime' | 'static';

/** Lote de conexões REAIS novas (cada item é uma conexão do log), reproduzidas na ordem em que ocorreram. */
export interface FlowBatch {
  id: number;
  flows: BehaviorFlow[];
  sampleEvery: number;
}

interface WorldMapProps {
  countries: BehaviorCountry[];
  originCode: string;
  mode: MapMode;
  selected: string | null;
  onSelect: (code: string | null) => void;
  batch: FlowBatch | null;
  /** Janela (ms) em que um lote é reproduzido: igual ao intervalo de atualização. */
  replayMs: number;
}

const SVG_NS = 'http://www.w3.org/2000/svg';
const MAX_ARCS = 14;
const MAX_LIVE_PARTICLES = 260;
const reducedMotion = () =>
  typeof window !== 'undefined' && window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;

const fmt = (n: number) => n.toLocaleString('pt-BR');
const heatT = (conn: number, max: number) => (max > 0 ? Math.log1p(conn) / Math.log1p(max) : 0);

interface Pending {
  at: number;
  code: string;
  blocked: boolean;
  threat: boolean;
}

interface Live {
  el: SVGCircleElement;
  ring: SVGCircleElement | null;
  path: SVGPathElement;
  start: number;
  dur: number;
  blocked: boolean;
  threat: boolean;
  len: number;
  done: boolean;
}

export function WorldMap({ countries, originCode, mode, selected, onSelect, batch, replayMs }: WorldMapProps) {
  const geo = useMemo(() => getWorldGeo(), []);
  const [hover, setHover] = useState<{ code: string; x: number; y: number } | null>(null);
  const still = useMemo(() => reducedMotion(), []);

  const particlesRef = useRef<SVGGElement | null>(null);
  const arcEls = useRef(new Map<string, SVGPathElement>());
  const pending = useRef<Pending[]>([]);
  const live = useRef<Live[]>([]);
  const lastBatch = useRef<number>(-1);

  const byCode = useMemo(() => new Map(countries.map((c) => [c.code, c])), [countries]);
  const max = countries.reduce((m, c) => Math.max(m, c.connections), 0);

  const origin = geo.byCode.get(originCode);
  const originXY = origin ? geo.project(origin.centroid[0], origin.centroid[1]) : null;

  // Arcos: os países mais acessados no período + qualquer país que apareça no lote em reprodução
  const arcCodes = useMemo(() => {
    const set = new Set(countries.filter((c) => c.code !== originCode).slice(0, MAX_ARCS).map((c) => c.code));
    for (const f of batch?.flows ?? []) if (f.country !== originCode) set.add(f.country);
    return [...set];
  }, [countries, originCode, batch]);

  const arcs = useMemo(() => {
    if (!originXY) return [];
    const topMax = countries.filter((c) => c.code !== originCode).reduce((m, c) => Math.max(m, c.connections), 0);
    return arcCodes
      .map((code) => {
        const g = geo.byCode.get(code);
        if (!g) return null;
        const [x2, y2] = geo.project(g.centroid[0], g.centroid[1]);
        const [x1, y1] = originXY;
        const dist = Math.hypot(x2 - x1, y2 - y1);
        const cx = (x1 + x2) / 2;
        const cy = (y1 + y2) / 2 - Math.min(180, dist * 0.32);
        const c = byCode.get(code);
        const share = c && topMax > 0 ? c.connections / topMax : 0.05;
        const color = c && c.threatIps > 0 ? '#ef4444' : c && c.connections > 0 && c.blocked / c.connections > 0.3 ? '#f59e0b' : '#38bdf8';
        return { code, d: `M${x1.toFixed(1)} ${y1.toFixed(1)} Q${cx.toFixed(1)} ${cy.toFixed(1)} ${x2.toFixed(1)} ${y2.toFixed(1)}`, color, width: 0.6 + share * 2.2 };
      })
      .filter((a): a is NonNullable<typeof a> => a !== null);
  }, [arcCodes, byCode, countries, geo, originCode, originXY]);

  // Novo lote de conexões reais: agenda cada uma no instante proporcional ao horário em que ocorreu
  useEffect(() => {
    if (mode !== 'realtime' || still || !batch || batch.id === lastBatch.current) return;
    lastBatch.current = batch.id;
    const flows = batch.flows.filter((f) => f.country !== originCode);
    if (flows.length === 0) return;
    const times = flows.map((f) => Date.parse(f.at));
    const first = Math.min(...times);
    const span = Math.max(1, Math.max(...times) - first);
    const now = performance.now();
    const window = Math.max(1500, replayMs - 800);
    flows.forEach((f, i) => {
      const offset = span <= 1 ? (i / flows.length) * window : ((times[i] - first) / span) * window;
      pending.current.push({ at: now + offset, code: f.country, blocked: f.blocked, threat: f.threat });
    });
    if (pending.current.length > 2000) pending.current.splice(0, pending.current.length - 2000);
  }, [batch, mode, still, originCode, replayMs]);

  // Laço de animação: cada partícula é UMA conexão real
  useEffect(() => {
    const layer = particlesRef.current;
    if (mode !== 'realtime' || still || !layer) {
      pending.current = [];
      live.current = [];
      if (layer) layer.replaceChildren();
      return;
    }
    let raf = 0;
    const circle = (r: number, fill: string, opacity = 1) => {
      const el = document.createElementNS(SVG_NS, 'circle');
      el.setAttribute('r', String(r));
      el.setAttribute('fill', fill);
      el.setAttribute('opacity', String(opacity));
      layer.appendChild(el);
      return el;
    };
    const tick = (t: number) => {
      raf = requestAnimationFrame(tick);
      // nascimento
      const due: Pending[] = [];
      const rest: Pending[] = [];
      for (const p of pending.current) (p.at <= t ? due : rest).push(p);
      pending.current = rest;
      for (const p of due) {
        const path = arcEls.current.get(p.code);
        if (!path || live.current.length >= MAX_LIVE_PARTICLES) continue;
        const len = path.getTotalLength();
        const color = p.threat ? '#f43f5e' : p.blocked ? '#f59e0b' : '#38bdf8';
        live.current.push({
          el: circle(p.threat ? 3.6 : p.blocked ? 2.6 : 2.2, color),
          ring: null,
          path,
          start: t,
          dur: Math.min(3200, 1300 + len * 2.4),
          blocked: p.blocked,
          threat: p.threat,
          len,
          done: false,
        });
      }
      // movimento
      const keep: Live[] = [];
      for (const l of live.current) {
        const p = (t - l.start) / l.dur;
        // bloqueada: morre a ~35% do caminho (o destino nunca é alcançado); permitida: chega ao fim
        const stopAt = l.blocked ? 0.35 : 1;
        const pos = Math.min(p, stopAt);
        const pt = l.path.getPointAtLength(l.len * pos);
        l.el.setAttribute('cx', pt.x.toFixed(1));
        l.el.setAttribute('cy', pt.y.toFixed(1));
        if (p >= stopAt) {
          if (!l.ring) {
            l.ring = circle(2, 'none');
            l.ring.setAttribute('stroke', l.blocked ? '#f59e0b' : l.threat ? '#f43f5e' : '#38bdf8');
            l.ring.setAttribute('stroke-width', '1.4');
            l.ring.setAttribute('cx', pt.x.toFixed(1));
            l.ring.setAttribute('cy', pt.y.toFixed(1));
            l.el.setAttribute('opacity', l.blocked ? '0' : '0.9');
          }
          const q = Math.min(1, (p - stopAt) / 0.35);
          l.ring.setAttribute('r', String(2 + q * (l.threat ? 14 : 9)));
          l.ring.setAttribute('opacity', String(1 - q));
          if (q >= 1) {
            l.el.remove();
            l.ring.remove();
            continue;
          }
        }
        keep.push(l);
      }
      live.current = keep;
    };
    raf = requestAnimationFrame(tick);
    return () => {
      cancelAnimationFrame(raf);
      pending.current = [];
      live.current = [];
      layer.replaceChildren();
    };
  }, [mode, still]);

  const hovered = hover ? byCode.get(hover.code) : null;

  return (
    <div className="relative rounded-md bg-[var(--fw-surface-soft)] overflow-hidden">
      <svg viewBox={`0 0 ${MAP_W} ${MAP_H}`} className="w-full h-auto block" role="img" aria-label="Mapa mundi de tráfego por país">
        <defs>
          <radialGradient id="bhv-ocean" cx="50%" cy="45%" r="70%">
            <stop offset="0%" stopColor="rgba(56,189,248,0.10)" />
            <stop offset="100%" stopColor="rgba(56,189,248,0.02)" />
          </radialGradient>
          <filter id="bhv-glow" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="2" result="b" />
            <feMerge>
              <feMergeNode in="b" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>
        <path d={geo.sphere} fill="url(#bhv-ocean)" stroke="var(--fw-border)" strokeWidth={0.6} />

        <g>
          {geo.countries.map((c) => {
            const data = byCode.get(c.code);
            const t = data ? heatT(data.connections, max) : 0;
            const isSel = selected === c.code;
            let fill = 'var(--fw-surface-alt)';
            let fillOpacity = 1;
            if (data) {
              if (mode === 'static') {
                fill = `hsl(${heatHue(t)} 85% 52%)`;
                fillOpacity = 0.35 + t * 0.6;
              } else {
                fill = '#38bdf8';
                fillOpacity = 0.12 + t * 0.42;
              }
            }
            if (c.code === originCode) {
              fill = '#2563eb';
              fillOpacity = 0.55;
            }
            return (
              <path
                key={c.code}
                d={c.d}
                fill={fill}
                fillOpacity={fillOpacity}
                stroke={isSel ? '#f8fafc' : 'var(--fw-border-strong)'}
                strokeWidth={isSel ? 1.6 : 0.4}
                className={data ? 'cursor-pointer' : undefined}
                onPointerMove={(e) => {
                  const box = e.currentTarget.ownerSVGElement?.getBoundingClientRect();
                  if (data && box) setHover({ code: c.code, x: e.clientX - box.left, y: e.clientY - box.top });
                }}
                onPointerLeave={() => setHover(null)}
                onClick={() => data && onSelect(isSel ? null : c.code)}
              >
                <title>{c.name}</title>
              </path>
            );
          })}
        </g>

        {/* Rotas: espessura = participação no período. Em tempo real, as partículas são conexões reais. */}
        <g pointerEvents="none" filter={mode === 'realtime' ? 'url(#bhv-glow)' : undefined}>
          {arcs.map((a) => (
            <path
              key={a.code}
              ref={(el) => {
                if (el) arcEls.current.set(a.code, el);
                else arcEls.current.delete(a.code);
              }}
              d={a.d}
              fill="none"
              stroke={a.color}
              strokeOpacity={mode === 'static' ? 0 : selected && selected !== a.code ? 0.1 : 0.32}
              strokeWidth={a.width}
              strokeLinecap="round"
            />
          ))}
          <g ref={particlesRef} />
        </g>

        {/* Pontos vermelhos: onde estão os destinos (centro do país: a base é por país) */}
        <g pointerEvents="none">
          {countries
            .filter((c) => c.code !== originCode)
            .slice(0, mode === 'static' ? 60 : 24)
            .map((c) => {
              const g = geo.byCode.get(c.code);
              if (!g) return null;
              const [x, y] = geo.project(g.centroid[0], g.centroid[1]);
              const r = 2 + heatT(c.connections, max) * 4.5;
              return (
                <g key={c.code}>
                  {c.threatIps > 0 && !still && (
                    <circle cx={x} cy={y} r={r} fill="none" stroke="#ef4444" strokeWidth={1}>
                      <animate attributeName="r" values={`${r};${r + 9}`} dur="2.2s" repeatCount="indefinite" />
                      <animate attributeName="opacity" values="0.8;0" dur="2.2s" repeatCount="indefinite" />
                    </circle>
                  )}
                  <circle cx={x} cy={y} r={r} fill="#ef4444" stroke="#fff" strokeWidth={0.8} opacity={c.threatIps > 0 ? 1 : 0.85} />
                </g>
              );
            })}
        </g>

        {originXY && (
          <g pointerEvents="none">
            {!still && (
              <circle cx={originXY[0]} cy={originXY[1]} r={5} fill="none" stroke="#60a5fa" strokeWidth={1.2}>
                <animate attributeName="r" values="5;16" dur="2.6s" repeatCount="indefinite" />
                <animate attributeName="opacity" values="0.9;0" dur="2.6s" repeatCount="indefinite" />
              </circle>
            )}
            <circle cx={originXY[0]} cy={originXY[1]} r={5} fill="#3b82f6" stroke="#fff" strokeWidth={1.4} />
          </g>
        )}
      </svg>

      {hovered && hover && (
        <div
          role="tooltip"
          className="pointer-events-none absolute z-10 w-56 rounded-lg border border-[var(--fw-border-strong)] bg-white p-3 text-xs shadow-xl"
          style={{ left: hover.x + 14, top: hover.y + 14 }}
        >
          <p className="font-semibold text-[var(--fw-heading)]">
            {flagEmoji(hovered.code)} {countryName(hovered.code)}
          </p>
          <p className="mt-1 text-[var(--fw-text-muted)] tabular-nums">
            {fmt(hovered.connections)} conexões · {fmt(hovered.blocked)} bloqueadas
          </p>
          <p className="text-[var(--fw-text-muted)] tabular-nums">{fmt(hovered.ips)} IPs distintos</p>
          {hovered.threatIps > 0 && <p className="mt-1 font-semibold text-red-600">{fmt(hovered.threatIps)} IP(s) em lista de ameaça</p>}
        </div>
      )}
    </div>
  );
}
