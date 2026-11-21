import { useMemo, useState } from 'react';
import type { BehaviorCountry } from '../types.ts';
import { heatHue } from '../utils/heat.ts';
import { MAP_H, MAP_W, countryName, flagEmoji, getWorldGeo } from '../utils/worldGeo.ts';

export type MapMode = 'realtime' | 'static';

interface WorldMapProps {
  countries: BehaviorCountry[];
  originCode: string;
  mode: MapMode;
  selected: string | null;
  onSelect: (code: string | null) => void;
  recentByCountry: Map<string, number>;
}

const MAX_ARCS = 14;
const reducedMotion = () =>
  typeof window !== 'undefined' && window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;

const fmt = (n: number) => n.toLocaleString('pt-BR');

function heatT(conn: number, max: number): number {
  return max > 0 ? Math.log1p(conn) / Math.log1p(max) : 0;
}

export function WorldMap({ countries, originCode, mode, selected, onSelect, recentByCountry }: WorldMapProps) {
  const geo = useMemo(() => getWorldGeo(), []);
  const [hover, setHover] = useState<{ code: string; x: number; y: number } | null>(null);
  const still = useMemo(() => reducedMotion(), []);

  const byCode = useMemo(() => new Map(countries.map((c) => [c.code, c])), [countries]);
  const max = countries.reduce((m, c) => Math.max(m, c.connections), 0);

  const origin = geo.byCode.get(originCode);
  const originXY = origin ? geo.project(origin.centroid[0], origin.centroid[1]) : null;

  const arcs = useMemo(() => {
    if (!originXY) return [];
    const top = countries.filter((c) => c.code !== originCode).slice(0, MAX_ARCS);
    const topMax = top.reduce((m, c) => Math.max(m, c.connections), 0);
    return top
      .map((c, i) => {
        const g = geo.byCode.get(c.code);
        if (!g) return null;
        const [x2, y2] = geo.project(g.centroid[0], g.centroid[1]);
        const [x1, y1] = originXY;
        const dist = Math.hypot(x2 - x1, y2 - y1);
        const cx = (x1 + x2) / 2;
        const cy = (y1 + y2) / 2 - Math.min(180, dist * 0.32);
        const share = topMax > 0 ? c.connections / topMax : 0;
        const recent = recentByCountry.get(c.code) ?? 0;
        const color = c.threatIps > 0 ? '#ef4444' : c.connections > 0 && c.blocked / c.connections > 0.3 ? '#f59e0b' : '#38bdf8';
        return {
          code: c.code,
          d: `M${x1.toFixed(1)} ${y1.toFixed(1)} Q${cx.toFixed(1)} ${cy.toFixed(1)} ${x2.toFixed(1)} ${y2.toFixed(1)}`,
          color,
          width: 0.8 + share * 2.6,
          particles: Math.max(1, Math.round(1 + share * 4 + Math.min(2, recent / 20))),
          seed: i,
          x2,
          y2,
        };
      })
      .filter((a): a is NonNullable<typeof a> => a !== null);
  }, [countries, geo, originCode, originXY, recentByCountry]);

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
            <feGaussianBlur stdDeviation="2.2" result="b" />
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
            const isOrigin = c.code === originCode;
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
            if (isOrigin) {
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

        {mode === 'realtime' && (
          <g filter="url(#bhv-glow)" pointerEvents="none">
            {arcs.map((a) => (
              <g key={a.code}>
                <path d={a.d} fill="none" stroke={a.color} strokeOpacity={selected && selected !== a.code ? 0.12 : 0.45} strokeWidth={a.width} strokeLinecap="round" />
                {!still &&
                  Array.from({ length: a.particles }, (_, k) => (
                    <circle key={k} r={1.8 + a.width * 0.35} fill={a.color} opacity={selected && selected !== a.code ? 0.25 : 1}>
                      <animateMotion
                        dur={`${2.4 + ((a.seed * 7 + k * 3) % 10) * 0.18}s`}
                        begin={`${((a.seed * 5 + k * 13) % 17) * 0.23}s`}
                        repeatCount="indefinite"
                        path={a.d}
                        keyPoints="0;1"
                        keyTimes="0;1"
                        calcMode="linear"
                      />
                    </circle>
                  ))}
              </g>
            ))}
          </g>
        )}

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
                  {(c.threatIps > 0 || mode === 'static') && !still && (
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
          style={{ left: Math.min(hover.x + 14, 9999), top: hover.y + 14 }}
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
