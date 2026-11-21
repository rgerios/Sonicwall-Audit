/**
 * Escala de calor das bolhas: t = 0 (pequena) é azul frio e t = 1 (grande) é vermelho quente,
 * passando por ciano, verde, amarelo e laranja.
 */
const STOPS: Array<[number, number]> = [
  [0, 218],
  [0.2, 195],
  [0.4, 150],
  [0.6, 58],
  [0.8, 28],
  [1, 2],
];

const clamp01 = (v: number) => Math.min(1, Math.max(0, Number.isFinite(v) ? v : 0));

/** Matiz HSL (0 a 360) para a posição t na escala. */
export function heatHue(t: number): number {
  const x = clamp01(t);
  for (let i = 1; i < STOPS.length; i += 1) {
    const [t1, h1] = STOPS[i];
    if (x <= t1) {
      const [t0, h0] = STOPS[i - 1];
      return h0 + ((x - t0) / (t1 - t0)) * (h1 - h0);
    }
  }
  return STOPS[STOPS.length - 1][1];
}

export interface HeatStyle {
  hue: number;
  stroke: string;
  fill: string;
  glow: string;
  glowRadius: number;
  strokeWidth: number;
}

/** Cores de uma bolha na posição t: contorno forte, preenchimento translúcido e brilho nas quentes. */
export function heatStyle(t: number): HeatStyle {
  const x = clamp01(t);
  const hue = Math.round(heatHue(x));
  return {
    hue,
    stroke: `hsl(${hue} 82% 44%)`,
    fill: `hsl(${hue} 90% 56% / ${(0.12 + 0.3 * x).toFixed(2)})`,
    glow: `hsl(${hue} 95% 55% / ${(0.65 * x * x).toFixed(2)})`,
    glowRadius: Math.round(2 + 14 * x),
    strokeWidth: Number((1.2 + 2.2 * x).toFixed(2)),
  };
}

/** Degradê CSS da legenda (do frio ao quente). */
export function heatGradientCss(): string {
  const stops = STOPS.map(([t, h]) => `hsl(${h} 85% 50%) ${Math.round(t * 100)}%`).join(', ');
  return `linear-gradient(90deg, ${stops})`;
}
