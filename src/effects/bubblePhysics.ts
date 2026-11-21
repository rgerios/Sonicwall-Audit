/**
 * Física leve das bolhas do radar: o ponteiro empurra as bolhas próximas (com um leve giro em
 * torno dele, como nos "pixels" do fundo) e uma mola traz cada uma de volta à posição de repouso.
 * Sem dependências e sem DOM: recebe e altera números, para poder ser testada.
 */
export interface Body {
  id: string;
  /** Posição de repouso (centro) e raio. */
  x: number;
  y: number;
  r: number;
  /** Deslocamento atual e velocidade (o que a mola e o ponteiro alteram). */
  ox: number;
  oy: number;
  vx: number;
  vy: number;
  /** Fase da deriva ociosa (diferente para cada bolha). */
  seed: number;
  /** Se a bolha pertence a um grupo, ela não pode sair do círculo do grupo. */
  parent?: { x: number; y: number; r: number };
}

export interface Pointer {
  x: number;
  y: number;
  active: boolean;
}

export interface PhysicsOptions {
  /** Alcance do ponteiro (a partir da borda da bolha). */
  radius: number;
  /** Deslocamento máximo empurrando para fora e girando, em unidades do layout. */
  push: number;
  swirl: number;
  /** Mola (1/s²) e amortecimento (1/s). */
  stiffness: number;
  damping: number;
  /** Amplitude da deriva ociosa. */
  drift: number;
}

export const DEFAULT_PHYSICS: PhysicsOptions = {
  radius: 170,
  push: 30,
  swirl: 12,
  stiffness: 70,
  damping: 9,
  drift: 2.4,
};

export function seedFor(id: string): number {
  let h = 0;
  for (let i = 0; i < id.length; i += 1) h = (h * 31 + id.charCodeAt(i)) >>> 0;
  return (h % 6283) / 1000;
}

export function createBody(
  id: string,
  x: number,
  y: number,
  r: number,
  parent?: { x: number; y: number; r: number }
): Body {
  return { id, x, y, r, ox: 0, oy: 0, vx: 0, vy: 0, seed: seedFor(id), parent };
}

/** Avança a simulação dt segundos. timeMs alimenta a deriva ociosa. */
export function stepBodies(
  bodies: Body[],
  pointer: Pointer,
  dtRaw: number,
  timeMs: number,
  options: Partial<PhysicsOptions> = {}
): void {
  const o = { ...DEFAULT_PHYSICS, ...options };
  // Evita saltos (aba em segundo plano, quadro lento) que fariam a mola explodir
  const dt = Math.min(0.05, Math.max(0, dtRaw));
  if (dt === 0) return;

  for (const b of bodies) {
    let tx = Math.sin(timeMs * 0.0007 + b.seed) * o.drift;
    let ty = Math.cos(timeMs * 0.0006 + b.seed * 1.3) * o.drift;

    if (pointer.active) {
      const dx = b.x - pointer.x;
      const dy = b.y - pointer.y;
      const d = Math.hypot(dx, dy);
      // Distância até a BORDA: quem está sob o ponteiro não foge dele (precisa continuar clicável)
      const edge = d - b.r;
      if (edge > 0 && edge < o.radius) {
        const f = Math.pow(1 - edge / o.radius, 1.6);
        const nx = dx / (d || 1);
        const ny = dy / (d || 1);
        // Bolhas pequenas são mais leves: movem mais
        const lightness = Math.min(1.6, Math.max(0.55, 28 / b.r));
        tx += nx * o.push * f * lightness - ny * o.swirl * f * lightness;
        ty += ny * o.push * f * lightness + nx * o.swirl * f * lightness;
      }
    }

    b.vx += (o.stiffness * (tx - b.ox) - o.damping * b.vx) * dt;
    b.vy += (o.stiffness * (ty - b.oy) - o.damping * b.vy) * dt;
    b.ox += b.vx * dt;
    b.oy += b.vy * dt;

    if (b.parent) {
      const maxDist = Math.max(0, b.parent.r - b.r - 2);
      const ax = b.x + b.ox - b.parent.x;
      const ay = b.y + b.oy - b.parent.y;
      const dist = Math.hypot(ax, ay);
      if (dist > maxDist && dist > 0) {
        const k = maxDist / dist;
        b.ox = b.parent.x + ax * k - b.x;
        b.oy = b.parent.y + ay * k - b.y;
        // Anula a velocidade que ainda empurra para fora
        const nx = ax / dist;
        const ny = ay / dist;
        const out = b.vx * nx + b.vy * ny;
        if (out > 0) {
          b.vx -= out * nx;
          b.vy -= out * ny;
        }
      }
    }
  }
}
