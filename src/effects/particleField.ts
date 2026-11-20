/**
 * Campo de partículas em canvas que reage ao ponteiro.
 * Sem dependências. Retorna uma função de limpeza que cancela o loop e remove todos os listeners.
 */
export interface ParticleFieldOptions {
  /** Espaçamento da grade em px. */
  gap: number;
  /** Raio de influência do cursor em px. */
  radius: number;
  /** Deslocamento máximo para fora, em px. */
  repel: number;
  /** Matiz (HSL) quando o traço está longe do cursor, e quanto ele avança ao chegar perto. */
  hueBase: number;
  hueRange: number;
  /** Cor dos traços em repouso. */
  rest: string;
}

export const DEFAULT_PARTICLE_OPTIONS: ParticleFieldOptions = {
  gap: 30,
  radius: 200,
  repel: 16,
  hueBase: 190,
  hueRange: 70,
  rest: 'rgba(120,150,200,0.2)',
};

interface Particle {
  x: number;
  y: number;
  k: number;
}

/** Lê as cores do tema (variáveis CSS --fx-*) com os valores padrão como fallback. */
export function readThemeOptions(
  base: ParticleFieldOptions,
  style: CSSStyleDeclaration = getComputedStyle(document.documentElement)
): ParticleFieldOptions {
  const num = (name: string, fallback: number) => {
    const raw = Number.parseFloat(style.getPropertyValue(name));
    return Number.isFinite(raw) ? raw : fallback;
  };
  const rest = style.getPropertyValue('--fx-rest').trim();
  return {
    ...base,
    hueBase: num('--fx-hue-base', base.hueBase),
    hueRange: num('--fx-hue-range', base.hueRange),
    rest: rest || base.rest,
  };
}

export function startParticleField(
  canvas: HTMLCanvasElement,
  opts: Partial<ParticleFieldOptions> = {}
): () => void {
  const ctx = canvas.getContext('2d');
  if (!ctx) return () => undefined;

  let o: ParticleFieldOptions = readThemeOptions({ ...DEFAULT_PARTICLE_OPTIONS, ...opts });
  const motionQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
  const m = { x: -9999, y: -9999, tx: -9999, ty: -9999, on: false };
  let W = 0;
  let H = 0;
  let parts: Particle[] = [];
  let raf = 0;
  let animating = false;

  function resize() {
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    W = window.innerWidth;
    H = window.innerHeight;
    canvas.width = Math.round(W * dpr);
    canvas.height = Math.round(H * dpr);
    ctx!.setTransform(dpr, 0, 0, dpr, 0, 0);
    parts = [];
    for (let y = o.gap / 2; y < H; y += o.gap) {
      for (let x = o.gap / 2; x < W; x += o.gap) {
        parts.push({
          x: x + (Math.random() - 0.5) * 8,
          y: y + (Math.random() - 0.5) * 8,
          k: Math.random() * 6.28,
        });
      }
    }
    if (!animating) draw(0);
  }

  function draw(t: number) {
    const c = ctx!;
    c.clearRect(0, 0, W, H);
    // Easing de 14% por frame: o ponto de influência persegue o mouse sem saltar
    m.x += (m.tx - m.x) * 0.14;
    m.y += (m.ty - m.y) * 0.14;
    c.lineCap = 'round';
    c.lineWidth = 1.4;
    c.strokeStyle = o.rest;
    c.beginPath();
    const hot: Array<{ p: Particle; base: number; dx: number; dy: number; d: number; f: number }> = [];
    for (const p of parts) {
      const base = Math.sin(p.x * 0.008 + t * 0.0004 + p.k * 0.1) + Math.cos(p.y * 0.01 - t * 0.0003);
      const dx = m.x - p.x;
      const dy = m.y - p.y;
      const d = Math.hypot(dx, dy);
      const f = m.on && d < o.radius ? Math.pow(1 - d / o.radius, 1.6) : 0;
      if (f < 0.02) {
        const cx = Math.cos(base) * 3;
        const cy = Math.sin(base) * 3;
        c.moveTo(p.x - cx, p.y - cy);
        c.lineTo(p.x + cx, p.y + cy);
      } else {
        hot.push({ p, base, dx, dy, d: d || 1, f });
      }
    }
    c.stroke();
    for (const { p, base, dx, dy, d, f } of hot) {
      // Mistura o ruído de repouso com a tangente ao cursor (órbita) conforme a proximidade
      const tang = Math.atan2(dy, dx) + Math.PI / 2;
      const ang = Math.atan2(
        Math.sin(base) * (1 - f) + Math.sin(tang) * f,
        Math.cos(base) * (1 - f) + Math.cos(tang) * f
      );
      const px = p.x - (dx / d) * f * o.repel;
      const py = p.y - (dy / d) * f * o.repel;
      const len = 3 + f * 9;
      c.strokeStyle = `hsla(${o.hueBase + f * o.hueRange}, 90%, ${58 + f * 12}%, ${0.25 + f * 0.75})`;
      c.lineWidth = 1.4 + f * 1.2;
      c.beginPath();
      c.moveTo(px - Math.cos(ang) * len, py - Math.sin(ang) * len);
      c.lineTo(px + Math.cos(ang) * len, py + Math.sin(ang) * len);
      c.stroke();
    }
  }

  const loop = (t: number) => {
    if (!document.hidden) draw(t);
    raf = requestAnimationFrame(loop);
  };

  const onMove = (e: PointerEvent) => {
    m.tx = e.clientX;
    m.ty = e.clientY;
    if (!m.on) {
      m.x = e.clientX;
      m.y = e.clientY;
    }
    m.on = true;
  };
  const onLeave = () => {
    m.on = false;
  };
  // 'pointerleave' no document nem sempre dispara ao sair da janela: mouseout sem destino cobre isso
  const onMouseOut = (e: MouseEvent) => {
    if (!e.relatedTarget) m.on = false;
  };

  function startAnimation() {
    if (animating) return;
    animating = true;
    window.addEventListener('pointermove', onMove, { passive: true });
    document.documentElement.addEventListener('pointerleave', onLeave);
    document.addEventListener('mouseout', onMouseOut);
    window.addEventListener('blur', onLeave);
    raf = requestAnimationFrame(loop);
  }

  function stopAnimation() {
    if (!animating) return;
    animating = false;
    cancelAnimationFrame(raf);
    window.removeEventListener('pointermove', onMove);
    document.documentElement.removeEventListener('pointerleave', onLeave);
    document.removeEventListener('mouseout', onMouseOut);
    window.removeEventListener('blur', onLeave);
    m.on = false;
    draw(0);
  }

  const onMotionPreferenceChange = () => {
    if (motionQuery.matches) stopAnimation();
    else startAnimation();
  };

  // Troca de tema/fabricante muda as variáveis --fx-*; relê sem recriar a grade
  const themeObserver = new MutationObserver(() => {
    o = readThemeOptions({ ...DEFAULT_PARTICLE_OPTIONS, ...opts });
    if (!animating) draw(0);
  });
  themeObserver.observe(document.documentElement, {
    attributes: true,
    attributeFilter: ['data-theme', 'data-vendor'],
  });

  resize();
  window.addEventListener('resize', resize);
  motionQuery.addEventListener('change', onMotionPreferenceChange);
  if (motionQuery.matches) draw(0);
  else startAnimation();

  return () => {
    cancelAnimationFrame(raf);
    animating = false;
    window.removeEventListener('resize', resize);
    window.removeEventListener('pointermove', onMove);
    document.documentElement.removeEventListener('pointerleave', onLeave);
    document.removeEventListener('mouseout', onMouseOut);
    window.removeEventListener('blur', onLeave);
    motionQuery.removeEventListener('change', onMotionPreferenceChange);
    themeObserver.disconnect();
  };
}
