/**
 * Chuva de zeros e uns em canvas, para o fundo da tela de login.
 * Sem dependências. Limita o DPR a 2, limita a ~30 fps, pausa com a aba oculta,
 * desenha um quadro estático sob prefers-reduced-motion e limpa tudo ao parar.
 */
interface Column {
  x: number;
  y: number;
  speed: number;
  len: number;
  bits: number[];
}

const STEP = 26;
const FONT_SIZE = 15;
const LINE_H = 19;
const FRAME_MS = 1000 / 30;

export function startBinaryRain(canvas: HTMLCanvasElement): () => void {
  const ctx = canvas.getContext('2d');
  if (!ctx) return () => undefined;

  const motionQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
  let W = 0;
  let H = 0;
  let cols: Column[] = [];
  let raf = 0;
  let last = 0;
  let animating = false;

  const rand = (min: number, max: number) => min + Math.random() * (max - min);

  function newColumn(x: number, spread: boolean): Column {
    const len = Math.round(rand(8, 24));
    return {
      x,
      y: spread ? rand(-H * 0.2, H * 1.1) : -rand(0, H * 0.4),
      speed: rand(35, 110),
      len,
      bits: Array.from({ length: 48 }, () => (Math.random() < 0.5 ? 0 : 1)),
    };
  }

  function resize() {
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    W = window.innerWidth;
    H = window.innerHeight;
    canvas.width = Math.round(W * dpr);
    canvas.height = Math.round(H * dpr);
    ctx!.setTransform(dpr, 0, 0, dpr, 0, 0);
    cols = [];
    for (let x = STEP / 2; x < W; x += STEP) cols.push(newColumn(x, true));
    draw(0);
  }

  function draw(dt: number) {
    const c = ctx!;
    c.clearRect(0, 0, W, H);
    c.font = `${FONT_SIZE}px "JetBrains Mono", ui-monospace, Menlo, monospace`;
    c.textAlign = 'center';
    for (let k = 0; k < cols.length; k += 1) {
      const col = cols[k];
      col.y += col.speed * dt;
      if (col.y - col.len * LINE_H > H) cols[k] = newColumn(col.x, false);
      for (let i = 0; i < col.len; i += 1) {
        const yy = col.y - i * LINE_H;
        if (yy < -LINE_H || yy > H + LINE_H) continue;
        const row = Math.floor(yy / LINE_H);
        c.globalAlpha = i === 0 ? 0.95 : (1 - i / col.len) * 0.6;
        c.fillStyle = i === 0 ? '#e6fbff' : '#7fd8ff';
        c.fillText(String(col.bits[((row % 48) + 48) % 48]), col.x, yy);
      }
    }
    c.globalAlpha = 1;
  }

  const loop = (t: number) => {
    raf = requestAnimationFrame(loop);
    if (document.hidden) {
      last = t;
      return;
    }
    if (t - last < FRAME_MS) return;
    const dt = Math.min((t - last) / 1000, 0.1);
    last = t;
    // Troca alguns dígitos de vez em quando: dá a impressão de dados "vivos"
    const col = cols[(Math.random() * cols.length) | 0];
    if (col) col.bits[(Math.random() * 48) | 0] ^= 1;
    draw(dt);
  };

  function start() {
    if (animating) return;
    animating = true;
    last = performance.now();
    raf = requestAnimationFrame(loop);
  }

  function stop() {
    if (!animating) return;
    animating = false;
    cancelAnimationFrame(raf);
    draw(0);
  }

  const onMotionChange = () => (motionQuery.matches ? stop() : start());

  resize();
  window.addEventListener('resize', resize);
  motionQuery.addEventListener('change', onMotionChange);
  if (!motionQuery.matches) start();

  return () => {
    animating = false;
    cancelAnimationFrame(raf);
    window.removeEventListener('resize', resize);
    motionQuery.removeEventListener('change', onMotionChange);
  };
}
