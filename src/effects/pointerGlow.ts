/**
 * Brilho radial que segue o ponteiro dentro de elementos com a classe `.fx`.
 * Só atualiza as variáveis CSS --mx e --my; o desenho é feito em CSS (ver index.css).
 */
const GLOW_PARK = '-400px';

export function startPointerGlow(root: Document = document): () => void {
  let active: HTMLElement | null = null;

  const park = (el: HTMLElement | null) => {
    el?.style.setProperty('--mx', GLOW_PARK);
    el?.style.setProperty('--my', GLOW_PARK);
  };

  const onMove = (e: PointerEvent) => {
    const target = e.target instanceof Element ? e.target : null;
    const el = target?.closest<HTMLElement>('.fx') ?? null;
    if (el !== active) {
      park(active);
      active = el;
    }
    if (!el) return;
    const r = el.getBoundingClientRect();
    el.style.setProperty('--mx', `${e.clientX - r.left}px`);
    el.style.setProperty('--my', `${e.clientY - r.top}px`);
  };

  const onLeave = () => {
    park(active);
    active = null;
  };

  root.addEventListener('pointermove', onMove, { passive: true });
  root.documentElement.addEventListener('pointerleave', onLeave);
  window.addEventListener('blur', onLeave);

  return () => {
    root.removeEventListener('pointermove', onMove);
    root.documentElement.removeEventListener('pointerleave', onLeave);
    window.removeEventListener('blur', onLeave);
    park(active);
  };
}
