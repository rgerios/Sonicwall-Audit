import { useEffect, useRef } from 'react';
import { startParticleField } from '../effects/particleField.ts';
import { startPointerGlow } from '../effects/pointerGlow.ts';

/**
 * Fundo decorativo: campo de partículas atrás de todo o conteúdo e brilho nos elementos `.fx`.
 * Não captura cliques (pointer-events: none) e é invisível para leitores de tela.
 */
export function ParticleBackground() {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const stopField = startParticleField(canvas);
    const stopGlow = startPointerGlow();
    return () => {
      stopField();
      stopGlow();
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      aria-hidden="true"
      className="fx-canvas"
      style={{ position: 'fixed', inset: 0, width: '100%', height: '100%', pointerEvents: 'none', zIndex: 0 }}
    />
  );
}
