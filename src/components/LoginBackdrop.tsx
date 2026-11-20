import { useEffect, useRef } from 'react';
import { Cloud, KeyRound, ShieldCheck, Smartphone, Users, Wifi } from 'lucide-react';
import { startBinaryRain } from '../effects/binaryRain.ts';

/**
 * Fundo animado e levemente desfocado da tela de login. Neutro em relação ao fabricante:
 * cadeados translúcidos flutuando, ícones de rede/nuvem/dispositivos e chuva de dados.
 * Decorativo: invisível para leitores de tela e sem captura de cliques.
 */
function Padlock({ tone }: { tone: 'blue' | 'orange' }) {
  const fill = tone === 'orange' ? 'rgba(255,170,90,0.30)' : 'rgba(125,200,255,0.26)';
  const stroke = tone === 'orange' ? 'rgba(255,205,150,0.6)' : 'rgba(175,228,255,0.6)';
  return (
    <svg viewBox="0 0 100 120" width="100%" height="100%" focusable="false">
      <path d="M28 54V38a22 22 0 0 1 44 0v16" fill="none" stroke={stroke} strokeWidth="9" strokeLinecap="round" />
      <rect x="12" y="52" width="76" height="62" rx="9" fill={fill} stroke={stroke} strokeWidth="2.5" />
      <circle cx="50" cy="78" r="7.5" fill="rgba(6,16,31,0.55)" />
      <path d="M46.5 82h7l3 18h-13z" fill="rgba(6,16,31,0.55)" />
    </svg>
  );
}

interface LockSpec {
  left: string;
  top: string;
  size: number;
  blur: number;
  opacity: number;
  duration: number;
  delay: number;
  rotate: number;
  tone: 'blue' | 'orange';
  hideOnSmall?: boolean;
}

const LOCKS: LockSpec[] = [
  { left: '66%', top: '30%', size: 230, blur: 3, opacity: 0.95, duration: 18, delay: 0, rotate: 0, tone: 'blue' },
  { left: '8%', top: '8%', size: 150, blur: 2.5, opacity: 0.9, duration: 16, delay: -4, rotate: -4, tone: 'orange' },
  { left: '34%', top: '58%', size: 120, blur: 2, opacity: 0.8, duration: 20, delay: -8, rotate: 3, tone: 'blue', hideOnSmall: true },
  { left: '82%', top: '6%', size: 70, blur: 1, opacity: 0.55, duration: 14, delay: -2, rotate: 5, tone: 'blue' },
  { left: '20%', top: '74%', size: 64, blur: 1.5, opacity: 0.5, duration: 15, delay: -6, rotate: -6, tone: 'blue' },
  { left: '56%', top: '8%', size: 46, blur: 0.5, opacity: 0.55, duration: 13, delay: -9, rotate: 2, tone: 'orange', hideOnSmall: true },
  { left: '90%', top: '70%', size: 90, blur: 4, opacity: 0.5, duration: 22, delay: -11, rotate: -3, tone: 'orange', hideOnSmall: true },
];

const TILES = [
  { Icon: Cloud, left: '44%', top: '14%', delay: -1 },
  { Icon: Users, left: '14%', top: '38%', delay: -5 },
  { Icon: Smartphone, left: '72%', top: '64%', delay: -3 },
  { Icon: Wifi, left: '30%', top: '30%', delay: -7 },
  { Icon: ShieldCheck, left: '86%', top: '42%', delay: -9 },
  { Icon: KeyRound, left: '50%', top: '78%', delay: -2 },
];

export function LoginBackdrop() {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    return startBinaryRain(canvas);
  }, []);

  return (
    <div className="login-backdrop" aria-hidden="true">
      <canvas ref={canvasRef} className="login-rain" />
      {LOCKS.map((l, i) => (
        <div
          key={i}
          className={`lb-item ${l.hideOnSmall ? 'hidden sm:block' : ''}`}
          style={
            {
              left: l.left,
              top: l.top,
              width: l.size,
              height: l.size * 1.2,
              '--b': `${l.blur}px`,
              '--o': l.opacity,
              '--d': `${l.duration}s`,
              '--delay': `${l.delay}s`,
              '--r': `${l.rotate}deg`,
            } as React.CSSProperties
          }
        >
          <Padlock tone={l.tone} />
        </div>
      ))}
      {TILES.map(({ Icon, left, top, delay }, i) => (
        <div
          key={i}
          className={`lb-item lb-tile ${i > 3 ? 'hidden md:flex' : 'flex'}`}
          style={{ left, top, '--b': '1.5px', '--o': 0.75, '--d': '12s', '--delay': `${delay}s`, '--r': '0deg' } as React.CSSProperties}
        >
          <Icon className="w-5 h-5 text-sky-100" strokeWidth={1.6} />
        </div>
      ))}
      <div className="login-vignette" />
    </div>
  );
}
