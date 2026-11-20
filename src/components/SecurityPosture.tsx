import { useEffect, useMemo, useState } from 'react';
import { ArrowRight, CheckCircle2, ChevronDown, ChevronUp, TrendingDown, TrendingUp } from 'lucide-react';
import type { ActiveSection, AuditOverview, FirewallVendor } from '../types.ts';
import {
  computePosture,
  GRADE_LABEL,
  loadPostureHistory,
  postureDelta,
  recordPostureSnapshot,
  SEVERITY_LABEL,
  type FindingSeverity,
  type PostureGrade,
} from '../utils/posture.ts';

interface SecurityPostureProps {
  vendor: FirewallVendor;
  overview: AuditOverview;
  onNavigate: (section: ActiveSection) => void;
}

const SEVERITY_STYLE: Record<FindingSeverity, string> = {
  critical: 'bg-red-100 text-red-800 border-red-200',
  high: 'bg-orange-100 text-orange-800 border-orange-200',
  medium: 'bg-amber-100 text-amber-800 border-amber-200',
  low: 'bg-slate-100 text-slate-700 border-slate-200',
};

const GRADE_COLOR: Record<PostureGrade, string> = {
  good: '#15803d',
  attention: '#b45309',
  critical: '#b91c1c',
  unknown: '#64748b',
};

const SECTION_LABEL: Record<ActiveSection, string> = {
  overview: 'Ver alertas',
  syslogs: 'Ver logs',
  rules: 'Revisar regras',
  nats: 'Revisar NATs',
  reports: 'Ver relatório',
  ai: 'Perguntar à IA',
  connect: 'Configurar',
};

const VISIBLE_DEFAULT = 4;

function ScoreRing({ score, grade }: { score: number; grade: PostureGrade }) {
  const radius = 42;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference * (1 - score / 100);
  const color = GRADE_COLOR[grade];
  return (
    <svg
      viewBox="0 0 100 100"
      className="w-28 h-28 shrink-0"
      role="img"
      aria-label={`Score de postura ${score} de 100`}
    >
      <circle cx="50" cy="50" r={radius} fill="none" stroke="var(--fw-border)" strokeWidth="9" />
      <circle
        cx="50"
        cy="50"
        r={radius}
        fill="none"
        stroke={color}
        strokeWidth="9"
        strokeLinecap="round"
        strokeDasharray={circumference}
        strokeDashoffset={offset}
        transform="rotate(-90 50 50)"
        style={{ transition: 'stroke-dashoffset 600ms ease' }}
      />
      <text x="50" y="52" textAnchor="middle" fontSize="26" fontWeight="700" fill={color}>
        {score}
      </text>
      <text x="50" y="68" textAnchor="middle" fontSize="9" fill="var(--fw-text-muted)">
        de 100
      </text>
    </svg>
  );
}

export function SecurityPosture({ vendor, overview, onNavigate }: SecurityPostureProps) {
  const siteId = overview.activeSite?.id ?? 'default';
  const posture = useMemo(() => computePosture(overview), [overview]);
  const [history, setHistory] = useState(() => loadPostureHistory(vendor, siteId));
  const [expanded, setExpanded] = useState(false);

  useEffect(() => {
    setHistory(recordPostureSnapshot(vendor, siteId, posture));
  }, [vendor, siteId, posture]);

  const trend = useMemo(() => postureDelta(history, posture.score), [history, posture.score]);

  if (posture.grade === 'unknown') return null;

  const shown = expanded ? posture.findings : posture.findings.slice(0, VISIBLE_DEFAULT);
  const hidden = posture.findings.length - shown.length;

  return (
    <section
      aria-label="Postura de segurança"
      className="bg-white border border-[var(--fw-border)] rounded-xl p-5 flex flex-col md:flex-row gap-5"
    >
      <div className="flex md:flex-col items-center md:items-start gap-4 md:w-44 shrink-0">
        <ScoreRing score={posture.score} grade={posture.grade} />
        <div>
          <p className="text-[11px] uppercase tracking-wide text-[var(--fw-text-muted)]">Postura</p>
          <p className="text-lg font-semibold" style={{ color: GRADE_COLOR[posture.grade] }}>
            {GRADE_LABEL[posture.grade]}
          </p>
          {trend && trend.delta !== 0 && (
            <p
              className={`mt-1 inline-flex items-center gap-1 text-xs font-medium ${
                trend.delta > 0 ? 'text-green-700' : 'text-red-700'
              }`}
              title={`Comparado a ${new Date(trend.since).toLocaleString('pt-BR')}`}
            >
              {trend.delta > 0 ? <TrendingUp className="w-3.5 h-3.5" /> : <TrendingDown className="w-3.5 h-3.5" />}
              {trend.delta > 0 ? '+' : ''}
              {trend.delta} pts na semana
            </p>
          )}
        </div>
      </div>

      <div className="flex-1 min-w-0">
        <div className="flex items-baseline justify-between gap-3 mb-2">
          <h2 className="text-sm font-semibold text-[var(--fw-heading)]">
            Achados priorizados
            <span className="ml-2 font-normal text-[var(--fw-text-muted)]">
              {posture.findings.length === 0
                ? 'nenhum problema encontrado'
                : `${posture.findings.length} para tratar`}
            </span>
          </h2>
        </div>

        {posture.findings.length === 0 ? (
          <p className="flex items-center gap-2 text-sm text-green-700">
            <CheckCircle2 className="w-4 h-4" /> Política limpa e sem alertas ativos. Continue monitorando.
          </p>
        ) : (
          <ul className="divide-y divide-[var(--fw-border-soft)]">
            {shown.map((f) => (
              <li key={f.id} className="py-2 flex items-start gap-3">
                <span
                  className={`mt-0.5 shrink-0 text-[10px] font-semibold uppercase tracking-wide border rounded px-1.5 py-0.5 ${SEVERITY_STYLE[f.severity]}`}
                >
                  {SEVERITY_LABEL[f.severity]}
                </span>
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-medium text-[var(--fw-text-body)]">{f.title}</p>
                  <p className="text-xs text-[var(--fw-text-muted)]">{f.detail}</p>
                </div>
                <button
                  type="button"
                  onClick={() => onNavigate(f.section)}
                  className="shrink-0 inline-flex items-center gap-1 text-xs font-medium text-[var(--fw-accent)] hover:text-[var(--fw-accent-hover)] hover:underline"
                >
                  {SECTION_LABEL[f.section]} <ArrowRight className="w-3 h-3" />
                </button>
              </li>
            ))}
          </ul>
        )}

        {posture.findings.length > VISIBLE_DEFAULT && (
          <button
            type="button"
            onClick={() => setExpanded((v) => !v)}
            className="mt-2 inline-flex items-center gap-1 text-xs font-medium text-[var(--fw-text-muted)] hover:text-[var(--fw-accent)]"
          >
            {expanded ? (
              <>
                <ChevronUp className="w-3.5 h-3.5" /> Mostrar menos
              </>
            ) : (
              <>
                <ChevronDown className="w-3.5 h-3.5" /> Mostrar mais {hidden}
              </>
            )}
          </button>
        )}
      </div>
    </section>
  );
}
