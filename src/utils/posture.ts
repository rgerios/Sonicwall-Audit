import type { ActiveSection, AuditOverview, FirewallVendor } from '../types.ts';

export type FindingSeverity = 'critical' | 'high' | 'medium' | 'low';

export interface PostureFinding {
  id: string;
  severity: FindingSeverity;
  title: string;
  detail: string;
  /** Pontos descontados do score por este achado. */
  penalty: number;
  /** Tela onde o achado pode ser tratado. */
  section: ActiveSection;
  /** Quantidade de itens afetados, quando aplicável. */
  count?: number;
}

export type PostureGrade = 'good' | 'attention' | 'critical' | 'unknown';

export interface PostureResult {
  score: number;
  grade: PostureGrade;
  findings: PostureFinding[];
}

export const SEVERITY_ORDER: Record<FindingSeverity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

export const SEVERITY_LABEL: Record<FindingSeverity, string> = {
  critical: 'Crítico',
  high: 'Alto',
  medium: 'Médio',
  low: 'Baixo',
};

export const GRADE_LABEL: Record<PostureGrade, string> = {
  good: 'Boa',
  attention: 'Atenção',
  critical: 'Crítica',
  unknown: 'Sem dados',
};

const capped = (value: number, cap: number) => Math.min(value, cap);

function plural(n: number, one: string, many: string): string {
  return n === 1 ? one : many;
}

/**
 * Calcula a postura de segurança a partir do overview já carregado: nenhuma chamada extra
 * à API. Cada achado desconta pontos com teto próprio, então um único problema recorrente
 * não zera o score sozinho.
 */
export function computePosture(overview: AuditOverview | null): PostureResult {
  if (!overview) return { score: 0, grade: 'unknown', findings: [] };

  const hasPolicyData = overview.rulesSummary.total > 0 || overview.natsSummary.total > 0;
  const hasLogs = overview.totalSyslogs > 0;
  if (!hasPolicyData && !hasLogs) return { score: 0, grade: 'unknown', findings: [] };

  const findings: PostureFinding[] = [];
  const push = (f: PostureFinding) => {
    if (f.penalty > 0) findings.push(f);
  };

  const { rulesSummary: rules, natsSummary: nats } = overview;
  const alerts = overview.alerts ?? [];
  const criticalAlerts = alerts.filter((a) => a.severity === 'critical').length;
  const warningAlerts = alerts.filter((a) => a.severity === 'warning').length;

  if (criticalAlerts > 0) {
    push({
      id: 'alerts-critical',
      severity: 'critical',
      title: `${criticalAlerts} ${plural(criticalAlerts, 'alerta crítico ativo', 'alertas críticos ativos')}`,
      detail: 'Ameaças, licenças vencidas ou falhas graves aguardando tratamento na Visão Geral.',
      penalty: capped(criticalAlerts * 8, 40),
      section: 'overview',
      count: criticalAlerts,
    });
  }

  if (rules.overpermissive > 0) {
    push({
      id: 'rules-overpermissive',
      severity: 'high',
      title: `${rules.overpermissive} ${plural(rules.overpermissive, 'regra permissiva demais', 'regras permissivas demais')}`,
      detail: 'Regras com origem, destino ou serviço amplos (any) ampliam a superfície de ataque.',
      penalty: capped(rules.overpermissive * 6, 24),
      section: 'rules',
      count: rules.overpermissive,
    });
  }

  if (rules.shadowed > 0) {
    push({
      id: 'rules-shadowed',
      severity: 'medium',
      title: `${rules.shadowed} ${plural(rules.shadowed, 'regra sombreada', 'regras sombreadas')}`,
      detail: 'Nunca são avaliadas porque uma regra anterior já cobre o mesmo tráfego.',
      penalty: capped(rules.shadowed * 3, 12),
      section: 'rules',
      count: rules.shadowed,
    });
  }

  if (rules.unused > 0 && rules.total > 0) {
    const ratio = rules.unused / rules.total;
    push({
      id: 'rules-unused',
      severity: ratio >= 0.3 ? 'high' : 'medium',
      title: `${rules.unused} ${plural(rules.unused, 'regra sem uso', 'regras sem uso')} (${Math.round(ratio * 100)}% do total)`,
      detail: 'Sem hits no período observado. Candidatas a desabilitar e, depois, remover.',
      penalty: capped(Math.round(ratio * 20), 15),
      section: 'rules',
      count: rules.unused,
    });
  }

  if (rules.disabled > 0) {
    push({
      id: 'rules-disabled',
      severity: 'low',
      title: `${rules.disabled} ${plural(rules.disabled, 'regra desabilitada', 'regras desabilitadas')}`,
      detail: 'Regras desligadas que ainda poluem a política. Remova as que não voltarão a ser usadas.',
      penalty: capped(rules.disabled, 4),
      section: 'rules',
      count: rules.disabled,
    });
  }

  if (nats.orphaned > 0) {
    push({
      id: 'nats-orphaned',
      severity: 'medium',
      title: `${nats.orphaned} ${plural(nats.orphaned, 'NAT órfão', 'NATs órfãos')}`,
      detail: 'Referenciam objetos ou interfaces que não existem mais.',
      penalty: capped(nats.orphaned * 3, 9),
      section: 'nats',
      count: nats.orphaned,
    });
  }
  if (nats.unused > 0) {
    push({
      id: 'nats-unused',
      severity: 'low',
      title: `${nats.unused} ${plural(nats.unused, 'NAT sem uso', 'NATs sem uso')}`,
      detail: 'Sem tráfego traduzido no período observado.',
      penalty: capped(nats.unused * 1, 5),
      section: 'nats',
      count: nats.unused,
    });
  }

  if (warningAlerts > 0) {
    push({
      id: 'alerts-warning',
      severity: 'low',
      title: `${warningAlerts} ${plural(warningAlerts, 'aviso ativo', 'avisos ativos')}`,
      detail: 'Anomalias de volume, falhas de coleta ou suspeitas que merecem revisão.',
      penalty: capped(warningAlerts * 2, 8),
      section: 'overview',
      count: warningAlerts,
    });
  }

  // Cobertura: sem logs recentes a auditoria enxerga só a configuração, não o comportamento.
  if (!overview.udpStatus?.running && !hasLogs) {
    push({
      id: 'coverage-no-syslog',
      severity: 'medium',
      title: 'Sem coleta de syslog',
      detail: 'Receptor UDP parado e nenhum log importado: regras e NATs sem uso não podem ser comprovados.',
      penalty: 8,
      section: 'connect',
    });
  } else if (overview.udpStatus?.running && !overview.udpStatus.lastPacketAt && !hasLogs) {
    push({
      id: 'coverage-silent',
      severity: 'low',
      title: 'Receptor ativo, mas nenhum pacote recebido',
      detail: `Aponte o firewall para a porta ${overview.udpStatus.port}/UDP deste servidor.`,
      penalty: 4,
      section: 'connect',
    });
  }

  if (overview.sync?.lastError && overview.sync.consecutiveFailures >= 3) {
    push({
      id: 'sync-failing',
      severity: 'medium',
      title: 'Sincronização automática falhando',
      detail: `${overview.sync.consecutiveFailures} falhas seguidas: ${overview.sync.lastError}`,
      penalty: 5,
      section: 'connect',
    });
  }

  findings.sort(
    (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || b.penalty - a.penalty
  );
  const score = Math.max(0, 100 - findings.reduce((sum, f) => sum + f.penalty, 0));
  const grade: PostureGrade = score >= 85 ? 'good' : score >= 65 ? 'attention' : 'critical';
  return { score, grade, findings };
}

export interface PostureSnapshot {
  at: number;
  score: number;
  findings: number;
}

const HISTORY_LIMIT = 40;
const MIN_GAP_MS = 60 * 60 * 1000;
const COMPARE_WINDOW_MS = 7 * 24 * 60 * 60 * 1000;

function storageKey(vendor: FirewallVendor, siteId: string): string {
  return `fwaudit:posture:${vendor}:${siteId}`;
}

export function loadPostureHistory(vendor: FirewallVendor, siteId: string): PostureSnapshot[] {
  try {
    const raw = localStorage.getItem(storageKey(vendor, siteId));
    const parsed = raw ? (JSON.parse(raw) as unknown) : [];
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(
      (s): s is PostureSnapshot =>
        s && typeof s.at === 'number' && typeof s.score === 'number' && typeof s.findings === 'number'
    );
  } catch {
    return [];
  }
}

/** Registra um ponto no histórico (no máximo um por hora) e devolve o histórico atualizado. */
export function recordPostureSnapshot(
  vendor: FirewallVendor,
  siteId: string,
  result: PostureResult,
  now = Date.now()
): PostureSnapshot[] {
  const history = loadPostureHistory(vendor, siteId);
  if (result.grade === 'unknown') return history;
  const last = history[history.length - 1];
  if (last && now - last.at < MIN_GAP_MS) return history;
  const next = [...history, { at: now, score: result.score, findings: result.findings.length }].slice(
    -HISTORY_LIMIT
  );
  try {
    localStorage.setItem(storageKey(vendor, siteId), JSON.stringify(next));
  } catch {
    // armazenamento indisponível: a tendência simplesmente não aparece
  }
  return next;
}

/** Diferença de score contra o ponto mais antigo da última semana (com pelo menos 1h de idade). */
export function postureDelta(
  history: PostureSnapshot[],
  currentScore: number,
  now = Date.now()
): { delta: number; since: number } | null {
  const candidates = history.filter((s) => now - s.at >= MIN_GAP_MS && now - s.at <= COMPARE_WINDOW_MS);
  if (candidates.length === 0) return null;
  const base = candidates[0];
  return { delta: currentScore - base.score, since: base.at };
}
