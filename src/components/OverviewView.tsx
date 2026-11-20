import { useEffect, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  ArrowDown,
  ArrowRight,
  ArrowUp,
  Ban,
  CheckCircle2,
  Clock,
  Cpu,
  Database,
  Eye,
  EyeOff,
  FileBarChart2,
  GripVertical,
  HardDrive,
  Lock,
  Maximize2,
  Minimize2,
  Network,
  RotateCcw,
  ServerCog,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
} from 'lucide-react';
import {
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import type { ActiveSection, AuditOverview, FirewallVendor } from '../types.ts';
import { VENDOR_THEMES } from '../utils/vendorTheme.ts';
import { OverviewAlertCenter } from './OverviewAlertCenter.tsx';
import { ResourceHistoryCard } from './ResourceHistoryCard.tsx';
import { SecurityPosture } from './SecurityPosture.tsx';

interface OverviewViewProps {
  vendor: FirewallVendor;
  overview: AuditOverview | null;
  loading: boolean;
  onNavigate: (section: ActiveSection) => void;
  onLoadSample: () => void;
  onOverviewUpdated: (next: AuditOverview) => void;
  onInvestigateSyslog: (query: string) => void;
  onAnalyzeWithAi: (prompt: string) => void;
  openAlertConfigSignal?: number;
}

type WidgetId =
  | 'kpi-summary'
  | 'appliance-health'
  | 'link-consumption'
  | 'traffic-24h'
  | 'policy-hygiene'
  | 'top-blocked'
  | 'top-ports'
  | 'zone-traffic';

interface WidgetPreference {
  id: WidgetId;
  span: 1 | 2;
  visible: boolean;
}

const WIDGET_META: Record<WidgetId, { title: string }> = {
  'kpi-summary': { title: 'Indicadores Gerais' },
  'appliance-health': { title: 'Saúde do Appliance, Uptime & Licenças' },
  'link-consumption': { title: 'Consumo de Links & Túneis VPN' },
  'traffic-24h': { title: 'Volume de Syslogs (24h)' },
  'policy-hygiene': { title: 'Higiene das Políticas' },
  'top-blocked': { title: 'Origens Bloqueadas' },
  'top-ports': { title: 'Portas Mais Visadas' },
  'zone-traffic': { title: 'Fluxo entre Zonas / Interfaces' },
};

const DEFAULT_LAYOUT: WidgetPreference[] = [
  { id: 'kpi-summary', span: 2, visible: true },
  { id: 'appliance-health', span: 2, visible: true },
  { id: 'link-consumption', span: 2, visible: true },
  { id: 'traffic-24h', span: 2, visible: true },
  { id: 'policy-hygiene', span: 1, visible: true },
  { id: 'top-blocked', span: 1, visible: true },
  { id: 'top-ports', span: 1, visible: true },
  { id: 'zone-traffic', span: 1, visible: true },
];

function getLayoutStorageKey(vendor: FirewallVendor): string {
  return `fwaudit_overview_layout_v1_${vendor}`;
}

function formatTrafficBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let val = bytes;
  let idx = 0;
  while (val >= 1024 && idx < units.length - 1) {
    val /= 1024;
    idx += 1;
  }
  return `${val.toFixed(idx >= 3 ? 2 : 1)} ${units[idx]}`;
}

function loadSavedLayout(vendor: FirewallVendor): WidgetPreference[] {
  try {
    const raw = localStorage.getItem(getLayoutStorageKey(vendor));
    if (!raw) return DEFAULT_LAYOUT;
    const parsed = JSON.parse(raw) as unknown;
    if (!Array.isArray(parsed)) return DEFAULT_LAYOUT;

    const validIds = new Set<WidgetId>(DEFAULT_LAYOUT.map((w) => w.id));
    const seen = new Set<WidgetId>();
    const restored: WidgetPreference[] = [];

    for (const item of parsed) {
      if (
        item &&
        typeof item === 'object' &&
        'id' in item &&
        validIds.has((item as WidgetPreference).id) &&
        !seen.has((item as WidgetPreference).id)
      ) {
        const w = item as WidgetPreference;
        seen.add(w.id);
        restored.push({
          id: w.id,
          span: w.span === 2 ? 2 : 1,
          visible: w.visible !== false,
        });
      }
    }

    for (const def of DEFAULT_LAYOUT) {
      if (!seen.has(def.id)) {
        restored.push(def);
      }
    }
    return restored.length === DEFAULT_LAYOUT.length ? restored : DEFAULT_LAYOUT;
  } catch {
    return DEFAULT_LAYOUT;
  }
}

export function OverviewView({
  vendor,
  overview,
  loading,
  onNavigate,
  onLoadSample,
  onOverviewUpdated,
  onInvestigateSyslog,
  onAnalyzeWithAi,
  openAlertConfigSignal = 0,
}: OverviewViewProps) {
  const theme = VENDOR_THEMES[vendor];
  const [layout, setLayout] = useState<WidgetPreference[]>(() => loadSavedLayout(vendor));
  const [draggingId, setDraggingId] = useState<WidgetId | null>(null);
  const [dragOverId, setDragOverId] = useState<WidgetId | null>(null);
  const [armedDragId, setArmedDragId] = useState<WidgetId | null>(null);
  const [showWidgetManager, setShowWidgetManager] = useState(false);

  useEffect(() => {
    setLayout(loadSavedLayout(vendor));
    setShowWidgetManager(false);
  }, [vendor]);

  useEffect(() => {
    try {
      localStorage.setItem(getLayoutStorageKey(vendor), JSON.stringify(layout));
    } catch {
      // Storage quota or restricted mode ignored
    }
  }, [layout, vendor]);

  const moveWidget = (sourceId: WidgetId, targetId: WidgetId) => {
    if (sourceId === targetId) return;
    setLayout((prev) => {
      const fromIndex = prev.findIndex((w) => w.id === sourceId);
      const toIndex = prev.findIndex((w) => w.id === targetId);
      if (fromIndex < 0 || toIndex < 0) return prev;
      const next = [...prev];
      const [moved] = next.splice(fromIndex, 1);
      next.splice(toIndex, 0, moved);
      return next;
    });
  };

  const stepWidget = (id: WidgetId, direction: -1 | 1) => {
    setLayout((prev) => {
      const visibleIds = prev.filter((w) => w.visible).map((w) => w.id);
      const visIdx = visibleIds.indexOf(id);
      const swapVisIdx = visIdx + direction;
      if (visIdx < 0 || swapVisIdx < 0 || swapVisIdx >= visibleIds.length) return prev;

      const targetId = visibleIds[swapVisIdx];
      const idxA = prev.findIndex((w) => w.id === id);
      const idxB = prev.findIndex((w) => w.id === targetId);
      const next = [...prev];
      const temp = next[idxA];
      next[idxA] = next[idxB];
      next[idxB] = temp;
      return next;
    });
  };

  const toggleSpan = (id: WidgetId) => {
    setLayout((prev) =>
      prev.map((w) => (w.id === id ? { ...w, span: w.span === 2 ? 1 : 2 } : w))
    );
  };

  const toggleVisibility = (id: WidgetId) => {
    setLayout((prev) => {
      const visibleCount = prev.filter((w) => w.visible).length;
      const target = prev.find((w) => w.id === id);
      if (target?.visible && visibleCount <= 1) return prev;
      return prev.map((w) => (w.id === id ? { ...w, visible: !w.visible } : w));
    });
  };

  const resetLayout = () => {
    setLayout(DEFAULT_LAYOUT);
    setShowWidgetManager(false);
  };

  if (loading && !overview) {
    return (
      <div className="space-y-6 animate-pulse">
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
          {[1, 2, 3, 4].map((i) => (
            <div key={i} className="h-28 bg-white border border-[var(--fw-border)] rounded-lg" />
          ))}
        </div>
        <div className="h-72 bg-white border border-[var(--fw-border)] rounded-lg" />
      </div>
    );
  }

  const hasData =
    overview &&
    (overview.totalSyslogs > 0 ||
      overview.rulesSummary.total > 0 ||
      overview.natsSummary.total > 0 ||
      (overview.telemetry?.interfaces?.length ?? 0) > 0);

  if (!hasData) {
    return (
      <div className="bg-white border border-[var(--fw-border)] rounded-lg p-10 max-w-3xl">
        <h2 className="text-xl font-semibold text-[var(--fw-heading)]">
          Nenhum dado {theme.label} carregado ainda
        </h2>
        <p className="text-sm text-[var(--fw-text-muted)] mt-2 leading-relaxed max-w-2xl">
          {vendor === 'fortigate' ? (
            <>
              Para iniciar a auditoria FortiGate, conecte diretamente na API REST do FortiOS usando
              um token Bearer, inicie o receptor Syslog UDP na porta{' '}
              <span className="font-mono text-[var(--fw-heading)]">5515</span> para eventos em
              tempo real, ou importe arquivos de syslog (<span className="font-mono">.log</span>).
            </>
          ) : (
            <>
              Para iniciar a auditoria no seu ambiente Linux, conecte diretamente na API REST do
              SonicOS, inicie o receptor UDP Syslog na porta{' '}
              <span className="font-mono text-[var(--fw-heading)]">5514</span> para receber
              eventos do firewall em tempo real, ou importe um arquivo de log (
              <span className="font-mono text-[var(--fw-heading)]">.log</span>) e configuração (
              <span className="font-mono text-[var(--fw-heading)]">.exp</span> /{' '}
              <span className="font-mono text-[var(--fw-heading)]">.json</span>).
            </>
          )}
        </p>

        <ol className="mt-6 grid grid-cols-1 md:grid-cols-3 gap-3 max-w-3xl list-none p-0" aria-label="Primeiros passos">
          {[
            {
              title: 'Conecte o firewall',
              done: Boolean(overview?.activeSite?.connection?.host),
              text:
                vendor === 'fortigate'
                  ? 'Informe host, porta e token da API REST do FortiOS (ou importe a configuração).'
                  : 'Informe host, usuário e senha da API SonicOS (ou importe o .exp / .json).',
            },
            {
              title: 'Envie os syslogs',
              done: Boolean(overview?.udpStatus?.lastPacketAt),
              text: `Aponte o firewall para este servidor na porta ${vendor === 'fortigate' ? '5515' : '5514'}/UDP. É isso que comprova regras e NATs sem uso.`,
            },
            {
              title: 'Revise os achados',
              done: false,
              text: 'Com dados carregados, a Visão Geral mostra a postura de segurança e o que tratar primeiro.',
            },
          ].map((step, index) => (
            <li
              key={step.title}
              className={`rounded-lg border p-3 text-xs ${
                step.done
                  ? 'border-emerald-300 bg-emerald-50'
                  : 'border-[var(--fw-border)] bg-[var(--fw-surface-soft)]'
              }`}
            >
              <p className="font-semibold text-[var(--fw-heading)] flex items-center gap-2">
                <span
                  className={`inline-flex items-center justify-center w-5 h-5 rounded-full text-[11px] ${
                    step.done ? 'bg-emerald-600 text-white' : 'bg-[var(--fw-accent)] text-white'
                  }`}
                  aria-hidden="true"
                >
                  {step.done ? '✓' : index + 1}
                </span>
                {step.title}
                {step.done && <span className="sr-only"> (concluído)</span>}
              </p>
              <p className="mt-1.5 text-[var(--fw-text-muted)] leading-snug">{step.text}</p>
            </li>
          ))}
        </ol>

        <div className="mt-6 flex flex-wrap items-center gap-3">
          <button
            type="button"
            onClick={() => onNavigate('connect')}
            className="inline-flex items-center gap-2 px-4 py-2.5 text-sm font-medium text-white bg-[var(--fw-accent)] rounded-md hover:bg-[var(--fw-accent-hover)] transition-colors"
          >
            <ServerCog className="w-4 h-4" />
            Configurar Conexão ou Importar Arquivos
          </button>
          <button
            type="button"
            onClick={onLoadSample}
            className="inline-flex items-center gap-2 px-4 py-2.5 text-sm font-medium text-[var(--fw-text-body)] bg-[var(--fw-bg)] border border-[var(--fw-border-strong)] rounded-md hover:bg-[var(--fw-surface)] transition-colors"
          >
            <Database className="w-4 h-4" />
            {theme.sampleButtonLabel}
          </button>
        </div>
      </div>
    );
  }

  const totalRules = overview.rulesSummary.total;
  const problemRules =
    overview.rulesSummary.unused +
    overview.rulesSummary.shadowed +
    overview.rulesSummary.disabled;

  const totalNats = overview.natsSummary.total;
  const problemNats =
    overview.natsSummary.unused +
    overview.natsSummary.orphaned +
    overview.natsSummary.disabled;

  const allowPct =
    overview.totalSyslogs > 0
      ? Math.round((overview.syslogBreakdown.allow / overview.totalSyslogs) * 100)
      : 0;
  const blockedPct =
    overview.totalSyslogs > 0
      ? Math.round((overview.syslogBreakdown.blocked / overview.totalSyslogs) * 100)
      : 0;

  const hourlyData = overview.hourlyLogVolume ?? [];
  const total24h = hourlyData.reduce((acc, point) => acc + point.total, 0);

  const ap = overview.appliance;
  const telemetry = overview.telemetry ?? { interfaces: [], vpns: [], licenses: [] };
  const connPct =
    ap.activeConnections !== undefined &&
    ap.activeConnections !== null &&
    ap.maxConnections &&
    ap.maxConnections > 0
      ? Math.min(100, Math.round((ap.activeConnections / ap.maxConnections) * 100))
      : null;

  const visibleWidgets = layout.filter((w) => w.visible);
  const isCustomLayout = JSON.stringify(layout) !== JSON.stringify(DEFAULT_LAYOUT);

  const renderWidgetBody = (id: WidgetId) => {
    switch (id) {
      case 'kpi-summary':
        return (
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
            <div className="bg-[var(--fw-bg)] border border-[var(--fw-border)] rounded-md p-4">
              <p className="text-xs font-medium text-[var(--fw-text-muted)]">Syslogs Analisados</p>
              <p className="text-2xl font-semibold text-[var(--fw-heading)] font-mono tabular-nums mt-2">
                {overview.totalSyslogs.toLocaleString('pt-BR')}
              </p>
              <p className="text-xs text-[var(--fw-text-muted)] mt-2 tabular-nums">
                Retenção: {overview.retention?.retentionDays ?? 10} dias ·{' '}
                {overview.syslogBreakdown.allow.toLocaleString('pt-BR')} permitidos
              </p>
            </div>

            <div className="bg-[var(--fw-bg)] border border-[var(--fw-border)] rounded-md p-4">
              <p className="text-xs font-medium text-[var(--fw-text-muted)]">
                Alertas Críticos e Drops
              </p>
              <p className="text-2xl font-semibold text-red-700 font-mono tabular-nums mt-2">
                {overview.syslogBreakdown.blocked.toLocaleString('pt-BR')}
              </p>
              <p className="text-xs text-[var(--fw-text-muted)] mt-2 tabular-nums">
                {overview.syslogBreakdown.criticalAndError} eventos severidade crítica/erro
              </p>
            </div>

            <button
              type="button"
              onClick={() => onNavigate('rules')}
              className="text-left bg-[var(--fw-bg)] border border-[var(--fw-border)] rounded-md p-4 hover:border-[var(--fw-border-strong)] transition-colors"
            >
              <div className="flex items-center justify-between">
                <p className="text-xs font-medium text-[var(--fw-text-muted)]">
                  Regras de Firewall Sem Uso
                </p>
                <ArrowRight className="w-3.5 h-3.5 text-[var(--fw-text-subtle)]" />
              </div>
              <p className="text-2xl font-semibold text-amber-800 font-mono tabular-nums mt-2">
                {problemRules.toLocaleString('pt-BR')}
                <span className="text-sm font-normal text-[var(--fw-text-subtle)]">
                  {' '}
                  / {totalRules.toLocaleString('pt-BR')}
                </span>
              </p>
              <p className="text-xs text-[var(--fw-text-muted)] mt-2 tabular-nums">
                {overview.rulesSummary.unused} zero hits · {overview.rulesSummary.shadowed} sombreadas
              </p>
            </button>

            <button
              type="button"
              onClick={() => onNavigate('nats')}
              className="text-left bg-[var(--fw-bg)] border border-[var(--fw-border)] rounded-md p-4 hover:border-[var(--fw-border-strong)] transition-colors"
            >
              <div className="flex items-center justify-between">
                <p className="text-xs font-medium text-[var(--fw-text-muted)]">
                  {vendor === 'fortigate' ? 'VIPs & NATs Sem Uso' : 'Políticas NAT Sem Uso'}
                </p>
                <ArrowRight className="w-3.5 h-3.5 text-[var(--fw-text-subtle)]" />
              </div>
              <p className="text-2xl font-semibold text-amber-800 font-mono tabular-nums mt-2">
                {problemNats.toLocaleString('pt-BR')}
                <span className="text-sm font-normal text-[var(--fw-text-subtle)]">
                  {' '}
                  / {totalNats.toLocaleString('pt-BR')}
                </span>
              </p>
              <p className="text-xs text-[var(--fw-text-muted)] mt-2 tabular-nums">
                {overview.natsSummary.unused} sem uso · {overview.natsSummary.orphaned} órfãs
              </p>
            </button>
          </div>
        );

      case 'appliance-health':
        return (
          <div className="space-y-5">
            <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
              <div className="bg-[var(--fw-bg)] border border-[var(--fw-border)] rounded-md p-4">
                <div className="flex items-center justify-between text-xs text-[var(--fw-text-muted)]">
                  <span>Uptime &amp; Disponibilidade</span>
                  <Clock className="w-3.5 h-3.5 text-[var(--fw-accent)]" />
                </div>
                <p className="text-xl font-semibold text-[var(--fw-heading)] font-mono tabular-nums mt-2">
                  {ap.uptimeFormatted || 'Via API REST'}
                </p>
                <p className="text-[11px] text-[var(--fw-text-muted)] mt-1.5 font-mono truncate">
                  {ap.haRole ? `HA: ${ap.haRole}` : `Host: ${ap.host}`} · S/N {ap.serialNumber}
                </p>
              </div>

              <div className="bg-[var(--fw-bg)] border border-[var(--fw-border)] rounded-md p-4">
                <div className="flex items-center justify-between text-xs text-[var(--fw-text-muted)]">
                  <span>
                    {vendor === 'fortigate' ? 'Versão FortiOS & Modelo' : 'Versão SonicOS & ROM'}
                  </span>
                  <ShieldCheck className="w-3.5 h-3.5 text-[var(--fw-accent)]" />
                </div>
                <p
                  className="text-sm font-semibold text-[var(--fw-heading)] font-mono mt-2 truncate"
                  title={ap.firmware}
                >
                  {ap.firmware}
                </p>
                <p className="text-[11px] text-[var(--fw-text-muted)] mt-2 font-mono tabular-nums truncate">
                  {ap.romVersion ? `ROM ${ap.romVersion}` : ap.model}
                  {ap.safemodeVersion ? ` · SafeMode ${ap.safemodeVersion}` : ''}
                </p>
              </div>

              <div className="bg-[var(--fw-bg)] border border-[var(--fw-border)] rounded-md p-4">
                <div className="flex items-center justify-between text-xs text-[var(--fw-text-muted)]">
                  <span>CPU &amp; Memória RAM</span>
                  <Cpu className="w-3.5 h-3.5 text-[var(--fw-accent)]" />
                </div>
                <div className="mt-2 space-y-2">
                  <div>
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-[var(--fw-text-muted)]">CPU</span>
                      <span className="font-mono tabular-nums font-semibold text-[var(--fw-heading)]">
                        {ap.cpuPercent !== undefined && ap.cpuPercent !== null
                          ? `${ap.cpuPercent}%`
                          : '—'}
                      </span>
                    </div>
                    <div className="h-1.5 w-full bg-[var(--fw-surface-alt)] rounded-sm overflow-hidden mt-1">
                      <div
                        className="h-full bg-[var(--fw-accent)]"
                        style={{ width: `${ap.cpuPercent ?? 0}%` }}
                      />
                    </div>
                  </div>
                  <div>
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-[var(--fw-text-muted)]">RAM</span>
                      <span className="font-mono tabular-nums font-semibold text-[var(--fw-heading)]">
                        {ap.memoryPercent !== undefined && ap.memoryPercent !== null
                          ? `${ap.memoryPercent}%`
                          : '—'}
                      </span>
                    </div>
                    <div className="h-1.5 w-full bg-[var(--fw-surface-alt)] rounded-sm overflow-hidden mt-1">
                      <div
                        className="h-full bg-[var(--fw-accent-mid)]"
                        style={{ width: `${ap.memoryPercent ?? 0}%` }}
                      />
                    </div>
                  </div>
                </div>
              </div>

              <div className="bg-[var(--fw-bg)] border border-[var(--fw-border)] rounded-md p-4">
                <div className="flex items-center justify-between text-xs text-[var(--fw-text-muted)]">
                  <span>Conexões Simultâneas</span>
                  <Activity className="w-3.5 h-3.5 text-[var(--fw-accent)]" />
                </div>
                <p className="text-xl font-semibold text-[var(--fw-heading)] font-mono tabular-nums mt-2">
                  {ap.activeConnections !== undefined && ap.activeConnections !== null
                    ? ap.activeConnections.toLocaleString('pt-BR')
                    : '—'}
                  {ap.maxConnections ? (
                    <span className="text-xs font-normal text-[var(--fw-text-subtle)]">
                      {' '}
                      / {ap.maxConnections.toLocaleString('pt-BR')}
                    </span>
                  ) : null}
                </p>
                {connPct !== null ? (
                  <div className="mt-2">
                    <div className="h-1.5 w-full bg-[var(--fw-surface-alt)] rounded-sm overflow-hidden">
                      <div
                        className="h-full bg-[var(--fw-accent)]"
                        style={{ width: `${connPct}%` }}
                      />
                    </div>
                    <p className="text-[11px] text-[var(--fw-text-muted)] mt-1 font-mono tabular-nums">
                      {connPct}% da tabela de sessões
                    </p>
                  </div>
                ) : (
                  <p className="text-[11px] text-[var(--fw-text-muted)] mt-2">
                    Sincronize via API REST para métricas em tempo real
                  </p>
                )}
              </div>
            </div>

            {telemetry.licenses.length > 0 && (
              <div className="border border-[var(--fw-border)] rounded-md overflow-hidden">
                <div className="bg-[var(--fw-surface)] px-4 py-2 border-b border-[var(--fw-border)] flex items-center justify-between text-xs">
                  <span className="font-medium text-[var(--fw-text-body)] inline-flex items-center gap-1.5">
                    <HardDrive className="w-3.5 h-3.5" />
                    {vendor === 'fortigate'
                      ? 'Licenças & Serviços de Segurança FortiGuard'
                      : 'Licenças & Serviços de Segurança SonicGuard'}
                  </span>
                  <span className="text-[var(--fw-text-muted)] font-mono tabular-nums">
                    {telemetry.licenses.filter((l) => l.status === 'active').length}/
                    {telemetry.licenses.length} ativos
                  </span>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 divide-y sm:divide-y-0 sm:divide-x divide-[var(--fw-border-soft)] bg-white">
                  {telemetry.licenses.map((lic) => (
                    <div key={lic.service} className="p-3 text-xs">
                      <p
                        className="font-medium text-[var(--fw-heading)] truncate"
                        title={lic.service}
                      >
                        {lic.service}
                      </p>
                      <div className="mt-1.5 flex items-center justify-between gap-2">
                        {lic.status === 'active' ? (
                          <span className="inline-flex items-center gap-1 text-emerald-800 font-medium">
                            <CheckCircle2 className="w-3.5 h-3.5" /> Ativa
                          </span>
                        ) : lic.status === 'expiring' ? (
                          <span className="inline-flex items-center gap-1 text-amber-800 font-medium">
                            <AlertTriangle className="w-3.5 h-3.5" /> Expirando
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 text-red-700 font-medium">
                            <Ban className="w-3.5 h-3.5" />{' '}
                            {lic.status === 'expired' ? 'Expirada' : 'Inativa'}
                          </span>
                        )}
                        <span className="font-mono text-[11px] text-[var(--fw-text-subtle)] tabular-nums">
                          {lic.expiresAt || '—'}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        );

      case 'link-consumption':
        return telemetry.interfaces.length === 0 && telemetry.vpns.length === 0 ? (
          <div className="py-6 text-center text-xs text-[var(--fw-text-muted)]">
            Nenhum dado de interface ou VPN disponível ainda. Conecte diretamente via API REST{' '}
            {vendor === 'fortigate' ? 'FortiOS' : 'SonicOS'} (ou carregue a amostra de demonstração)
            para acompanhar consumo de link Rx/Tx em Mbps e status de túneis.
          </div>
        ) : (
          <div className="space-y-6">
            {telemetry.interfaces.length > 0 && (
              <div className="grid grid-cols-1 xl:grid-cols-5 gap-6 items-start">
                <div className="xl:col-span-2 bg-[var(--fw-bg)] border border-[var(--fw-border)] rounded-md p-4">
                  <div className="flex items-center justify-between mb-3">
                    <span className="text-xs font-medium text-[var(--fw-heading)] inline-flex items-center gap-1.5">
                      <Network className="w-3.5 h-3.5 text-[var(--fw-accent)]" /> Vazão Instantânea
                      por Interface (Mbps)
                    </span>
                  </div>
                  <div className="h-56 w-full">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart
                        data={telemetry.interfaces}
                        margin={{ top: 6, right: 8, left: -16, bottom: 0 }}
                      >
                        <CartesianGrid
                          strokeDasharray="3 3"
                          stroke={theme.chartGrid}
                          vertical={false}
                        />
                        <XAxis
                          dataKey="name"
                          tick={{ fontSize: 11, fill: theme.chartAxis }}
                          axisLine={{ stroke: theme.chartGrid }}
                          tickLine={false}
                        />
                        <YAxis
                          tick={{ fontSize: 11, fill: theme.chartAxis }}
                          axisLine={false}
                          tickLine={false}
                        />
                        <Tooltip
                          contentStyle={{
                            backgroundColor: '#FFFFFF',
                            borderColor: theme.chartGrid,
                            borderRadius: '6px',
                            fontSize: '12px',
                          }}
                        />
                        <Legend wrapperStyle={{ fontSize: '11px', paddingTop: '6px' }} />
                        <Bar
                          dataKey="rxMbps"
                          name="Download (Rx Mbps)"
                          fill={theme.chartPrimary}
                          radius={[2, 2, 0, 0]}
                        />
                        <Bar
                          dataKey="txMbps"
                          name="Upload (Tx Mbps)"
                          fill={theme.chartAllow}
                          radius={[2, 2, 0, 0]}
                        />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                </div>

                <div className="xl:col-span-3 overflow-x-auto border border-[var(--fw-border)] rounded-md">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="bg-[var(--fw-surface)] text-[var(--fw-text-body)] border-b border-[var(--fw-border)]">
                        <th className="py-2 px-3 text-left font-medium">Interface</th>
                        <th className="py-2 px-3 text-left font-medium">IP / Papel</th>
                        <th className="py-2 px-3 text-left font-medium">Link</th>
                        <th className="py-2 px-3 text-right font-medium">Rx / Tx (Mbps)</th>
                        <th className="py-2 px-3 text-right font-medium">Uso</th>
                        <th className="py-2 px-3 text-right font-medium">Tráfego Total</th>
                        <th className="py-2 px-3 text-right font-medium">Erros</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[var(--fw-border-soft)]">
                      {telemetry.interfaces.map((iface) => (
                        <tr key={iface.name}>
                          <td className="py-2.5 px-3">
                            <p className="font-mono font-semibold text-[var(--fw-heading)]">
                              {iface.name}
                            </p>
                            <p className="text-[11px] text-[var(--fw-text-subtle)]">
                              Zona {iface.zone}
                            </p>
                          </td>
                          <td className="py-2.5 px-3">
                            <p className="font-mono text-[var(--fw-heading)]">{iface.ip}</p>
                            <p className="text-[11px] text-[var(--fw-text-subtle)]">
                              {iface.role === 'wan-primary'
                                ? 'WAN Principal'
                                : iface.role === 'wan-failover'
                                  ? 'WAN Failover'
                                  : 'Rede Interna'}
                            </p>
                          </td>
                          <td className="py-2.5 px-3 font-mono tabular-nums">
                            {iface.linkStatus === 'up' ? (
                              <span className="text-emerald-800 font-medium">
                                UP · {iface.linkSpeedMbps}M
                              </span>
                            ) : (
                              <span className="text-red-700 font-medium">DOWN</span>
                            )}
                          </td>
                          <td className="py-2.5 px-3 text-right font-mono tabular-nums text-[var(--fw-heading)]">
                            {iface.rxMbps.toFixed(1)} / {iface.txMbps.toFixed(1)}
                          </td>
                          <td className="py-2.5 px-3 text-right">
                            {(() => {
                              const pctLimit =
                                overview.alertSettings?.bandwidthUtilizationLimitPercent ?? 80;
                              const isBreached = iface.utilizationPercent >= pctLimit;
                              return (
                                <div className="inline-flex flex-col items-end">
                                  <span
                                    className={`font-mono tabular-nums font-semibold ${
                                      isBreached ? 'text-red-700' : 'text-[var(--fw-accent)]'
                                    }`}
                                  >
                                    {iface.utilizationPercent.toFixed(1)}%
                                  </span>
                                  <div className="w-16 h-1.5 bg-[var(--fw-surface-alt)] rounded-sm overflow-hidden mt-1">
                                    <div
                                      className={`h-full ${
                                        isBreached
                                          ? 'bg-red-600'
                                          : iface.utilizationPercent > Math.max(40, pctLimit - 15)
                                            ? 'bg-amber-600'
                                            : 'bg-[var(--fw-accent)]'
                                      }`}
                                      style={{
                                        width: `${Math.min(100, iface.utilizationPercent)}%`,
                                      }}
                                    />
                                  </div>
                                </div>
                              );
                            })()}
                          </td>
                          <td className="py-2.5 px-3 text-right font-mono tabular-nums text-[var(--fw-text-muted)]">
                            {formatTrafficBytes(iface.rxBytes + iface.txBytes)}
                          </td>
                          <td className="py-2.5 px-3 text-right font-mono tabular-nums">
                            <span
                              className={
                                iface.rxErrors + iface.txErrors > 0
                                  ? 'text-amber-800 font-semibold'
                                  : 'text-[var(--fw-text-subtle)]'
                              }
                            >
                              {iface.rxErrors + iface.txErrors}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {telemetry.vpns.length > 0 && (
              <div className="border border-[var(--fw-border)] rounded-md overflow-hidden">
                <div className="bg-[var(--fw-surface)] px-4 py-2 border-b border-[var(--fw-border)] flex items-center justify-between text-xs">
                  <span className="font-medium text-[var(--fw-text-body)] inline-flex items-center gap-1.5">
                    <Lock className="w-3.5 h-3.5" /> Túneis VPN Site-to-Site &amp; SSL VPN
                  </span>
                  <span className="text-[var(--fw-text-muted)] font-mono tabular-nums">
                    {telemetry.vpns.filter((v) => v.status === 'up').length}/{telemetry.vpns.length}{' '}
                    ativos
                  </span>
                </div>
                <div className="divide-y divide-[var(--fw-border-soft)] bg-white">
                  {telemetry.vpns.map((vpn) => (
                    <div
                      key={`${vpn.type}-${vpn.name}`}
                      className="px-4 py-2.5 flex flex-wrap items-center justify-between gap-3 text-xs"
                    >
                      <div className="min-w-0">
                        <p className="font-medium text-[var(--fw-heading)]">{vpn.name}</p>
                        <p className="text-[11px] font-mono text-[var(--fw-text-subtle)]">
                          {vpn.type === 'ipsec' ? 'IPSec Site-to-Site' : 'SSL VPN'} · Peer:{' '}
                          {vpn.peer}
                        </p>
                      </div>
                      <div className="flex items-center gap-4 shrink-0">
                        <span className="font-mono text-[11px] text-[var(--fw-text-muted)] tabular-nums">
                          Rx {formatTrafficBytes(vpn.rxBytes)} / Tx{' '}
                          {formatTrafficBytes(vpn.txBytes)}
                        </span>
                        {vpn.status === 'up' ? (
                          <span className="inline-flex items-center gap-1 text-emerald-800 font-semibold font-mono">
                            <CheckCircle2 className="w-3.5 h-3.5" /> UP
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 text-red-700 font-semibold font-mono">
                            <Ban className="w-3.5 h-3.5" /> DOWN
                          </span>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        );

      case 'traffic-24h':
        return (
          <div>
            <div className="flex flex-wrap items-center justify-between gap-3 mb-4">
              <p className="text-xs text-[var(--fw-text-muted)] tabular-nums">
                Distribuição horária de eventos ingeridos · {total24h.toLocaleString('pt-BR')} log(s)
                nas últimas 24h
              </p>
              <button
                type="button"
                onClick={() => onNavigate('syslogs')}
                className="text-xs font-medium text-[var(--fw-accent)] hover:underline whitespace-nowrap"
              >
                Explorar syslogs
              </button>
            </div>
            <div className="h-72 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={hourlyData} margin={{ top: 8, right: 16, left: -12, bottom: 0 }}>
                  <CartesianGrid
                    strokeDasharray="3 3"
                    stroke={theme.chartGrid}
                    vertical={false}
                  />
                  <XAxis
                    dataKey="hourLabel"
                    tick={{ fontSize: 11, fill: theme.chartAxis }}
                    axisLine={{ stroke: theme.chartGrid }}
                    tickLine={false}
                    interval={2}
                  />
                  <YAxis
                    allowDecimals={false}
                    tick={{ fontSize: 11, fill: theme.chartAxis }}
                    axisLine={false}
                    tickLine={false}
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#FFFFFF',
                      borderColor: theme.chartGrid,
                      borderRadius: '6px',
                      fontSize: '12px',
                    }}
                    labelStyle={{ fontWeight: 600, marginBottom: '4px' }}
                  />
                  <Legend wrapperStyle={{ fontSize: '12px', paddingTop: '8px' }} />
                  <Line
                    type="monotone"
                    dataKey="total"
                    name="Total Processado"
                    stroke={theme.chartPrimary}
                    strokeWidth={2.25}
                    dot={{ r: 2.5, fill: theme.chartPrimary }}
                    activeDot={{ r: 4.5 }}
                  />
                  <Line
                    type="monotone"
                    dataKey="allow"
                    name="Permitidos"
                    stroke={theme.chartAllow}
                    strokeWidth={2}
                    dot={false}
                    activeDot={{ r: 4 }}
                  />
                  <Line
                    type="monotone"
                    dataKey="blocked"
                    name="Bloqueados (Drop/Deny)"
                    stroke={theme.chartBlocked}
                    strokeWidth={1.75}
                    strokeDasharray="4 3"
                    dot={false}
                    activeDot={{ r: 4 }}
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </div>
        );

      case 'policy-hygiene':
        return (
          <div className="space-y-5">
            <div className="flex items-center justify-between gap-4">
              <p className="text-xs text-[var(--fw-text-muted)]">
                Correlação cruzada entre contadores do{' '}
                {vendor === 'fortigate' ? 'FortiOS' : 'SonicOS'} e tráfego observado nos syslogs
              </p>
              <button
                type="button"
                onClick={() => onNavigate('reports')}
                className="inline-flex items-center gap-1.5 text-xs font-medium text-[var(--fw-accent)] hover:underline whitespace-nowrap shrink-0"
              >
                <FileBarChart2 className="w-3.5 h-3.5" />
                Relatório Completo
              </button>
            </div>

            <div>
              <div className="flex items-center justify-between text-xs mb-2">
                <span className="font-medium text-[var(--fw-text-body)]">
                  Proporção de Tráfego nos Syslogs
                </span>
                <span className="font-mono text-[var(--fw-text-muted)] tabular-nums">
                  {allowPct}% Permitido · {blockedPct}% Bloqueado
                </span>
              </div>
              <div className="h-2.5 w-full bg-[var(--fw-surface-alt)] rounded-sm overflow-hidden flex">
                <div
                  className="h-full"
                  style={{ width: `${allowPct}%`, backgroundColor: theme.chartAllow }}
                  title={`Permitido: ${allowPct}%`}
                />
                <div
                  className="bg-red-600 h-full"
                  style={{ width: `${blockedPct}%` }}
                  title={`Bloqueado: ${blockedPct}%`}
                />
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="p-4 bg-[var(--fw-bg)] rounded-md border border-[var(--fw-border)] space-y-2">
                <p className="text-xs font-medium text-[var(--fw-text-body)]">
                  Regras de Acesso IPv4
                </p>
                <div className="space-y-1.5 text-xs">
                  <div className="flex items-center justify-between">
                    <span className="inline-flex items-center gap-1.5 text-emerald-800">
                      <CheckCircle2 className="w-3.5 h-3.5" /> Ativas com tráfego
                    </span>
                    <span className="font-mono tabular-nums text-[var(--fw-heading)]">
                      {overview.rulesSummary.active}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="inline-flex items-center gap-1.5 text-amber-800">
                      <AlertTriangle className="w-3.5 h-3.5" /> Sem uso (0 hits)
                    </span>
                    <span className="font-mono tabular-nums text-[var(--fw-heading)]">
                      {overview.rulesSummary.unused}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="inline-flex items-center gap-1.5 text-amber-800">
                      <ShieldAlert className="w-3.5 h-3.5" /> Sombreadas / Desabilitadas
                    </span>
                    <span className="font-mono tabular-nums text-[var(--fw-heading)]">
                      {overview.rulesSummary.shadowed + overview.rulesSummary.disabled}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="inline-flex items-center gap-1.5 text-red-700">
                      <Ban className="w-3.5 h-3.5" /> Permissivas (Any → Any)
                    </span>
                    <span className="font-mono tabular-nums text-[var(--fw-heading)]">
                      {overview.rulesSummary.overpermissive}
                    </span>
                  </div>
                </div>
              </div>

              <div className="p-4 bg-[var(--fw-bg)] rounded-md border border-[var(--fw-border)] space-y-2">
                <p className="text-xs font-medium text-[var(--fw-text-body)]">
                  {vendor === 'fortigate' ? 'VIPs, IP Pools & NAT' : 'Políticas NAT IPv4'}
                </p>
                <div className="space-y-1.5 text-xs">
                  <div className="flex items-center justify-between">
                    <span className="inline-flex items-center gap-1.5 text-emerald-800">
                      <CheckCircle2 className="w-3.5 h-3.5" /> Traduções ativas
                    </span>
                    <span className="font-mono tabular-nums text-[var(--fw-heading)]">
                      {overview.natsSummary.active}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="inline-flex items-center gap-1.5 text-amber-800">
                      <AlertTriangle className="w-3.5 h-3.5" /> Sem uso (0 hits)
                    </span>
                    <span className="font-mono tabular-nums text-[var(--fw-heading)]">
                      {overview.natsSummary.unused}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="inline-flex items-center gap-1.5 text-red-700">
                      <Ban className="w-3.5 h-3.5" /> Órfãs (sem regra associada)
                    </span>
                    <span className="font-mono tabular-nums text-[var(--fw-heading)]">
                      {overview.natsSummary.orphaned}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-[var(--fw-text-muted)]">Desabilitadas na tabela</span>
                    <span className="font-mono tabular-nums text-[var(--fw-heading)]">
                      {overview.natsSummary.disabled}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        );

      case 'top-blocked':
        return overview.topBlockedSources.length === 0 ? (
          <p className="text-xs text-[var(--fw-text-muted)] py-8 text-center">
            Nenhum bloqueio registrado nos syslogs carregados.
          </p>
        ) : (
          <div className="divide-y divide-[var(--fw-border-soft)]">
            {overview.topBlockedSources.map((item) => (
              <div key={item.ip} className="py-2.5 flex items-center justify-between text-xs">
                <div>
                  <p className="font-mono text-[var(--fw-heading)] font-medium">{item.ip}</p>
                  <p className="text-[var(--fw-text-muted)]">Zona {item.zone}</p>
                </div>
                <span className="font-mono tabular-nums text-red-700 font-medium">
                  {item.count.toLocaleString('pt-BR')} drops
                </span>
              </div>
            ))}
          </div>
        );

      case 'top-ports':
        return overview.topTargetedPorts.length === 0 ? (
          <p className="text-xs text-[var(--fw-text-muted)] py-6 text-center">
            Sem portas registradas.
          </p>
        ) : (
          <div className="overflow-x-auto"><table className="w-full text-xs">
            <thead>
              <tr className="text-[var(--fw-text-muted)] border-b border-[var(--fw-border-soft)]">
                <th className="py-2 text-left font-medium">Serviço / Porta</th>
                <th className="py-2 text-right font-medium">Total</th>
                <th className="py-2 text-right font-medium">Bloqueios</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--fw-border-soft)]">
              {overview.topTargetedPorts.map((row) => (
                <tr key={`${row.protocol}-${row.port}`}>
                  <td className="py-2.5 font-mono text-[var(--fw-heading)]">
                    {row.protocol}/{row.port}
                  </td>
                  <td className="py-2.5 text-right font-mono tabular-nums text-[var(--fw-text-body)]">
                    {row.count.toLocaleString('pt-BR')}
                  </td>
                  <td className="py-2.5 text-right font-mono tabular-nums text-red-700">
                    {row.blocked.toLocaleString('pt-BR')}
                  </td>
                </tr>
              ))}
            </tbody>
          </table></div>
        );

      case 'zone-traffic':
        return overview.zoneTraffic.length === 0 ? (
          <p className="text-xs text-[var(--fw-text-muted)] py-6 text-center">
            Sem fluxos de zona registrados.
          </p>
        ) : (
          <div className="overflow-x-auto"><table className="w-full text-xs">
            <thead>
              <tr className="text-[var(--fw-text-muted)] border-b border-[var(--fw-border-soft)]">
                <th className="py-2 text-left font-medium">Origem → Destino</th>
                <th className="py-2 text-right font-medium">Permitidos</th>
                <th className="py-2 text-right font-medium">Bloqueados</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--fw-border-soft)]">
              {overview.zoneTraffic.map((z) => (
                <tr key={z.pair}>
                  <td className="py-2.5 font-mono text-[var(--fw-heading)]">{z.pair}</td>
                  <td className="py-2.5 text-right font-mono tabular-nums text-emerald-800">
                    {z.allow.toLocaleString('pt-BR')}
                  </td>
                  <td className="py-2.5 text-right font-mono tabular-nums text-red-700">
                    {z.blocked.toLocaleString('pt-BR')}
                  </td>
                </tr>
              ))}
            </tbody>
          </table></div>
        );
    }
  };

  return (
    <div className="space-y-4">
      <SecurityPosture vendor={vendor} overview={overview} onNavigate={onNavigate} />

      <OverviewAlertCenter
        vendor={vendor}
        overview={overview}
        onOverviewUpdated={onOverviewUpdated}
        onInvestigateSyslog={onInvestigateSyslog}
        onAnalyzeWithAi={onAnalyzeWithAi}
        openConfigSignal={openAlertConfigSignal}
      />

      <ResourceHistoryCard vendor={vendor} overview={overview} />

      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="text-xs text-[var(--fw-text-muted)]">
          Arraste os painéis pelo ícone de grade para reorganizar ou alterne entre 1 e 2 colunas.
        </p>
        <div className="flex items-center gap-2">
          {isCustomLayout && (
            <button
              type="button"
              onClick={resetLayout}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-[var(--fw-text-body)] bg-white border border-[var(--fw-border-strong)] rounded-md hover:bg-[var(--fw-surface)] whitespace-nowrap"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              Restaurar Padrão
            </button>
          )}
          <button
            type="button"
            onClick={() => setShowWidgetManager((v) => !v)}
            className={`inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md border whitespace-nowrap transition-colors ${
              showWidgetManager
                ? 'bg-[var(--fw-accent)] text-white border-[var(--fw-accent)]'
                : 'bg-white text-[var(--fw-text-body)] border-[var(--fw-border-strong)] hover:bg-[var(--fw-surface)]'
            }`}
          >
            <SlidersHorizontal className="w-3.5 h-3.5" />
            Gerenciar Widgets
          </button>
        </div>
      </div>

      {showWidgetManager && (
        <div className="bg-white border border-[var(--fw-border)] rounded-lg p-4">
          <div className="flex items-center justify-between pb-3 border-b border-[var(--fw-border-soft)] mb-3">
            <span className="text-xs font-semibold text-[var(--fw-heading)]">
              Visibilidade e Largura dos Widgets ({theme.label})
            </span>
            <button
              type="button"
              onClick={resetLayout}
              className="text-xs text-[var(--fw-accent)] hover:underline"
            >
              Resetar ordem e visibilidade
            </button>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5">
            {layout.map((widget) => (
              <div
                key={widget.id}
                className="flex items-center justify-between gap-2 px-3 py-2 bg-[var(--fw-bg)] border border-[var(--fw-border)] rounded-md text-xs"
              >
                <span className="font-medium text-[var(--fw-heading)] truncate">
                  {WIDGET_META[widget.id].title}
                </span>
                <div className="flex items-center gap-1.5 shrink-0">
                  <button
                    type="button"
                    onClick={() => toggleSpan(widget.id)}
                    className="px-2 py-1 text-[11px] font-mono bg-white border border-[var(--fw-border-strong)] rounded text-[var(--fw-text-body)] hover:bg-[var(--fw-surface)]"
                    title="Alternar largura (1 ou 2 colunas)"
                  >
                    {widget.span === 2 ? '2 col' : '1 col'}
                  </button>
                  <button
                    type="button"
                    onClick={() => toggleVisibility(widget.id)}
                    className={`p-1.5 rounded border transition-colors ${
                      widget.visible
                        ? 'bg-white border-[var(--fw-border-strong)] text-[var(--fw-accent)] hover:bg-[var(--fw-surface)]'
                        : 'bg-[var(--fw-surface-alt)] border-[var(--fw-border-strong)] text-[var(--fw-text-subtle)]'
                    }`}
                    title={widget.visible ? 'Ocultar widget' : 'Exibir widget'}
                    aria-label={widget.visible ? 'Ocultar widget' : 'Exibir widget'}
                  >
                    {widget.visible ? (
                      <Eye className="w-3.5 h-3.5" />
                    ) : (
                      <EyeOff className="w-3.5 h-3.5" />
                    )}
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {visibleWidgets.map((widget, visibleIdx) => {
          const isDragging = draggingId === widget.id;
          const isDropTarget = dragOverId === widget.id && draggingId !== widget.id;

          return (
            <section
              key={widget.id}
              draggable={armedDragId === widget.id}
              onDragStart={(e) => {
                setDraggingId(widget.id);
                e.dataTransfer.effectAllowed = 'move';
                e.dataTransfer.setData('text/plain', widget.id);
              }}
              onDragOver={(e) => {
                e.preventDefault();
                e.dataTransfer.dropEffect = 'move';
                if (dragOverId !== widget.id) {
                  setDragOverId(widget.id);
                }
              }}
              onDragLeave={() => {
                if (dragOverId === widget.id) {
                  setDragOverId(null);
                }
              }}
              onDrop={(e) => {
                e.preventDefault();
                const sourceId = (e.dataTransfer.getData('text/plain') as WidgetId) || draggingId;
                if (sourceId && sourceId !== widget.id) {
                  moveWidget(sourceId, widget.id);
                }
                setDraggingId(null);
                setDragOverId(null);
                setArmedDragId(null);
              }}
              onDragEnd={() => {
                setDraggingId(null);
                setDragOverId(null);
                setArmedDragId(null);
              }}
              className={`fx bg-white rounded-lg border transition-colors ${
                widget.span === 2 ? 'lg:col-span-2' : 'lg:col-span-1'
              } ${
                isDropTarget
                  ? 'border-[var(--fw-accent)] ring-2 ring-[var(--fw-accent-mid)]/25 bg-[var(--fw-bg)]'
                  : 'border-[var(--fw-border)]'
              } ${isDragging ? 'opacity-50' : 'opacity-100'}`}
            >
              <div className="px-5 py-3 border-b border-[var(--fw-border-soft)] flex items-center justify-between gap-3">
                <div className="flex items-center gap-2 min-w-0">
                  <button
                    type="button"
                    onMouseDown={() => setArmedDragId(widget.id)}
                    onMouseUp={() => setArmedDragId(null)}
                    aria-label={`Arrastar ${WIDGET_META[widget.id].title}`}
                    title="Arraste para reordenar"
                    className="p-1 -ml-1 text-[var(--fw-text-subtle)] hover:text-[var(--fw-heading)] cursor-grab active:cursor-grabbing rounded focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--fw-accent-mid)]"
                  >
                    <GripVertical className="w-4 h-4" />
                  </button>
                  <h2 className="text-sm font-semibold text-[var(--fw-heading)] truncate">
                    {WIDGET_META[widget.id].title}
                  </h2>
                </div>

                <div className="flex items-center gap-1 shrink-0">
                  <button
                    type="button"
                    onClick={() => stepWidget(widget.id, -1)}
                    disabled={visibleIdx === 0}
                    title="Mover para cima / esquerda"
                    aria-label={`Mover ${WIDGET_META[widget.id].title} para trás`}
                    className="p-1.5 text-[var(--fw-text-subtle)] hover:text-[var(--fw-heading)] hover:bg-[var(--fw-surface)] rounded disabled:opacity-30"
                  >
                    <ArrowUp className="w-3.5 h-3.5" />
                  </button>
                  <button
                    type="button"
                    onClick={() => stepWidget(widget.id, 1)}
                    disabled={visibleIdx === visibleWidgets.length - 1}
                    title="Mover para baixo / direita"
                    aria-label={`Mover ${WIDGET_META[widget.id].title} para frente`}
                    className="p-1.5 text-[var(--fw-text-subtle)] hover:text-[var(--fw-heading)] hover:bg-[var(--fw-surface)] rounded disabled:opacity-30"
                  >
                    <ArrowDown className="w-3.5 h-3.5" />
                  </button>
                  <button
                    type="button"
                    onClick={() => toggleSpan(widget.id)}
                    title={widget.span === 2 ? 'Reduzir para 1 coluna' : 'Expandir para 2 colunas'}
                    aria-label="Alternar largura do widget"
                    className="p-1.5 text-[var(--fw-text-subtle)] hover:text-[var(--fw-heading)] hover:bg-[var(--fw-surface)] rounded hidden lg:inline-flex"
                  >
                    {widget.span === 2 ? (
                      <Minimize2 className="w-3.5 h-3.5" />
                    ) : (
                      <Maximize2 className="w-3.5 h-3.5" />
                    )}
                  </button>
                </div>
              </div>

              <div className="p-5">{renderWidgetBody(widget.id)}</div>
            </section>
          );
        })}
      </div>
    </div>
  );
}
