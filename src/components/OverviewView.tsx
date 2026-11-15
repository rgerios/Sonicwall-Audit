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
import type { ActiveSection, AuditOverview } from '../types.ts';
import { OverviewAlertCenter } from './OverviewAlertCenter.tsx';

interface OverviewViewProps {
  overview: AuditOverview | null;
  loading: boolean;
  onNavigate: (section: ActiveSection) => void;
  onLoadSample: () => void;
  onOverviewUpdated: (next: AuditOverview) => void;
  onInvestigateSyslog: (query: string) => void;
  onAnalyzeWithAi: (prompt: string) => void;
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
  'zone-traffic': { title: 'Fluxo entre Zonas' },
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

const LAYOUT_STORAGE_KEY = 'sonicaudit_overview_layout_v1';

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

function loadSavedLayout(): WidgetPreference[] {
  try {
    const raw = localStorage.getItem(LAYOUT_STORAGE_KEY);
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
  overview,
  loading,
  onNavigate,
  onLoadSample,
  onOverviewUpdated,
  onInvestigateSyslog,
  onAnalyzeWithAi,
}: OverviewViewProps) {
  const [layout, setLayout] = useState<WidgetPreference[]>(() => loadSavedLayout());
  const [draggingId, setDraggingId] = useState<WidgetId | null>(null);
  const [dragOverId, setDragOverId] = useState<WidgetId | null>(null);
  const [armedDragId, setArmedDragId] = useState<WidgetId | null>(null);
  const [showWidgetManager, setShowWidgetManager] = useState(false);

  useEffect(() => {
    try {
      localStorage.setItem(LAYOUT_STORAGE_KEY, JSON.stringify(layout));
    } catch {
      // Storage quota or restricted mode ignored
    }
  }, [layout]);

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
            <div key={i} className="h-28 bg-white border border-[#D4E4D8] rounded-lg" />
          ))}
        </div>
        <div className="h-72 bg-white border border-[#D4E4D8] rounded-lg" />
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
      <div className="bg-white border border-[#D4E4D8] rounded-lg p-10 max-w-3xl">
        <h2 className="text-xl font-semibold text-[#123325]">
          Nenhum dado SonicWall carregado ainda
        </h2>
        <p className="text-sm text-[#456354] mt-2 leading-relaxed max-w-2xl">
          Para iniciar a auditoria no seu ambiente Linux, conecte diretamente na API REST do
          SonicOS, inicie o receptor UDP Syslog para receber eventos do firewall em tempo real,
          ou importe um arquivo de log (<span className="font-mono text-[#123325]">.log</span>)
          e configuração (<span className="font-mono text-[#123325]">.exp</span> /{' '}
          <span className="font-mono text-[#123325]">.json</span>).
        </p>

        <div className="mt-6 flex flex-wrap items-center gap-3">
          <button
            type="button"
            onClick={() => onNavigate('connect')}
            className="inline-flex items-center gap-2 px-4 py-2.5 text-sm font-medium text-white bg-[#1E4D3B] rounded-md hover:bg-[#163A2C] transition-colors"
          >
            <ServerCog className="w-4 h-4" />
            Configurar Conexão ou Importar Arquivos
          </button>
          <button
            type="button"
            onClick={onLoadSample}
            className="inline-flex items-center gap-2 px-4 py-2.5 text-sm font-medium text-[#1D3B2E] bg-[#F4F8F5] border border-[#BFD5C5] rounded-md hover:bg-[#E7F2EA] transition-colors"
          >
            <Database className="w-4 h-4" />
            Carregar Amostra SonicWall TZ470
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
            <div className="bg-[#F4F8F5] border border-[#D4E4D8] rounded-md p-4">
              <p className="text-xs font-medium text-[#4B6B5C]">Syslogs Analisados</p>
              <p className="text-2xl font-semibold text-[#123325] font-mono tabular-nums mt-2">
                {overview.totalSyslogs.toLocaleString('pt-BR')}
              </p>
              <p className="text-xs text-[#4B6B5C] mt-2 tabular-nums">
                Retenção: {overview.retention?.retentionDays ?? 10} dias ·{' '}
                {overview.syslogBreakdown.allow.toLocaleString('pt-BR')} permitidos
              </p>
            </div>

            <div className="bg-[#F4F8F5] border border-[#D4E4D8] rounded-md p-4">
              <p className="text-xs font-medium text-[#4B6B5C]">Alertas Críticos e Drops</p>
              <p className="text-2xl font-semibold text-red-700 font-mono tabular-nums mt-2">
                {overview.syslogBreakdown.blocked.toLocaleString('pt-BR')}
              </p>
              <p className="text-xs text-[#4B6B5C] mt-2 tabular-nums">
                {overview.syslogBreakdown.criticalAndError} eventos severidade crítica/erro
              </p>
            </div>

            <button
              type="button"
              onClick={() => onNavigate('rules')}
              className="text-left bg-[#F4F8F5] border border-[#D4E4D8] rounded-md p-4 hover:border-[#9EC2AA] transition-colors"
            >
              <div className="flex items-center justify-between">
                <p className="text-xs font-medium text-[#4B6B5C]">Regras de Firewall Sem Uso</p>
                <ArrowRight className="w-3.5 h-3.5 text-[#7CA08A]" />
              </div>
              <p className="text-2xl font-semibold text-amber-800 font-mono tabular-nums mt-2">
                {problemRules.toLocaleString('pt-BR')}
                <span className="text-sm font-normal text-[#6D8B7B]">
                  {' '}
                  / {totalRules.toLocaleString('pt-BR')}
                </span>
              </p>
              <p className="text-xs text-[#4B6B5C] mt-2 tabular-nums">
                {overview.rulesSummary.unused} zero hits · {overview.rulesSummary.shadowed} sombreadas
              </p>
            </button>

            <button
              type="button"
              onClick={() => onNavigate('nats')}
              className="text-left bg-[#F4F8F5] border border-[#D4E4D8] rounded-md p-4 hover:border-[#9EC2AA] transition-colors"
            >
              <div className="flex items-center justify-between">
                <p className="text-xs font-medium text-[#4B6B5C]">Políticas NAT Sem Uso</p>
                <ArrowRight className="w-3.5 h-3.5 text-[#7CA08A]" />
              </div>
              <p className="text-2xl font-semibold text-amber-800 font-mono tabular-nums mt-2">
                {problemNats.toLocaleString('pt-BR')}
                <span className="text-sm font-normal text-[#6D8B7B]">
                  {' '}
                  / {totalNats.toLocaleString('pt-BR')}
                </span>
              </p>
              <p className="text-xs text-[#4B6B5C] mt-2 tabular-nums">
                {overview.natsSummary.unused} sem uso · {overview.natsSummary.orphaned} órfãs
              </p>
            </button>
          </div>
        );

      case 'appliance-health':
        return (
          <div className="space-y-5">
            <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
              <div className="bg-[#F4F8F5] border border-[#D4E4D8] rounded-md p-4">
                <div className="flex items-center justify-between text-xs text-[#4B6B5C]">
                  <span>Uptime & Disponibilidade</span>
                  <Clock className="w-3.5 h-3.5 text-[#1E4D3B]" />
                </div>
                <p className="text-xl font-semibold text-[#123325] font-mono tabular-nums mt-2">
                  {ap.uptimeFormatted || 'Via API REST'}
                </p>
                <p className="text-[11px] text-[#4B6B5C] mt-1.5 font-mono truncate">
                  {ap.haRole ? `HA: ${ap.haRole}` : `Host: ${ap.host}`} · S/N {ap.serialNumber}
                </p>
              </div>

              <div className="bg-[#F4F8F5] border border-[#D4E4D8] rounded-md p-4">
                <div className="flex items-center justify-between text-xs text-[#4B6B5C]">
                  <span>Versão SonicOS & ROM</span>
                  <ShieldCheck className="w-3.5 h-3.5 text-[#1E4D3B]" />
                </div>
                <p className="text-sm font-semibold text-[#123325] font-mono mt-2 truncate" title={ap.firmware}>
                  {ap.firmware}
                </p>
                <p className="text-[11px] text-[#4B6B5C] mt-2 font-mono tabular-nums truncate">
                  {ap.romVersion ? `ROM ${ap.romVersion}` : ap.model}
                  {ap.safemodeVersion ? ` · SafeMode ${ap.safemodeVersion}` : ''}
                </p>
              </div>

              <div className="bg-[#F4F8F5] border border-[#D4E4D8] rounded-md p-4">
                <div className="flex items-center justify-between text-xs text-[#4B6B5C]">
                  <span>CPU & Memória RAM</span>
                  <Cpu className="w-3.5 h-3.5 text-[#1E4D3B]" />
                </div>
                <div className="mt-2 space-y-2">
                  <div>
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-[#456354]">CPU</span>
                      <span className="font-mono tabular-nums font-semibold text-[#123325]">
                        {ap.cpuPercent !== undefined && ap.cpuPercent !== null ? `${ap.cpuPercent}%` : '—'}
                      </span>
                    </div>
                    <div className="h-1.5 w-full bg-[#DCE9E0] rounded-sm overflow-hidden mt-1">
                      <div
                        className="h-full bg-[#1E4D3B]"
                        style={{ width: `${ap.cpuPercent ?? 0}%` }}
                      />
                    </div>
                  </div>
                  <div>
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-[#456354]">RAM</span>
                      <span className="font-mono tabular-nums font-semibold text-[#123325]">
                        {ap.memoryPercent !== undefined && ap.memoryPercent !== null ? `${ap.memoryPercent}%` : '—'}
                      </span>
                    </div>
                    <div className="h-1.5 w-full bg-[#DCE9E0] rounded-sm overflow-hidden mt-1">
                      <div
                        className="h-full bg-[#4CA87A]"
                        style={{ width: `${ap.memoryPercent ?? 0}%` }}
                      />
                    </div>
                  </div>
                </div>
              </div>

              <div className="bg-[#F4F8F5] border border-[#D4E4D8] rounded-md p-4">
                <div className="flex items-center justify-between text-xs text-[#4B6B5C]">
                  <span>Conexões Simultâneas</span>
                  <Activity className="w-3.5 h-3.5 text-[#1E4D3B]" />
                </div>
                <p className="text-xl font-semibold text-[#123325] font-mono tabular-nums mt-2">
                  {ap.activeConnections !== undefined && ap.activeConnections !== null
                    ? ap.activeConnections.toLocaleString('pt-BR')
                    : '—'}
                  {ap.maxConnections ? (
                    <span className="text-xs font-normal text-[#5C7A6B]">
                      {' '}
                      / {ap.maxConnections.toLocaleString('pt-BR')}
                    </span>
                  ) : null}
                </p>
                {connPct !== null ? (
                  <div className="mt-2">
                    <div className="h-1.5 w-full bg-[#DCE9E0] rounded-sm overflow-hidden">
                      <div className="h-full bg-[#1E4D3B]" style={{ width: `${connPct}%` }} />
                    </div>
                    <p className="text-[11px] text-[#4B6B5C] mt-1 font-mono tabular-nums">
                      {connPct}% da tabela de sessões
                    </p>
                  </div>
                ) : (
                  <p className="text-[11px] text-[#4B6B5C] mt-2">
                    Sincronize via API REST para métricas em tempo real
                  </p>
                )}
              </div>
            </div>

            {telemetry.licenses.length > 0 && (
              <div className="border border-[#D4E4D8] rounded-md overflow-hidden">
                <div className="bg-[#EDF5EF] px-4 py-2 border-b border-[#D4E4D8] flex items-center justify-between text-xs">
                  <span className="font-medium text-[#244838] inline-flex items-center gap-1.5">
                    <HardDrive className="w-3.5 h-3.5" /> Licenças & Serviços de Segurança SonicGuard
                  </span>
                  <span className="text-[#4B6B5C] font-mono tabular-nums">
                    {telemetry.licenses.filter((l) => l.status === 'active').length}/
                    {telemetry.licenses.length} ativos
                  </span>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 divide-y sm:divide-y-0 sm:divide-x divide-[#E6F0E8] bg-white">
                  {telemetry.licenses.map((lic) => (
                    <div key={lic.service} className="p-3 text-xs">
                      <p className="font-medium text-[#123325] truncate" title={lic.service}>
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
                            <Ban className="w-3.5 h-3.5" /> {lic.status === 'expired' ? 'Expirada' : 'Inativa'}
                          </span>
                        )}
                        <span className="font-mono text-[11px] text-[#5C7A6B] tabular-nums">
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
          <div className="py-6 text-center text-xs text-[#4B6B5C]">
            Nenhum dado de interface ou VPN disponível ainda. Conecte diretamente via API REST do SonicOS
            (ou carregue a amostra TZ470) para acompanhar consumo de link Rx/Tx em Mbps e status de túneis.
          </div>
        ) : (
          <div className="space-y-6">
            {telemetry.interfaces.length > 0 && (
              <div className="grid grid-cols-1 xl:grid-cols-5 gap-6 items-start">
                <div className="xl:col-span-2 bg-[#F4F8F5] border border-[#D4E4D8] rounded-md p-4">
                  <div className="flex items-center justify-between mb-3">
                    <span className="text-xs font-medium text-[#123325] inline-flex items-center gap-1.5">
                      <Network className="w-3.5 h-3.5 text-[#1E4D3B]" /> Vazão Instantânea por Interface (Mbps)
                    </span>
                  </div>
                  <div className="h-56 w-full">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart
                        data={telemetry.interfaces}
                        margin={{ top: 6, right: 8, left: -16, bottom: 0 }}
                      >
                        <CartesianGrid strokeDasharray="3 3" stroke="#DCE9E0" vertical={false} />
                        <XAxis
                          dataKey="name"
                          tick={{ fontSize: 11, fill: '#4B6B5C' }}
                          axisLine={{ stroke: '#D4E4D8' }}
                          tickLine={false}
                        />
                        <YAxis
                          tick={{ fontSize: 11, fill: '#4B6B5C' }}
                          axisLine={false}
                          tickLine={false}
                        />
                        <Tooltip
                          contentStyle={{
                            backgroundColor: '#FFFFFF',
                            borderColor: '#BFD5C5',
                            borderRadius: '6px',
                            fontSize: '12px',
                            color: '#123325',
                          }}
                        />
                        <Legend wrapperStyle={{ fontSize: '11px', paddingTop: '6px' }} />
                        <Bar dataKey="rxMbps" name="Download (Rx Mbps)" fill="#1E4D3B" radius={[2, 2, 0, 0]} />
                        <Bar dataKey="txMbps" name="Upload (Tx Mbps)" fill="#4CA87A" radius={[2, 2, 0, 0]} />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                </div>

                <div className="xl:col-span-3 overflow-x-auto border border-[#D4E4D8] rounded-md">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="bg-[#EDF5EF] text-[#244838] border-b border-[#D4E4D8]">
                        <th className="py-2 px-3 text-left font-medium">Interface</th>
                        <th className="py-2 px-3 text-left font-medium">IP / Papel</th>
                        <th className="py-2 px-3 text-left font-medium">Link</th>
                        <th className="py-2 px-3 text-right font-medium">Rx / Tx (Mbps)</th>
                        <th className="py-2 px-3 text-right font-medium">Uso</th>
                        <th className="py-2 px-3 text-right font-medium">Tráfego Total</th>
                        <th className="py-2 px-3 text-right font-medium">Erros</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#E6F0E8]">
                      {telemetry.interfaces.map((iface) => (
                        <tr key={iface.name}>
                          <td className="py-2.5 px-3">
                            <p className="font-mono font-semibold text-[#123325]">{iface.name}</p>
                            <p className="text-[11px] text-[#5C7A6B]">Zona {iface.zone}</p>
                          </td>
                          <td className="py-2.5 px-3">
                            <p className="font-mono text-[#123325]">{iface.ip}</p>
                            <p className="text-[11px] text-[#5C7A6B]">
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
                          <td className="py-2.5 px-3 text-right font-mono tabular-nums text-[#123325]">
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
                                      isBreached ? 'text-red-700' : 'text-[#1E4D3B]'
                                    }`}
                                  >
                                    {iface.utilizationPercent.toFixed(1)}%
                                  </span>
                                  <div className="w-16 h-1.5 bg-[#E2EDE5] rounded-sm overflow-hidden mt-1">
                                    <div
                                      className={`h-full ${
                                        isBreached
                                          ? 'bg-red-600'
                                          : iface.utilizationPercent > Math.max(40, pctLimit - 15)
                                            ? 'bg-amber-600'
                                            : 'bg-[#1E4D3B]'
                                      }`}
                                      style={{ width: `${Math.min(100, iface.utilizationPercent)}%` }}
                                    />
                                  </div>
                                </div>
                              );
                            })()}
                          </td>
                          <td className="py-2.5 px-3 text-right font-mono tabular-nums text-[#456354]">
                            {formatTrafficBytes(iface.rxBytes + iface.txBytes)}
                          </td>
                          <td className="py-2.5 px-3 text-right font-mono tabular-nums">
                            <span
                              className={
                                iface.rxErrors + iface.txErrors > 0 ? 'text-amber-800 font-semibold' : 'text-[#5C7A6B]'
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
              <div className="border border-[#D4E4D8] rounded-md overflow-hidden">
                <div className="bg-[#EDF5EF] px-4 py-2 border-b border-[#D4E4D8] flex items-center justify-between text-xs">
                  <span className="font-medium text-[#244838] inline-flex items-center gap-1.5">
                    <Lock className="w-3.5 h-3.5" /> Túneis VPN Site-to-Site & SSL VPN
                  </span>
                  <span className="text-[#4B6B5C] font-mono tabular-nums">
                    {telemetry.vpns.filter((v) => v.status === 'up').length}/{telemetry.vpns.length} ativos
                  </span>
                </div>
                <div className="divide-y divide-[#E6F0E8] bg-white">
                  {telemetry.vpns.map((vpn) => (
                    <div
                      key={`${vpn.type}-${vpn.name}`}
                      className="px-4 py-2.5 flex flex-wrap items-center justify-between gap-3 text-xs"
                    >
                      <div className="min-w-0">
                        <p className="font-medium text-[#123325]">{vpn.name}</p>
                        <p className="text-[11px] font-mono text-[#5C7A6B]">
                          {vpn.type === 'ipsec' ? 'IPSec Site-to-Site' : 'SSL VPN'} · Peer: {vpn.peer}
                        </p>
                      </div>
                      <div className="flex items-center gap-4 shrink-0">
                        <span className="font-mono text-[11px] text-[#456354] tabular-nums">
                          Rx {formatTrafficBytes(vpn.rxBytes)} / Tx {formatTrafficBytes(vpn.txBytes)}
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
              <p className="text-xs text-[#4B6B5C] tabular-nums">
                Distribuição horária de eventos ingeridos · {total24h.toLocaleString('pt-BR')} log(s) nas últimas 24h
              </p>
              <button
                type="button"
                onClick={() => onNavigate('syslogs')}
                className="text-xs font-medium text-[#1E4D3B] hover:underline whitespace-nowrap"
              >
                Explorar syslogs
              </button>
            </div>
            <div className="h-72 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={hourlyData} margin={{ top: 8, right: 16, left: -12, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#E2EDE5" vertical={false} />
                  <XAxis
                    dataKey="hourLabel"
                    tick={{ fontSize: 11, fill: '#4B6B5C' }}
                    axisLine={{ stroke: '#D4E4D8' }}
                    tickLine={false}
                    interval={2}
                  />
                  <YAxis
                    allowDecimals={false}
                    tick={{ fontSize: 11, fill: '#4B6B5C' }}
                    axisLine={false}
                    tickLine={false}
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#FFFFFF',
                      borderColor: '#BFD5C5',
                      borderRadius: '6px',
                      fontSize: '12px',
                      color: '#123325',
                    }}
                    labelStyle={{ fontWeight: 600, color: '#123325', marginBottom: '4px' }}
                  />
                  <Legend wrapperStyle={{ fontSize: '12px', paddingTop: '8px' }} />
                  <Line
                    type="monotone"
                    dataKey="total"
                    name="Total Processado"
                    stroke="#1E4D3B"
                    strokeWidth={2.25}
                    dot={{ r: 2.5, fill: '#1E4D3B' }}
                    activeDot={{ r: 4.5 }}
                  />
                  <Line
                    type="monotone"
                    dataKey="allow"
                    name="Permitidos"
                    stroke="#4CA87A"
                    strokeWidth={2}
                    dot={false}
                    activeDot={{ r: 4 }}
                  />
                  <Line
                    type="monotone"
                    dataKey="blocked"
                    name="Bloqueados (Drop/Deny)"
                    stroke="#DC2626"
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
              <p className="text-xs text-[#4B6B5C]">
                Correlação cruzada entre contadores do SonicOS e tráfego observado nos syslogs
              </p>
              <button
                type="button"
                onClick={() => onNavigate('reports')}
                className="inline-flex items-center gap-1.5 text-xs font-medium text-[#1E4D3B] hover:underline whitespace-nowrap shrink-0"
              >
                <FileBarChart2 className="w-3.5 h-3.5" />
                Relatório Completo
              </button>
            </div>

            <div>
              <div className="flex items-center justify-between text-xs mb-2">
                <span className="font-medium text-[#1D3B2E]">Proporção de Tráfego nos Syslogs</span>
                <span className="font-mono text-[#4B6B5C] tabular-nums">
                  {allowPct}% Permitido · {blockedPct}% Bloqueado
                </span>
              </div>
              <div className="h-2.5 w-full bg-[#E8F1EB] rounded-sm overflow-hidden flex">
                <div
                  className="bg-[#3B8B66] h-full"
                  style={{ width: `${allowPct}%` }}
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
              <div className="p-4 bg-[#F4F8F5] rounded-md border border-[#D4E4D8] space-y-2">
                <p className="text-xs font-medium text-[#1D3B2E]">Regras de Acesso IPv4</p>
                <div className="space-y-1.5 text-xs">
                  <div className="flex items-center justify-between">
                    <span className="inline-flex items-center gap-1.5 text-emerald-800">
                      <CheckCircle2 className="w-3.5 h-3.5" /> Ativas com tráfego
                    </span>
                    <span className="font-mono tabular-nums text-[#123325]">
                      {overview.rulesSummary.active}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="inline-flex items-center gap-1.5 text-amber-800">
                      <AlertTriangle className="w-3.5 h-3.5" /> Sem uso (0 hits)
                    </span>
                    <span className="font-mono tabular-nums text-[#123325]">
                      {overview.rulesSummary.unused}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="inline-flex items-center gap-1.5 text-amber-800">
                      <ShieldAlert className="w-3.5 h-3.5" /> Sombreadas / Desabilitadas
                    </span>
                    <span className="font-mono tabular-nums text-[#123325]">
                      {overview.rulesSummary.shadowed + overview.rulesSummary.disabled}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="inline-flex items-center gap-1.5 text-red-700">
                      <Ban className="w-3.5 h-3.5" /> Permissivas (Any → Any)
                    </span>
                    <span className="font-mono tabular-nums text-[#123325]">
                      {overview.rulesSummary.overpermissive}
                    </span>
                  </div>
                </div>
              </div>

              <div className="p-4 bg-[#F4F8F5] rounded-md border border-[#D4E4D8] space-y-2">
                <p className="text-xs font-medium text-[#1D3B2E]">Políticas NAT IPv4</p>
                <div className="space-y-1.5 text-xs">
                  <div className="flex items-center justify-between">
                    <span className="inline-flex items-center gap-1.5 text-emerald-800">
                      <CheckCircle2 className="w-3.5 h-3.5" /> NATs ativos
                    </span>
                    <span className="font-mono tabular-nums text-[#123325]">
                      {overview.natsSummary.active}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="inline-flex items-center gap-1.5 text-amber-800">
                      <AlertTriangle className="w-3.5 h-3.5" /> NATs sem uso (0 hits)
                    </span>
                    <span className="font-mono tabular-nums text-[#123325]">
                      {overview.natsSummary.unused}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="inline-flex items-center gap-1.5 text-red-700">
                      <Ban className="w-3.5 h-3.5" /> Órfãs (sem regra de firewall)
                    </span>
                    <span className="font-mono tabular-nums text-[#123325]">
                      {overview.natsSummary.orphaned}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-[#456354]">Desabilitadas na tabela</span>
                    <span className="font-mono tabular-nums text-[#123325]">
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
          <p className="text-xs text-[#4B6B5C] py-8 text-center">
            Nenhum bloqueio registrado nos syslogs carregados.
          </p>
        ) : (
          <div className="divide-y divide-[#E6F0E8]">
            {overview.topBlockedSources.map((item) => (
              <div key={item.ip} className="py-2.5 flex items-center justify-between text-xs">
                <div>
                  <p className="font-mono text-[#123325] font-medium">{item.ip}</p>
                  <p className="text-[#4B6B5C]">Zona {item.zone}</p>
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
          <p className="text-xs text-[#4B6B5C] py-6 text-center">Sem portas registradas.</p>
        ) : (
          <table className="w-full text-xs">
            <thead>
              <tr className="text-[#4B6B5C] border-b border-[#E6F0E8]">
                <th className="py-2 text-left font-medium">Serviço / Porta</th>
                <th className="py-2 text-right font-medium">Total</th>
                <th className="py-2 text-right font-medium">Bloqueios</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#E6F0E8]">
              {overview.topTargetedPorts.map((row) => (
                <tr key={`${row.protocol}-${row.port}`}>
                  <td className="py-2.5 font-mono text-[#123325]">
                    {row.protocol}/{row.port}
                  </td>
                  <td className="py-2.5 text-right font-mono tabular-nums text-[#2C4B3D]">
                    {row.count.toLocaleString('pt-BR')}
                  </td>
                  <td className="py-2.5 text-right font-mono tabular-nums text-red-700">
                    {row.blocked.toLocaleString('pt-BR')}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        );

      case 'zone-traffic':
        return overview.zoneTraffic.length === 0 ? (
          <p className="text-xs text-[#4B6B5C] py-6 text-center">Sem fluxos de zona registrados.</p>
        ) : (
          <table className="w-full text-xs">
            <thead>
              <tr className="text-[#4B6B5C] border-b border-[#E6F0E8]">
                <th className="py-2 text-left font-medium">Origem → Destino</th>
                <th className="py-2 text-right font-medium">Permitidos</th>
                <th className="py-2 text-right font-medium">Bloqueados</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#E6F0E8]">
              {overview.zoneTraffic.map((z) => (
                <tr key={z.pair}>
                  <td className="py-2.5 font-mono text-[#123325]">{z.pair}</td>
                  <td className="py-2.5 text-right font-mono tabular-nums text-emerald-800">
                    {z.allow.toLocaleString('pt-BR')}
                  </td>
                  <td className="py-2.5 text-right font-mono tabular-nums text-red-700">
                    {z.blocked.toLocaleString('pt-BR')}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        );
    }
  };

  return (
    <div className="space-y-4">
      <OverviewAlertCenter
        overview={overview}
        onOverviewUpdated={onOverviewUpdated}
        onInvestigateSyslog={onInvestigateSyslog}
        onAnalyzeWithAi={onAnalyzeWithAi}
      />

      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="text-xs text-[#4B6B5C]">
          Arraste os painéis pelo ícone de grade para reorganizar ou alterne entre 1 e 2 colunas.
        </p>
        <div className="flex items-center gap-2">
          {isCustomLayout && (
            <button
              type="button"
              onClick={resetLayout}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-[#1D3B2E] bg-white border border-[#BFD5C5] rounded-md hover:bg-[#EDF5EF] whitespace-nowrap"
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
                ? 'bg-[#1E4D3B] text-white border-[#1E4D3B]'
                : 'bg-white text-[#1D3B2E] border-[#BFD5C5] hover:bg-[#EDF5EF]'
            }`}
          >
            <SlidersHorizontal className="w-3.5 h-3.5" />
            Gerenciar Widgets
          </button>
        </div>
      </div>

      {showWidgetManager && (
        <div className="bg-white border border-[#D4E4D8] rounded-lg p-4">
          <div className="flex items-center justify-between pb-3 border-b border-[#E6F0E8] mb-3">
            <span className="text-xs font-semibold text-[#123325]">
              Visibilidade e Largura dos Widgets
            </span>
            <button
              type="button"
              onClick={resetLayout}
              className="text-xs text-[#1E4D3B] hover:underline"
            >
              Resetar ordem e visibilidade
            </button>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5">
            {layout.map((widget) => (
              <div
                key={widget.id}
                className="flex items-center justify-between gap-2 px-3 py-2 bg-[#F4F8F5] border border-[#D4E4D8] rounded-md text-xs"
              >
                <span className="font-medium text-[#123325] truncate">
                  {WIDGET_META[widget.id].title}
                </span>
                <div className="flex items-center gap-1.5 shrink-0">
                  <button
                    type="button"
                    onClick={() => toggleSpan(widget.id)}
                    className="px-2 py-1 text-[11px] font-mono bg-white border border-[#BFD5C5] rounded text-[#2C4B3D] hover:bg-[#EDF5EF]"
                    title="Alternar largura (1 ou 2 colunas)"
                  >
                    {widget.span === 2 ? '2 col' : '1 col'}
                  </button>
                  <button
                    type="button"
                    onClick={() => toggleVisibility(widget.id)}
                    className={`p-1.5 rounded border transition-colors ${
                      widget.visible
                        ? 'bg-white border-[#BFD5C5] text-[#1E4D3B] hover:bg-[#EDF5EF]'
                        : 'bg-[#E5EFE8] border-[#BFD5C5] text-[#6D8B7B]'
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
              className={`bg-white rounded-lg border transition-colors ${
                widget.span === 2 ? 'lg:col-span-2' : 'lg:col-span-1'
              } ${
                isDropTarget
                  ? 'border-[#1E4D3B] ring-2 ring-[#2A6B52]/25 bg-[#F4F8F5]'
                  : 'border-[#D4E4D8]'
              } ${isDragging ? 'opacity-50' : 'opacity-100'}`}
            >
              <div className="px-5 py-3 border-b border-[#E6F0E8] flex items-center justify-between gap-3">
                <div className="flex items-center gap-2 min-w-0">
                  <button
                    type="button"
                    onMouseDown={() => setArmedDragId(widget.id)}
                    onMouseUp={() => setArmedDragId(null)}
                    aria-label={`Arrastar ${WIDGET_META[widget.id].title}`}
                    title="Arraste para reordenar"
                    className="p-1 -ml-1 text-[#6D8B7B] hover:text-[#123325] cursor-grab active:cursor-grabbing rounded focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#2A6B52]"
                  >
                    <GripVertical className="w-4 h-4" />
                  </button>
                  <h2 className="text-sm font-semibold text-[#123325] truncate">
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
                    className="p-1.5 text-[#5C7A6B] hover:text-[#123325] hover:bg-[#EDF5EF] rounded disabled:opacity-30"
                  >
                    <ArrowUp className="w-3.5 h-3.5" />
                  </button>
                  <button
                    type="button"
                    onClick={() => stepWidget(widget.id, 1)}
                    disabled={visibleIdx === visibleWidgets.length - 1}
                    title="Mover para baixo / direita"
                    aria-label={`Mover ${WIDGET_META[widget.id].title} para frente`}
                    className="p-1.5 text-[#5C7A6B] hover:text-[#123325] hover:bg-[#EDF5EF] rounded disabled:opacity-30"
                  >
                    <ArrowDown className="w-3.5 h-3.5" />
                  </button>
                  <button
                    type="button"
                    onClick={() => toggleSpan(widget.id)}
                    title={widget.span === 2 ? 'Reduzir para 1 coluna' : 'Expandir para 2 colunas'}
                    aria-label="Alternar largura do widget"
                    className="p-1.5 text-[#5C7A6B] hover:text-[#123325] hover:bg-[#EDF5EF] rounded hidden lg:inline-flex"
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
