import {
  Activity,
  ArrowLeftRight,
  Bot,
  Building2,
  FileBarChart2,
  FileTerminal,
  KeyRound,
  LogOut,
  Plus,
  ServerCog,
  ShieldAlert,
  Terminal,
} from 'lucide-react';
import type { ActiveSection, AuditOverview } from '../types.ts';

interface SidebarProps {
  activeSection: ActiveSection;
  onSelectSection: (section: ActiveSection) => void;
  overview: AuditOverview | null;
  authUsername: string | null;
  onSelectSite: (siteId: string) => void;
  onOpenPasswordModal: () => void;
  onLogout: () => void;
}

export function Sidebar({
  activeSection,
  onSelectSection,
  overview,
  authUsername,
  onSelectSite,
  onOpenPasswordModal,
  onLogout,
}: SidebarProps) {
  const unusedRulesCount =
    (overview?.rulesSummary.unused ?? 0) +
    (overview?.rulesSummary.shadowed ?? 0) +
    (overview?.rulesSummary.disabled ?? 0);

  const unusedNatsCount =
    (overview?.natsSummary.unused ?? 0) +
    (overview?.natsSummary.orphaned ?? 0) +
    (overview?.natsSummary.disabled ?? 0);

  const activeAlertsCount = overview?.alerts?.length ?? 0;

  const navItems: Array<{
    id: ActiveSection;
    label: string;
    icon: typeof Activity;
    count?: number;
  }> = [
    {
      id: 'overview',
      label: 'Visão Geral',
      icon: Activity,
      count: activeAlertsCount || undefined,
    },
    {
      id: 'syslogs',
      label: 'Syslogs',
      icon: FileTerminal,
      count: overview?.totalSyslogs || undefined,
    },
    {
      id: 'rules',
      label: 'Regras Sem Uso',
      icon: ShieldAlert,
      count: unusedRulesCount || undefined,
    },
    {
      id: 'nats',
      label: 'NATs Sem Uso',
      icon: ArrowLeftRight,
      count: unusedNatsCount || undefined,
    },
    { id: 'reports', label: 'Relatórios', icon: FileBarChart2 },
    { id: 'ai', label: 'Análise com IA', icon: Bot },
    { id: 'connect', label: 'Localidades & Linux', icon: ServerCog },
  ];

  const udpRunning = overview?.udpStatus.running ?? false;
  const retentionDays = overview?.retention?.retentionDays ?? 10;
  const sites = overview?.sites ?? [];
  const activeSite = overview?.activeSite;

  return (
    <aside className="w-64 shrink-0 border-r border-[#D4E4D8] bg-[#EDF5EF] flex flex-col justify-between min-h-screen">
      <div>
        <div className="px-5 h-16 flex items-center gap-2.5 border-b border-[#D4E4D8]">
          <Terminal className="w-5 h-5 text-[#1E4D3B] shrink-0" aria-hidden="true" />
          <span className="text-base font-bold tracking-tight text-[#123325] whitespace-nowrap">
            SonicAudit
          </span>
        </div>

        {sites.length > 0 && activeSite && (
          <div className="p-3 border-b border-[#D4E4D8] bg-[#E5F0E8] space-y-2">
            <div className="flex items-center justify-between text-[11px] font-medium text-[#395B4A]">
              <span className="inline-flex items-center gap-1">
                <Building2 className="w-3.5 h-3.5 text-[#1E4D3B]" />
                Localidade Ativa ({sites.length})
              </span>
              <button
                type="button"
                onClick={() => onSelectSection('connect')}
                title="Gerenciar localidades e firewalls"
                className="inline-flex items-center gap-0.5 text-[#1E4D3B] hover:underline"
              >
                <Plus className="w-3 h-3" />
                Gerenciar
              </button>
            </div>
            <select
              aria-label="Selecionar localidade do firewall"
              value={activeSite.id}
              onChange={(e) => onSelectSite(e.target.value)}
              className="w-full px-2.5 py-1.5 text-xs font-medium text-[#123325] bg-white border border-[#BFD5C5] rounded-md focus:outline-none focus:ring-2 focus:ring-[#2A6B52]"
            >
              {sites.map((site) => (
                <option key={site.id} value={site.id}>
                  {site.name}
                  {site.location ? ` (${site.location})` : ''}
                  {site.alertsCount > 0 ? ` · ${site.alertsCount} alerta(s)` : ''}
                </option>
              ))}
            </select>
          </div>
        )}

        <nav className="p-3 space-y-1" aria-label="Navegação principal">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeSection === item.id;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => onSelectSection(item.id)}
                className={`w-full flex items-center justify-between px-3 py-2.5 text-sm font-medium rounded-md transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#2A6B52] ${
                  isActive
                    ? 'bg-[#1E4D3B] text-white'
                    : 'text-[#2C4B3D] hover:bg-[#DFECE3] hover:text-[#123325]'
                }`}
              >
                <span className="flex items-center gap-2.5 min-w-0">
                  <Icon className="w-4 h-4 shrink-0" aria-hidden="true" />
                  <span className="truncate whitespace-nowrap">{item.label}</span>
                </span>
                {item.count !== undefined && (
                  <span
                    className={`font-mono text-xs tabular-nums ${
                      isActive ? 'text-[#C6DED0]' : 'text-[#4B6B5C]'
                    }`}
                  >
                    {item.count.toLocaleString('pt-BR')}
                  </span>
                )}
              </button>
            );
          })}
        </nav>
      </div>

      <div className="p-4 border-t border-[#D4E4D8] space-y-2.5 text-xs text-[#456354]">
        <div>
          <p className="font-medium text-[#123325] truncate">
            {overview?.appliance.model || 'Sem appliance'}
          </p>
          <p className="text-[#4B6B5C] truncate mt-0.5">
            {overview?.appliance.host && overview.appliance.host !== '-'
              ? `${overview.appliance.host} · ${overview.appliance.firmware}`
              : 'Conecte via API ou importe .exp'}
          </p>
        </div>

        <div className="pt-2 border-t border-[#D4E4D8] flex items-center justify-between">
          <span>Retenção logs</span>
          <span className="font-mono text-[#123325] tabular-nums">{retentionDays} dias</span>
        </div>

        <div className="flex items-center justify-between">
          <span>Receptor UDP</span>
          {udpRunning ? (
            <span className="flex items-center gap-1.5 font-mono text-[#1E4D3B] font-medium tabular-nums">
              <span className="w-2 h-2 rounded-full bg-[#2A6B52]" aria-hidden="true" />
              :{overview?.udpStatus.port}
            </span>
          ) : (
            <span className="text-[#4B6B5C] font-mono">Parado</span>
          )}
        </div>

        {authUsername && (
          <div className="pt-2.5 border-t border-[#D4E4D8] space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-[#4B6B5C]">Operador</span>
              <span className="font-mono font-medium text-[#123325] truncate max-w-[120px]">
                {authUsername}
              </span>
            </div>
            <div className="grid grid-cols-2 gap-1.5">
              <button
                type="button"
                onClick={onOpenPasswordModal}
                className="inline-flex items-center justify-center gap-1 px-2 py-1.5 text-[11px] font-medium text-[#1D3B2E] bg-white border border-[#BFD5C5] rounded hover:bg-[#F4F8F5]"
              >
                <KeyRound className="w-3 h-3" />
                Senha
              </button>
              <button
                type="button"
                onClick={onLogout}
                className="inline-flex items-center justify-center gap-1 px-2 py-1.5 text-[11px] font-medium text-red-700 bg-white border border-[#E4B8B8] rounded hover:bg-red-50"
              >
                <LogOut className="w-3 h-3" />
                Sair
              </button>
            </div>
          </div>
        )}
      </div>
    </aside>
  );
}
