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
import type { ActiveSection, AuditOverview, FirewallVendor } from '../types.ts';
import fortinetLogo from '../assets/images/fortinet-logo.svg';
import sonicwallLogo from '../assets/images/sonicwall-logo.png';
import { VENDOR_THEMES } from '../utils/vendorTheme.ts';

interface SidebarProps {
  vendor: FirewallVendor;
  onSelectVendor: (vendor: FirewallVendor) => void;
  activeSection: ActiveSection;
  onSelectSection: (section: ActiveSection) => void;
  overview: AuditOverview | null;
  authUsername: string | null;
  onSelectSite: (siteId: string) => void;
  onOpenPasswordModal: () => void;
  onLogout: () => void;
  /** Em telas estreitas o menu é uma gaveta; controla se está aberta. */
  mobileOpen?: boolean;
}

export function Sidebar({
  vendor,
  onSelectVendor,
  activeSection,
  onSelectSection,
  overview,
  authUsername,
  onSelectSite,
  onOpenPasswordModal,
  onLogout,
  mobileOpen = false,
}: SidebarProps) {
  const theme = VENDOR_THEMES[vendor];

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
      label: vendor === 'fortigate' ? 'VIPs & NATs Sem Uso' : 'NATs Sem Uso',
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
    <aside
      id="app-sidebar"
      className={`w-64 shrink-0 border-r border-[var(--fw-border)] bg-[var(--fw-surface)] flex flex-col justify-between min-h-screen transition-transform lg:transition-colors
        fixed inset-y-0 left-0 z-50 overflow-y-auto lg:static lg:z-auto lg:overflow-visible lg:translate-x-0
        ${mobileOpen ? 'translate-x-0 shadow-2xl' : '-translate-x-full'}`}
    >
      <div>
        <div className="px-5 h-16 flex items-center justify-between gap-2 border-b border-[var(--fw-border)]">
          <div className="flex items-center gap-2.5 min-w-0">
            <Terminal className="w-5 h-5 text-[var(--fw-accent)] shrink-0" aria-hidden="true" />
            <div className="min-w-0">
              <span className="text-base font-bold tracking-tight text-[var(--fw-heading)] whitespace-nowrap block leading-none">
                FW Audit
              </span>
              <span className="text-[10px] font-medium text-[var(--fw-text-muted)] block mt-0.5 truncate">
                Auditoria de firewall
              </span>
            </div>
          </div>
        </div>

        {vendor === 'fortigate' && (
          <div className="px-3 pt-3">
            {/* Fundo branco fixo (não segue o tema escuro): o logotipo é preto e vermelho */}
            <div className="rounded-lg bg-[#ffffff] border border-[var(--fw-border)] px-3 py-2.5 flex items-center justify-between gap-2">
              <img src={fortinetLogo} alt="Fortinet" className="h-[14px] w-auto" draggable={false} />
              <span className="text-[10px] font-medium uppercase tracking-wider text-[#5f5f5f] whitespace-nowrap">
                {theme.platformSubtitle}
              </span>
            </div>
          </div>
        )}

        {vendor === 'sonicwall' && (
          <div className="px-3 pt-3">
            {/* Fundo branco fixo (não segue o tema escuro): o logotipo é cinza e laranja */}
            <div className="rounded-lg bg-[#ffffff] border border-[var(--fw-border)] px-3 py-2 flex items-center justify-between gap-2">
              <img src={sonicwallLogo} alt="SonicWall" className="h-[18px] w-auto" draggable={false} />
              <span className="text-[10px] font-medium uppercase tracking-wider text-[#556363] whitespace-nowrap">
                {theme.platformSubtitle}
              </span>
            </div>
          </div>
        )}

        {/* Seletor de Ambiente / Vendor (Azul Pastel vs Vermelho Pastel) */}
        <div className="p-3 border-b border-[var(--fw-border)] bg-[var(--fw-surface-alt)] space-y-1.5">
          <p className="text-[11px] font-medium text-[var(--fw-text-muted)]">
            Ambiente do Firewall
          </p>
          <div
            className="grid grid-cols-2 gap-1 p-1 bg-white border border-[var(--fw-border-strong)] rounded-md"
            role="tablist"
            aria-label="Selecionar fabricante do firewall"
          >
            <button
              type="button"
              role="tab"
              aria-selected={vendor === 'sonicwall'}
              onClick={() => onSelectVendor('sonicwall')}
              className={`flex items-center justify-center gap-1.5 py-1.5 px-2 text-xs font-semibold rounded transition-colors ${
                vendor === 'sonicwall'
                  ? 'bg-[var(--fw-accent)] text-white'
                  : 'text-[var(--fw-text-body)] hover:bg-[var(--fw-surface-alt)]'
              }`}
            >
              <span
                className="w-2 h-2 rounded-full bg-[var(--fw-brand)]"
                aria-hidden="true"
              />
              SonicWall
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={vendor === 'fortigate'}
              onClick={() => onSelectVendor('fortigate')}
              className={`flex items-center justify-center gap-1.5 py-1.5 px-2 text-xs font-semibold rounded transition-colors ${
                vendor === 'fortigate'
                  ? 'bg-[var(--fw-accent)] text-white'
                  : 'text-[var(--fw-text-body)] hover:bg-[var(--fw-surface-alt)]'
              }`}
            >
              <span
                className="w-2 h-2 rounded-full bg-[var(--fw-brand)]"
                aria-hidden="true"
              />
              FortiGate
            </button>
          </div>
        </div>

        {sites.length > 0 && activeSite && (
          <div className="p-3 border-b border-[var(--fw-border)] bg-[var(--fw-surface-soft)] space-y-2">
            <div className="flex items-center justify-between text-[11px] font-medium text-[var(--fw-text-muted)]">
              <span className="inline-flex items-center gap-1">
                <Building2 className="w-3.5 h-3.5 text-[var(--fw-accent)]" />
                Localidade Ativa ({sites.length})
              </span>
              <button
                type="button"
                onClick={() => onSelectSection('connect')}
                title="Gerenciar localidades e firewalls"
                className="inline-flex items-center gap-0.5 text-[var(--fw-accent)] hover:underline"
              >
                <Plus className="w-3 h-3" />
                Gerenciar
              </button>
            </div>
            <select
              aria-label="Selecionar localidade do firewall"
              value={activeSite.id}
              onChange={(e) => onSelectSite(e.target.value)}
              className="w-full px-2.5 py-1.5 text-xs font-medium text-[var(--fw-heading)] bg-white border border-[var(--fw-border-strong)] rounded-md focus:outline-none focus:ring-2 focus:ring-[var(--fw-accent-mid)]"
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
                className={`w-full flex items-center justify-between px-3 py-2.5 text-sm font-medium rounded-md transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--fw-accent-mid)] ${
                  isActive
                    ? 'bg-[var(--fw-accent)] text-white'
                    : 'text-[var(--fw-text-body)] hover:bg-[var(--fw-surface-alt)] hover:text-[var(--fw-heading)]'
                }`}
              >
                <span className="flex items-center gap-2.5 min-w-0">
                  <Icon className="w-4 h-4 shrink-0" aria-hidden="true" />
                  <span className="truncate whitespace-nowrap">{item.label}</span>
                </span>
                {item.count !== undefined && (
                  <span
                    className={`font-mono text-xs tabular-nums ${
                      isActive ? 'text-[var(--fw-accent-on-dark)]' : 'text-[var(--fw-text-muted)]'
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

      <div className="p-4 border-t border-[var(--fw-border)] space-y-2.5 text-xs text-[var(--fw-text-muted)]">
        <div>
          <p className="font-medium text-[var(--fw-heading)] truncate">
            {overview?.appliance.model || `Sem appliance ${theme.label}`}
          </p>
          <p className="text-[var(--fw-text-subtle)] truncate mt-0.5">
            {overview?.appliance.host && overview.appliance.host !== '-'
              ? `${overview.appliance.host} · ${overview.appliance.firmware}`
              : vendor === 'fortigate'
                ? 'Conecte via FortiOS API ou Syslog'
                : 'Conecte via API ou importe .exp'}
          </p>
        </div>

        <div className="pt-2 border-t border-[var(--fw-border)] flex items-center justify-between">
          <span>Retenção logs</span>
          <span className="font-mono text-[var(--fw-heading)] tabular-nums">
            {retentionDays} dias
          </span>
        </div>

        <div className="flex items-center justify-between">
          <span>Receptor UDP</span>
          {udpRunning ? (
            <span className="flex items-center gap-1.5 font-mono text-[var(--fw-accent)] font-medium tabular-nums">
              <span
                className="w-2 h-2 rounded-full bg-[var(--fw-accent-mid)]"
                aria-hidden="true"
              />
              :{overview?.udpStatus.port}
            </span>
          ) : (
            <span className="text-[var(--fw-text-subtle)] font-mono">
              Parado (:{theme.defaultUdpPort})
            </span>
          )}
        </div>

        {authUsername && (
          <div className="pt-2.5 border-t border-[var(--fw-border)] space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-[var(--fw-text-subtle)]">Operador</span>
              <span className="font-mono font-medium text-[var(--fw-heading)] truncate max-w-[120px]">
                {authUsername}
              </span>
            </div>
            <div className="grid grid-cols-2 gap-1.5">
              <button
                type="button"
                onClick={onOpenPasswordModal}
                className="inline-flex items-center justify-center gap-1 px-2 py-1.5 text-[11px] font-medium text-[var(--fw-text-body)] bg-white border border-[var(--fw-border-strong)] rounded hover:bg-[var(--fw-bg)]"
              >
                <KeyRound className="w-3 h-3" />
                Senha
              </button>
              <button
                type="button"
                onClick={onLogout}
                className="inline-flex items-center justify-center gap-1 px-2 py-1.5 text-[11px] font-medium text-red-700 bg-white border border-red-200 rounded hover:bg-red-50"
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
