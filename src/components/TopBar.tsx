import { useEffect, useRef, useState } from 'react';
import {
  Bell,
  BellOff,
  BellRing,
  Database,
  Menu,
  Moon,
  Search,
  Settings2,
  Sun,
  Upload,
  X,
} from 'lucide-react';
import type { ActiveSection, AuditOverview, FirewallVendor } from '../types.ts';
import {
  DISMISSED_ALERTS_EVENT,
  dismissAlertKey,
  getAlertCategoryLabel,
  getAlertFingerprint,
  loadDismissedAlertKeys,
} from '../utils/alertHelpers.ts';
import { VENDOR_THEMES } from '../utils/vendorTheme.ts';

interface TopBarProps {
  vendor: FirewallVendor;
  activeSection: ActiveSection;
  activeSiteName?: string;
  overview: AuditOverview | null;
  onLoadSample: () => void;
  onGoToConnect: () => void;
  onOpenAlertConfig: () => void;
  onInvestigateSyslog: (query: string) => void;
  loadingSample: boolean;
  onOpenPalette?: () => void;
  onToggleMenu?: () => void;
  menuOpen?: boolean;
  toastPopupsEnabled: boolean;
  onToggleToastPopups: () => void;
  colorMode: 'light' | 'dark';
  onToggleColorMode: () => void;
}

export function TopBar({
  vendor,
  activeSection,
  activeSiteName,
  overview,
  onLoadSample,
  onGoToConnect,
  onOpenAlertConfig,
  onInvestigateSyslog,
  loadingSample,
  onOpenPalette,
  onToggleMenu,
  menuOpen = false,
  toastPopupsEnabled,
  onToggleToastPopups,
  colorMode,
  onToggleColorMode,
}: TopBarProps) {
  const theme = VENDOR_THEMES[vendor];
  const [popoverOpen, setPopoverOpen] = useState(false);
  const [dismissedKeys, setDismissedKeys] = useState<string[]>(() => loadDismissedAlertKeys(vendor));
  const popoverRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    setDismissedKeys(loadDismissedAlertKeys(vendor));
    setPopoverOpen(false);
  }, [vendor]);

  useEffect(() => {
    const onSync = (event: Event) => {
      const detail = (event as CustomEvent<{ vendor: FirewallVendor; keys: string[] }>).detail;
      if (detail?.vendor === vendor) {
        setDismissedKeys(detail.keys);
      }
    };
    window.addEventListener(DISMISSED_ALERTS_EVENT, onSync);
    return () => window.removeEventListener(DISMISSED_ALERTS_EVENT, onSync);
  }, [vendor]);

  useEffect(() => {
    if (!popoverOpen) return;
    const onClickOutside = (e: MouseEvent) => {
      if (popoverRef.current && !popoverRef.current.contains(e.target as Node)) {
        setPopoverOpen(false);
      }
    };
    document.addEventListener('mousedown', onClickOutside);
    return () => document.removeEventListener('mousedown', onClickOutside);
  }, [popoverOpen]);

  const dismissedSet = new Set(dismissedKeys);
  const activeAlerts = (overview?.alerts ?? []).filter(
    (a) => !dismissedSet.has(getAlertFingerprint(a))
  );
  const criticalCount = activeAlerts.filter((a) => a.severity === 'critical').length;

  const sectionLabels: Record<ActiveSection, string> = {
    overview: 'Visão Geral',
    syslogs: 'Análise de Syslogs',
    rules: 'Regras de Firewall Sem Uso',
    nats: vendor === 'fortigate' ? 'VIPs, IP Pools & NAT Sem Uso' : 'Políticas NAT Sem Uso',
    reports: 'Relatório Consolidado',
    ai: 'Análise Humana com IA',
    connect: 'Localidades, Conexão e Linux',
  };

  return (
    <header className="brand-topline h-16 bg-white border-b border-[var(--fw-border)] px-3 sm:px-6 flex items-center justify-between gap-6 shrink-0">
      <div className="flex items-center gap-2 text-sm min-w-0">
        {onToggleMenu && (
          <button
            type="button"
            onClick={onToggleMenu}
            aria-label="Abrir menu de navegação"
            aria-expanded={menuOpen}
            aria-controls="app-sidebar"
            className="lg:hidden -ml-2 p-2 rounded-md text-[var(--fw-text-body)] hover:bg-[var(--fw-surface)] shrink-0"
          >
            <Menu className="w-5 h-5" aria-hidden="true" />
          </button>
        )}
        <span className="text-[var(--fw-text-muted)] whitespace-nowrap shrink-0 hidden xl:inline">FW Audit</span>
        <span className="text-[var(--fw-text-faint)] hidden xl:inline" aria-hidden="true">
          /
        </span>
        <span className="font-medium text-[var(--fw-accent)] whitespace-nowrap shrink-0 hidden xl:inline">
          {theme.label}
        </span>
        <span className="text-[var(--fw-text-faint)] hidden xl:inline" aria-hidden="true">
          /
        </span>
        <h1 className="font-semibold text-[var(--fw-heading)] truncate">
          {sectionLabels[activeSection]}
        </h1>
        {activeSiteName && (
          <>
            <span className="text-[var(--fw-text-faint)] hidden sm:inline" aria-hidden="true">
              ·
            </span>
            <span className="text-xs font-medium text-[var(--fw-accent-mid)] truncate hidden sm:inline">
              {activeSiteName}
            </span>
          </>
        )}
      </div>

      <div className="flex items-center gap-1.5 sm:gap-2.5 shrink-0">
        {onOpenPalette && (
          <button
            type="button"
            onClick={onOpenPalette}
            title="Buscar telas, ações e IPs (Ctrl+K)"
            aria-label="Abrir paleta de comandos"
            className="inline-flex items-center gap-2 px-2.5 py-2 text-xs font-medium rounded-md border border-[var(--fw-border)] bg-white text-[var(--fw-text-muted)] hover:text-[var(--fw-accent)] hover:border-[var(--fw-border-strong)] transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            <Search className="w-3.5 h-3.5" aria-hidden="true" />
            <span className="hidden lg:inline">Buscar</span>
            <kbd className="hidden lg:inline font-mono text-[10px] text-[var(--fw-text-subtle)] border border-[var(--fw-border)] rounded px-1">
              Ctrl K
            </kbd>
          </button>
        )}
        <button
          type="button"
          onClick={onToggleToastPopups}
          aria-pressed={toastPopupsEnabled}
          title={
            toastPopupsEnabled
              ? 'Popups laterais de alerta ativados (clique para silenciar)'
              : 'Popups laterais desativados (alertas continuam no sino)'
          }
          className={`inline-flex items-center gap-1.5 px-2.5 py-2 text-xs font-medium rounded-md border transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
            toastPopupsEnabled
              ? 'bg-[var(--fw-bg)] text-[var(--fw-text-body)] border-[var(--fw-border-strong)] hover:bg-[var(--fw-surface)]'
              : 'bg-[var(--fw-surface-alt)] text-[var(--fw-text-muted)] border-[var(--fw-border)] hover:text-[var(--fw-heading)]'
          }`}
        >
          {toastPopupsEnabled ? (
            <BellRing className="w-3.5 h-3.5 text-[var(--fw-accent)]" aria-hidden="true" />
          ) : (
            <BellOff className="w-3.5 h-3.5" aria-hidden="true" />
          )}
          <span className="hidden lg:inline">
            {toastPopupsEnabled ? 'Popups ON' : 'Popups OFF'}
          </span>
        </button>

        <div className="relative" ref={popoverRef}>
          <button
            type="button"
            onClick={() => setPopoverOpen((v) => !v)}
            aria-expanded={popoverOpen}
            aria-label="Central de notificações e limites"
            className={`inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium rounded-md border transition-colors whitespace-nowrap shrink-0 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--fw-accent-mid)] ${
              criticalCount > 0
                ? 'bg-red-50 text-red-800 border-red-300 hover:bg-red-100'
                : activeAlerts.length > 0
                  ? 'bg-amber-50 text-amber-900 border-amber-300 hover:bg-amber-100'
                  : 'bg-[var(--fw-bg)] text-[var(--fw-text-body)] border-[var(--fw-border-strong)] hover:bg-[var(--fw-surface)]'
            }`}
          >
            <Bell className="w-3.5 h-3.5" aria-hidden="true" />
            <span className="hidden md:inline">Alertas</span>
            <span className="font-mono tabular-nums font-semibold">
              {activeAlerts.length}
            </span>
          </button>

          {popoverOpen && (
            <div className="absolute right-0 mt-2 w-96 max-w-[calc(100vw-2rem)] bg-white border border-[var(--fw-border-strong)] rounded-lg shadow-xl z-50 overflow-hidden">
              <div className="px-4 py-3 bg-[var(--fw-surface)] border-b border-[var(--fw-border)] flex items-center justify-between gap-2">
                <div>
                  <p className="text-xs font-semibold text-[var(--fw-heading)]">
                    Notificações Ativas ({activeAlerts.length})
                  </p>
                  <p className="text-[11px] text-[var(--fw-text-muted)]">
                    Limites de tráfego, anomalias e segurança
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => {
                    setPopoverOpen(false);
                    onOpenAlertConfig();
                  }}
                  className="inline-flex items-center gap-1 px-2.5 py-1 text-[11px] font-medium text-white bg-[var(--fw-accent)] rounded hover:bg-[var(--fw-accent-hover)] whitespace-nowrap"
                >
                  <Settings2 className="w-3 h-3" />
                  Configurar Regras
                </button>
              </div>

              <div className="max-h-80 overflow-y-auto divide-y divide-[var(--fw-border-soft)]">
                {activeAlerts.length === 0 ? (
                  <div className="p-5 text-center text-xs text-[var(--fw-text-muted)]">
                    Nenhum limite de tráfego ou anomalia nos logs foi atingido até o momento.
                  </div>
                ) : (
                  activeAlerts.slice(0, 8).map((alert) => {
                    const isCritical = alert.severity === 'critical';
                    return (
                      <div key={alert.id} className="p-3 space-y-1.5 hover:bg-[var(--fw-bg)]">
                        <div className="flex items-center justify-between gap-2 text-[11px]">
                          <span className="truncate">
                            <span
                              className={`font-mono font-bold ${
                                isCritical ? 'text-red-700' : 'text-amber-800'
                              }`}
                            >
                              {isCritical ? 'CRÍTICO' : 'AVISO'}
                            </span>
                            <span className="text-[var(--fw-text-faint)] mx-1.5">·</span>
                            <span className="font-medium text-[var(--fw-text-body)]">
                              {getAlertCategoryLabel(alert.category)}
                            </span>
                          </span>
                          <span className="font-mono font-semibold text-[var(--fw-heading)] tabular-nums shrink-0">
                            {alert.metricValue}
                          </span>
                        </div>
                        <p className="text-xs font-semibold text-[var(--fw-heading)]">
                          {alert.title}
                        </p>
                        <div className="flex items-center justify-between gap-2 pt-0.5">
                          <div className="flex items-center gap-2">
                            {alert.syslogFilterQuery && (
                              <button
                                type="button"
                                onClick={() => {
                                  setPopoverOpen(false);
                                  onInvestigateSyslog(alert.syslogFilterQuery || '');
                                }}
                                className="inline-flex items-center gap-1 text-[11px] font-medium text-[var(--fw-accent)] hover:underline"
                              >
                                <Search className="w-3 h-3" />
                                Ver Logs
                              </button>
                            )}
                          </div>
                          <button
                            type="button"
                            onClick={() =>
                              setDismissedKeys(dismissAlertKey(vendor, getAlertFingerprint(alert)))
                            }
                            className="inline-flex items-center gap-1 text-[11px] text-[var(--fw-text-subtle)] hover:text-[var(--fw-heading)]"
                          >
                            <X className="w-3 h-3" />
                            Silenciar
                          </button>
                        </div>
                      </div>
                    );
                  })
                )}
              </div>

              <div className="px-4 py-2.5 bg-[var(--fw-bg)] border-t border-[var(--fw-border)] flex items-center justify-between text-[11px]">
                <span className="text-[var(--fw-text-muted)]">
                  {activeAlerts.length > 8
                    ? `Exibindo 8 de ${activeAlerts.length} alertas`
                    : 'Atualização automática via UDP/API'}
                </span>
                <button
                  type="button"
                  onClick={() => {
                    setPopoverOpen(false);
                    onOpenAlertConfig();
                  }}
                  className="font-semibold text-[var(--fw-accent)] hover:underline"
                >
                  Abrir Painel Completo
                </button>
              </div>
            </div>
          )}
        </div>

        <button
          type="button"
          onClick={onLoadSample}
          disabled={loadingSample}
          aria-label={theme.sampleButtonLabel}
          title={theme.sampleButtonLabel}
          className="inline-flex items-center gap-2 px-3.5 py-2 text-xs font-medium text-[var(--fw-text-body)] bg-[var(--fw-bg)] border border-[var(--fw-border-strong)] rounded-md hover:bg-[var(--fw-surface)] transition-colors whitespace-nowrap shrink-0 disabled:opacity-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--fw-accent-mid)]"
        >
          <Database className="w-3.5 h-3.5" aria-hidden="true" />
          <span className="hidden md:inline">
            {loadingSample ? 'Carregando...' : theme.sampleButtonLabel}
          </span>
        </button>
        <button
          type="button"
          onClick={onGoToConnect}
          aria-label="Conectar ou Importar"
          title="Conectar ou Importar"
          className="inline-flex items-center gap-2 px-3.5 py-2 text-xs font-medium text-white bg-[var(--fw-cta)] rounded-md hover:bg-[var(--fw-cta-hover)] transition-colors whitespace-nowrap shrink-0 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--fw-accent-mid)]"
        >
          <Upload className="w-3.5 h-3.5" aria-hidden="true" />
          <span className="hidden md:inline">Conectar ou Importar</span>
        </button>

        <button
          type="button"
          onClick={onToggleColorMode}
          aria-label={colorMode === 'dark' ? 'Alternar para modo claro' : 'Alternar para modo escuro'}
          title={colorMode === 'dark' ? 'Modo Claro' : 'Modo Escuro'}
          className="p-2 text-[var(--fw-text-body)] bg-[var(--fw-bg)] border border-[var(--fw-border-strong)] rounded-md hover:bg-[var(--fw-surface)] transition-colors shrink-0 cursor-pointer"
        >
          {colorMode === 'dark' ? (
            <Sun className="w-4 h-4 text-amber-400" aria-hidden="true" />
          ) : (
            <Moon className="w-4 h-4" aria-hidden="true" />
          )}
        </button>
      </div>
    </header>
  );
}
