import { useEffect, useRef, useState } from 'react';
import { Bell, Database, Search, Settings2, Upload, X } from 'lucide-react';
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
    <header className="h-16 bg-white border-b border-[var(--fw-border)] px-6 flex items-center justify-between gap-6 shrink-0">
      <div className="flex items-center gap-2 text-sm min-w-0">
        <span className="text-[var(--fw-text-muted)] whitespace-nowrap shrink-0">FW Audit</span>
        <span className="text-[var(--fw-text-faint)]" aria-hidden="true">
          /
        </span>
        <span className="font-medium text-[var(--fw-accent)] whitespace-nowrap shrink-0">
          {theme.label}
        </span>
        <span className="text-[var(--fw-text-faint)]" aria-hidden="true">
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

      <div className="flex items-center gap-2.5 shrink-0">
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
          className="inline-flex items-center gap-2 px-3.5 py-2 text-xs font-medium text-[var(--fw-text-body)] bg-[var(--fw-bg)] border border-[var(--fw-border-strong)] rounded-md hover:bg-[var(--fw-surface)] transition-colors whitespace-nowrap shrink-0 disabled:opacity-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--fw-accent-mid)]"
        >
          <Database className="w-3.5 h-3.5" aria-hidden="true" />
          {loadingSample ? 'Carregando...' : theme.sampleButtonLabel}
        </button>
        <button
          type="button"
          onClick={onGoToConnect}
          className="inline-flex items-center gap-2 px-3.5 py-2 text-xs font-medium text-white bg-[var(--fw-accent)] rounded-md hover:bg-[var(--fw-accent-hover)] transition-colors whitespace-nowrap shrink-0 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--fw-accent-mid)]"
        >
          <Upload className="w-3.5 h-3.5" aria-hidden="true" />
          Conectar ou Importar
        </button>
      </div>
    </header>
  );
}
