import { useEffect, useState } from 'react';
import {
  AlertOctagon,
  AlertTriangle,
  Bell,
  Bot,
  Bug,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Gauge,
  Radar,
  RotateCcw,
  Search,
  Settings2,
  ShieldAlert,
  WifiOff,
  X,
} from 'lucide-react';
import type { AlertSettings, AuditOverview, FirewallVendor, OverviewAlert } from '../types.ts';
import { vendorApiUrl } from '../utils/vendorApi.ts';

interface OverviewAlertCenterProps {
  vendor: FirewallVendor;
  overview: AuditOverview;
  onOverviewUpdated: (next: AuditOverview) => void;
  onInvestigateSyslog: (query: string) => void;
  onAnalyzeWithAi: (prompt: string) => void;
}

type CategoryFilter = 'all' | 'bandwidth' | 'ips-malware' | 'logs';

function getDismissedStorageKey(vendor: FirewallVendor): string {
  return `fwaudit_dismissed_alerts_v1_${vendor}`;
}

function loadDismissedKeys(vendor: FirewallVendor): string[] {
  try {
    const raw = localStorage.getItem(getDismissedStorageKey(vendor));
    if (!raw) return [];
    const parsed = JSON.parse(raw) as unknown;
    return Array.isArray(parsed) ? parsed.filter((x): x is string => typeof x === 'string') : [];
  } catch {
    return [];
  }
}

function getAlertFingerprint(alert: OverviewAlert): string {
  return `${alert.id}|${alert.metricValue}`;
}

function getCategoryLabel(cat: OverviewAlert['category']): string {
  switch (cat) {
    case 'bandwidth':
      return 'Uso de Banda';
    case 'link-down':
      return 'Link Offline';
    case 'ips':
      return 'IPS / Origem Maliciosa';
    case 'malware':
      return 'Malware / Antivírus';
    case 'critical-log':
      return 'Falha Crítica';
    case 'suspicious-traffic':
      return 'Log Suspeito';
  }
}

function renderCategoryIcon(alert: OverviewAlert) {
  const cls =
    alert.severity === 'critical'
      ? 'w-4 h-4 text-red-700 shrink-0'
      : 'w-4 h-4 text-amber-800 shrink-0';
  switch (alert.category) {
    case 'bandwidth':
      return <Gauge className={cls} aria-hidden="true" />;
    case 'link-down':
      return <WifiOff className={cls} aria-hidden="true" />;
    case 'ips':
      return <ShieldAlert className={cls} aria-hidden="true" />;
    case 'malware':
      return <Bug className={cls} aria-hidden="true" />;
    case 'critical-log':
      return <AlertOctagon className={cls} aria-hidden="true" />;
    case 'suspicious-traffic':
      return <Radar className={cls} aria-hidden="true" />;
  }
}

export function OverviewAlertCenter({
  vendor,
  overview,
  onOverviewUpdated,
  onInvestigateSyslog,
  onAnalyzeWithAi,
}: OverviewAlertCenterProps) {
  const [dismissedKeys, setDismissedKeys] = useState<string[]>(() => loadDismissedKeys(vendor));
  const [categoryFilter, setCategoryFilter] = useState<CategoryFilter>('all');
  const [showAllAlerts, setShowAllAlerts] = useState(false);
  const [showConfig, setShowConfig] = useState(false);

  const [draftSettings, setDraftSettings] = useState<AlertSettings>(overview.alertSettings);
  const [savingConfig, setSavingConfig] = useState(false);
  const [configFeedback, setConfigFeedback] = useState<string | null>(null);

  useEffect(() => {
    setDismissedKeys(loadDismissedKeys(vendor));
    setCategoryFilter('all');
    setShowAllAlerts(false);
    setShowConfig(false);
    setConfigFeedback(null);
  }, [vendor]);

  useEffect(() => {
    setDraftSettings(overview.alertSettings);
  }, [overview.alertSettings]);

  useEffect(() => {
    try {
      localStorage.setItem(getDismissedStorageKey(vendor), JSON.stringify(dismissedKeys));
    } catch {
      // Ignored in restricted storage mode
    }
  }, [dismissedKeys, vendor]);

  const allAlerts = overview.alerts ?? [];
  const dismissedSet = new Set(dismissedKeys);
  const activeAlerts = allAlerts.filter((a) => !dismissedSet.has(getAlertFingerprint(a)));
  const dismissedActiveCount = allAlerts.length - activeAlerts.length;

  const filteredAlerts = activeAlerts.filter((a) => {
    if (categoryFilter === 'all') return true;
    if (categoryFilter === 'bandwidth') {
      return a.category === 'bandwidth' || a.category === 'link-down';
    }
    if (categoryFilter === 'ips-malware') {
      return a.category === 'ips' || a.category === 'malware';
    }
    return a.category === 'critical-log' || a.category === 'suspicious-traffic';
  });

  const criticalCount = activeAlerts.filter((a) => a.severity === 'critical').length;
  const warningCount = activeAlerts.filter((a) => a.severity === 'warning').length;

  const visibleAlerts = showAllAlerts ? filteredAlerts : filteredAlerts.slice(0, 4);

  const handleDismiss = (alert: OverviewAlert) => {
    const key = getAlertFingerprint(alert);
    setDismissedKeys((prev) => (prev.includes(key) ? prev : [...prev, key]));
  };

  const handleRestoreDismissed = () => {
    setDismissedKeys([]);
  };

  const handleSaveSettings = async () => {
    setSavingConfig(true);
    setConfigFeedback(null);
    try {
      const res = await fetch(vendorApiUrl(vendor, '/alerts/config'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(draftSettings),
      });
      if (res.ok) {
        const data = (await res.json()) as {
          alertSettings: AlertSettings;
          overview: AuditOverview;
        };
        if (data.overview) {
          onOverviewUpdated(data.overview);
        }
        setConfigFeedback('Limites aplicados e alertas reavaliados.');
        setTimeout(() => setConfigFeedback(null), 2500);
      }
    } finally {
      setSavingConfig(false);
    }
  };

  const hasCritical = criticalCount > 0;
  const hasAnyAlert = activeAlerts.length > 0;

  const containerStyle = hasCritical
    ? 'bg-red-50/90 border-red-300'
    : hasAnyAlert
      ? 'bg-amber-50/90 border-amber-300'
      : 'bg-[var(--fw-surface)] border-[var(--fw-border-strong)]';

  return (
    <section
      aria-label="Notificações e Alertas Imediatos"
      className={`border rounded-lg p-4 space-y-3 transition-colors ${containerStyle}`}
    >
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-start sm:items-center gap-3 min-w-0">
          <div
            className={`p-2 rounded-md border shrink-0 bg-white ${
              hasCritical
                ? 'border-red-300 text-red-700'
                : hasAnyAlert
                  ? 'border-amber-300 text-amber-800'
                  : 'border-[var(--fw-border-strong)] text-emerald-700'
            }`}
          >
            {hasCritical ? (
              <AlertOctagon className="w-4 h-4" aria-hidden="true" />
            ) : hasAnyAlert ? (
              <AlertTriangle className="w-4 h-4" aria-hidden="true" />
            ) : (
              <CheckCircle2 className="w-4 h-4" aria-hidden="true" />
            )}
          </div>

          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <h2 className="text-sm font-semibold text-[var(--fw-heading)]">
                {hasAnyAlert
                  ? 'Notificações de Segurança e Consumo de Banda'
                  : 'Monitoramento Ativo — Sem Alertas Críticos'}
              </h2>
              {hasAnyAlert && (
                <span className="text-xs font-mono tabular-nums font-semibold text-[var(--fw-heading)]">
                  ({criticalCount} crítico{criticalCount === 1 ? '' : 's'} · {warningCount} aviso
                  {warningCount === 1 ? '' : 's'})
                </span>
              )}
            </div>
            <p className="text-xs text-[var(--fw-text-muted)] mt-0.5 tabular-nums">
              {hasAnyAlert ? (
                <>
                  Limite de banda:{' '}
                  <span className="font-mono font-medium">
                    {overview.alertSettings.bandwidthUtilizationLimitPercent}%
                  </span>
                  {overview.alertSettings.bandwidthMbpsLimit > 0
                    ? ` ou ${overview.alertSettings.bandwidthMbpsLimit} Mbps`
                    : ''}
                  {' · '}IPS malicioso:{' '}
                  <span className="font-mono font-medium">
                    {overview.alertSettings.alertOnIps ? 'ativo' : 'pausado'}
                  </span>
                  {' · '}Logs suspeitos ≥{' '}
                  <span className="font-mono font-medium">
                    {overview.alertSettings.suspiciousBlockThreshold}
                  </span>{' '}
                  bloqueios
                </>
              ) : (
                <>
                  Nenhuma interface ultrapassou{' '}
                  {overview.alertSettings.bandwidthUtilizationLimitPercent}%
                  {overview.alertSettings.bandwidthMbpsLimit > 0
                    ? ` (${overview.alertSettings.bandwidthMbpsLimit} Mbps)`
                    : ''}{' '}
                  e nenhum evento crítico/IPS malicioso está pendente.
                </>
              )}
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2 shrink-0">
          {dismissedActiveCount > 0 && (
            <button
              type="button"
              onClick={handleRestoreDismissed}
              className="inline-flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-medium text-[var(--fw-text-body)] bg-white border border-[var(--fw-border-strong)] rounded-md hover:bg-[var(--fw-bg)]"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              Reexibir {dismissedActiveCount} silenciado(s)
            </button>
          )}
          <button
            type="button"
            onClick={() => setShowConfig((v) => !v)}
            className={`inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md border whitespace-nowrap transition-colors ${
              showConfig
                ? 'bg-[var(--fw-accent)] text-white border-[var(--fw-accent)]'
                : 'bg-white text-[var(--fw-text-body)] border-[var(--fw-border-strong)] hover:bg-[var(--fw-bg)]'
            }`}
          >
            <Settings2 className="w-3.5 h-3.5" />
            Limites de Alerta
          </button>
        </div>
      </div>

      {showConfig && (
        <div className="bg-white border border-[var(--fw-border)] rounded-md p-4 space-y-4">
          <div className="flex items-center justify-between border-b border-[var(--fw-border-soft)] pb-2.5">
            <span className="text-xs font-semibold text-[var(--fw-heading)] inline-flex items-center gap-1.5">
              <Bell className="w-3.5 h-3.5 text-[var(--fw-accent)]" />
              Configurar Gatilhos de Notificação Imediata
            </span>
            {configFeedback && (
              <span className="text-xs font-medium text-emerald-800">{configFeedback}</span>
            )}
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
            <label className="block space-y-1.5">
              <span className="font-medium text-[var(--fw-text-body)]">
                Limite de Uso do Link (%)
              </span>
              <div className="flex items-center gap-2">
                <input
                  type="range"
                  min={5}
                  max={100}
                  step={5}
                  value={draftSettings.bandwidthUtilizationLimitPercent}
                  onChange={(e) =>
                    setDraftSettings((s) => ({
                      ...s,
                      bandwidthUtilizationLimitPercent: Number(e.target.value),
                    }))
                  }
                  className="flex-1 accent-[var(--fw-accent)]"
                />
                <input
                  type="number"
                  min={5}
                  max={100}
                  value={draftSettings.bandwidthUtilizationLimitPercent}
                  onChange={(e) =>
                    setDraftSettings((s) => ({
                      ...s,
                      bandwidthUtilizationLimitPercent: Number(e.target.value),
                    }))
                  }
                  className="w-16 px-2 py-1 border border-[var(--fw-border-strong)] rounded font-mono text-right text-[var(--fw-heading)] bg-[var(--fw-bg-input)]"
                />
              </div>
            </label>

            <label className="block space-y-1.5">
              <span className="font-medium text-[var(--fw-text-body)]">
                Limite Absoluto de Banda (Mbps, 0 = off)
              </span>
              <input
                type="number"
                min={0}
                max={100000}
                step={10}
                value={draftSettings.bandwidthMbpsLimit}
                onChange={(e) =>
                  setDraftSettings((s) => ({
                    ...s,
                    bandwidthMbpsLimit: Math.max(0, Number(e.target.value) || 0),
                  }))
                }
                placeholder="Ex: 250"
                className="w-full px-3 py-1.5 border border-[var(--fw-border-strong)] rounded font-mono text-[var(--fw-heading)] bg-[var(--fw-bg-input)]"
              />
            </label>

            <label className="block space-y-1.5">
              <span className="font-medium text-[var(--fw-text-body)]">
                Limiar de Bloqueios Suspeitos (por IP)
              </span>
              <input
                type="number"
                min={1}
                max={100}
                value={draftSettings.suspiciousBlockThreshold}
                onChange={(e) =>
                  setDraftSettings((s) => ({
                    ...s,
                    suspiciousBlockThreshold: Math.max(1, Number(e.target.value) || 1),
                  }))
                }
                className="w-full px-3 py-1.5 border border-[var(--fw-border-strong)] rounded font-mono text-[var(--fw-heading)] bg-[var(--fw-bg-input)]"
              />
            </label>
          </div>

          <div className="flex flex-wrap items-center justify-between gap-4 pt-2 border-t border-[var(--fw-border-soft)] text-xs">
            <div className="flex flex-wrap items-center gap-5">
              <label className="inline-flex items-center gap-2 text-[var(--fw-text-body)] cursor-pointer">
                <input
                  type="checkbox"
                  checked={draftSettings.alertOnIps}
                  onChange={(e) =>
                    setDraftSettings((s) => ({ ...s, alertOnIps: e.target.checked }))
                  }
                  className="rounded border-[var(--fw-border-strong)] accent-[var(--fw-accent)]"
                />
                Alertar em eventos IPS / origem maliciosa
              </label>

              <label className="inline-flex items-center gap-2 text-[var(--fw-text-body)] cursor-pointer">
                <input
                  type="checkbox"
                  checked={draftSettings.alertOnCriticalLogs}
                  onChange={(e) =>
                    setDraftSettings((s) => ({ ...s, alertOnCriticalLogs: e.target.checked }))
                  }
                  className="rounded border-[var(--fw-border-strong)] accent-[var(--fw-accent)]"
                />
                Alertar em falhas críticas, Malware e varreduras suspeitas
              </label>
            </div>

            <button
              type="button"
              disabled={savingConfig}
              onClick={() => void handleSaveSettings()}
              className="px-4 py-1.5 text-xs font-medium text-white bg-[var(--fw-accent)] rounded-md hover:bg-[var(--fw-accent-hover)] disabled:opacity-50"
            >
              {savingConfig ? 'Aplicando...' : 'Aplicar Limites'}
            </button>
          </div>
        </div>
      )}

      {hasAnyAlert && (
        <>
          <div className="flex flex-wrap items-center gap-1.5 text-xs">
            {(
              [
                { id: 'all', label: `Todos (${activeAlerts.length})` },
                {
                  id: 'bandwidth',
                  label: `Banda / Links (${activeAlerts.filter((a) => a.category === 'bandwidth' || a.category === 'link-down').length})`,
                },
                {
                  id: 'ips-malware',
                  label: `IPS & Malware (${activeAlerts.filter((a) => a.category === 'ips' || a.category === 'malware').length})`,
                },
                {
                  id: 'logs',
                  label: `Falhas & Suspeitos (${activeAlerts.filter((a) => a.category === 'critical-log' || a.category === 'suspicious-traffic').length})`,
                },
              ] as Array<{ id: CategoryFilter; label: string }>
            ).map((tab) => (
              <button
                key={tab.id}
                type="button"
                onClick={() => setCategoryFilter(tab.id)}
                className={`px-2.5 py-1 rounded border text-xs font-medium transition-colors ${
                  categoryFilter === tab.id
                    ? 'bg-[var(--fw-accent)] text-white border-[var(--fw-accent)]'
                    : 'bg-white text-[var(--fw-text-body)] border-[var(--fw-border)] hover:bg-[var(--fw-bg)]'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>

          {filteredAlerts.length === 0 ? (
            <div className="bg-white border border-[var(--fw-border)] rounded-md px-4 py-3 text-xs text-[var(--fw-text-muted)]">
              Nenhuma notificação ativa para esta categoria.
            </div>
          ) : (
            <div className="space-y-2">
              {visibleAlerts.map((alert) => {
                const isCritical = alert.severity === 'critical';
                return (
                  <div
                    key={alert.id}
                    className={`bg-white border rounded-md px-4 py-3 flex flex-wrap items-start justify-between gap-3 ${
                      isCritical ? 'border-red-300' : 'border-amber-300'
                    }`}
                  >
                    <div className="flex items-start gap-3 min-w-0 flex-1">
                      <div className="mt-0.5">{renderCategoryIcon(alert)}</div>
                      <div className="min-w-0 space-y-1">
                        <div className="flex flex-wrap items-center gap-2 text-xs">
                          <span
                            className={`font-mono font-bold tracking-wide ${
                              isCritical ? 'text-red-700' : 'text-amber-800'
                            }`}
                          >
                            {isCritical ? 'CRÍTICO' : 'AVISO'}
                          </span>
                          <span className="text-[var(--fw-text-faint)]" aria-hidden="true">
                            ·
                          </span>
                          <span className="font-medium text-[var(--fw-text-body)]">
                            {getCategoryLabel(alert.category)}
                          </span>
                          <span className="text-[var(--fw-text-faint)]" aria-hidden="true">
                            ·
                          </span>
                          <span className="font-mono tabular-nums font-semibold text-[var(--fw-heading)]">
                            {alert.metricValue}
                          </span>
                          {alert.lastSeenAt && (
                            <>
                              <span className="text-[var(--fw-text-faint)]" aria-hidden="true">
                                ·
                              </span>
                              <span className="font-mono text-[11px] text-[var(--fw-text-subtle)] tabular-nums">
                                {alert.lastSeenAt}
                              </span>
                            </>
                          )}
                        </div>
                        <p className="text-xs font-semibold text-[var(--fw-heading)]">{alert.title}</p>
                        <p className="text-xs text-[var(--fw-text-muted)] leading-relaxed">
                          {alert.description}
                        </p>
                      </div>
                    </div>

                    <div className="flex flex-wrap items-center gap-1.5 shrink-0">
                      {alert.syslogFilterQuery && (
                        <button
                          type="button"
                          onClick={() => onInvestigateSyslog(alert.syslogFilterQuery || '')}
                          className="inline-flex items-center gap-1 px-2.5 py-1.5 text-xs font-medium text-[var(--fw-text-body)] bg-[var(--fw-bg)] border border-[var(--fw-border-strong)] rounded hover:bg-[var(--fw-surface)]"
                        >
                          <Search className="w-3.5 h-3.5" />
                          Ver Logs
                        </button>
                      )}
                      {alert.aiPrompt && (
                        <button
                          type="button"
                          onClick={() => onAnalyzeWithAi(alert.aiPrompt || '')}
                          className="inline-flex items-center gap-1 px-2.5 py-1.5 text-xs font-medium text-white bg-[var(--fw-accent)] rounded hover:bg-[var(--fw-accent-hover)]"
                        >
                          <Bot className="w-3.5 h-3.5" />
                          Analisar IA
                        </button>
                      )}
                      {(alert.category === 'bandwidth' || alert.category === 'link-down') && (
                        <button
                          type="button"
                          onClick={() => setShowConfig(true)}
                          className="inline-flex items-center gap-1 px-2.5 py-1.5 text-xs font-medium text-[var(--fw-text-body)] bg-[var(--fw-bg)] border border-[var(--fw-border-strong)] rounded hover:bg-[var(--fw-surface)]"
                        >
                          <Settings2 className="w-3.5 h-3.5" />
                          Ajustar Limite
                        </button>
                      )}
                      <button
                        type="button"
                        onClick={() => handleDismiss(alert)}
                        title="Silenciar este alerta"
                        aria-label={`Silenciar ${alert.title}`}
                        className="p-1.5 text-[var(--fw-text-subtle)] hover:text-[var(--fw-heading)] hover:bg-[var(--fw-surface)] rounded"
                      >
                        <X className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </div>
                );
              })}

              {filteredAlerts.length > 4 && (
                <button
                  type="button"
                  onClick={() => setShowAllAlerts((v) => !v)}
                  className="inline-flex items-center gap-1.5 text-xs font-medium text-[var(--fw-accent)] hover:underline pt-1"
                >
                  {showAllAlerts ? (
                    <>
                      <ChevronUp className="w-3.5 h-3.5" />
                      Mostrar apenas os 4 principais
                    </>
                  ) : (
                    <>
                      <ChevronDown className="w-3.5 h-3.5" />
                      Exibir todas as {filteredAlerts.length} notificações
                    </>
                  )}
                </button>
              )}
            </div>
          )}
        </>
      )}
    </section>
  );
}
