import { useEffect, useRef, useState } from 'react';
import {
  Activity,
  AlertOctagon,
  AlertTriangle,
  BarChart3,
  Bell,
  Bot,
  Bug,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Gauge,
  Radar,
  RotateCcw,
  Search,
  Send,
  Settings2,
  ShieldAlert,
  TrendingUp,
  WifiOff,
  X,
} from 'lucide-react';
import type {
  AlertSettings,
  AuditOverview,
  FirewallVendor,
  NotificationPublicConfig,
  OverviewAlert,
} from '../types.ts';
import {
  DISMISSED_ALERTS_EVENT,
  REEVALUATE_TOASTS_EVENT,
  dismissAlertKey,
  getAlertCategoryLabel,
  getAlertFingerprint,
  loadDismissedAlertKeys,
  restoreAllDismissedAlerts,
} from '../utils/alertHelpers.ts';
import { vendorApiUrl } from '../utils/vendorApi.ts';

interface OverviewAlertCenterProps {
  vendor: FirewallVendor;
  overview: AuditOverview;
  onOverviewUpdated: (next: AuditOverview) => void;
  onInvestigateSyslog: (query: string) => void;
  onAnalyzeWithAi: (prompt: string) => void;
  openConfigSignal?: number;
}

type CategoryFilter = 'all' | 'bandwidth' | 'traffic-anomaly' | 'ips-malware' | 'logs' | 'infra';

const INFRA_CATEGORIES = new Set(['collector', 'resource', 'vpn', 'license', 'config-change']);
const LOG_CATEGORIES = new Set(['critical-log', 'suspicious-traffic', 'auth']);

function formatAlertTime(iso?: string): string {
  if (!iso) return '';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString('pt-BR', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' });
}

const numberInputClass =
  'w-full px-3 py-1.5 border border-[var(--fw-border-strong)] rounded font-mono tabular-nums text-[var(--fw-heading)] bg-[var(--fw-bg-input)]';

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
    case 'traffic-volume':
      return <BarChart3 className={cls} aria-hidden="true" />;
    case 'anomaly':
      return <TrendingUp className={cls} aria-hidden="true" />;
    case 'ips':
      return <ShieldAlert className={cls} aria-hidden="true" />;
    case 'malware':
      return <Bug className={cls} aria-hidden="true" />;
    case 'critical-log':
      return <AlertOctagon className={cls} aria-hidden="true" />;
    case 'suspicious-traffic':
      return <Radar className={cls} aria-hidden="true" />;
    default:
      return <Activity className={cls} aria-hidden="true" />;
  }
}

export function OverviewAlertCenter({
  vendor,
  overview,
  onOverviewUpdated,
  onInvestigateSyslog,
  onAnalyzeWithAi,
  openConfigSignal = 0,
}: OverviewAlertCenterProps) {
  const sectionRef = useRef<HTMLElement | null>(null);
  const [dismissedKeys, setDismissedKeys] = useState<string[]>(() => loadDismissedAlertKeys(vendor));
  const [categoryFilter, setCategoryFilter] = useState<CategoryFilter>('all');
  const [showAllAlerts, setShowAllAlerts] = useState(false);
  const [showConfig, setShowConfig] = useState(false);

  const [draftSettings, setDraftSettings] = useState<AlertSettings>(overview.alertSettings);
  const [savingConfig, setSavingConfig] = useState(false);
  const [configFeedback, setConfigFeedback] = useState<string | null>(null);
  const [showAcked, setShowAcked] = useState(false);

  // Notificações externas (webhook / Telegram)
  const [notifConfig, setNotifConfig] = useState<NotificationPublicConfig | null>(null);
  const [notifWebhook, setNotifWebhook] = useState('');
  const [notifTgToken, setNotifTgToken] = useState('');
  const [notifTgChat, setNotifTgChat] = useState('');
  const [notifBusy, setNotifBusy] = useState(false);
  const [notifFeedback, setNotifFeedback] = useState<{ type: 'ok' | 'err'; text: string } | null>(null);

  useEffect(() => {
    if (!showConfig) return;
    let cancelled = false;
    void (async () => {
      const res = await fetch(vendorApiUrl(vendor, '/notifications/config'));
      if (res.ok && !cancelled) {
        const data = (await res.json()) as NotificationPublicConfig;
        setNotifConfig(data);
        setNotifTgChat(data.telegramChatId || '');
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [showConfig, vendor]);

  const saveNotifications = async (patch: Record<string, unknown>) => {
    setNotifBusy(true);
    setNotifFeedback(null);
    try {
      const res = await fetch(vendorApiUrl(vendor, '/notifications/config'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(patch),
      });
      const data = await res.json();
      if (!res.ok) {
        setNotifFeedback({ type: 'err', text: data.error || 'Erro ao salvar notificações.' });
        return;
      }
      setNotifConfig(data as NotificationPublicConfig);
      setNotifWebhook('');
      setNotifTgToken('');
      setNotifFeedback({ type: 'ok', text: 'Notificações salvas.' });
    } finally {
      setNotifBusy(false);
    }
  };

  const testNotifications = async () => {
    setNotifBusy(true);
    setNotifFeedback(null);
    try {
      const res = await fetch(vendorApiUrl(vendor, '/notifications/test'), { method: 'POST' });
      const data = await res.json();
      setNotifFeedback(
        res.ok
          ? { type: 'ok', text: 'Mensagem de teste enviada.' }
          : { type: 'err', text: data.error || 'Falha no envio de teste.' }
      );
    } finally {
      setNotifBusy(false);
    }
  };

  const setAck = async (alert: OverviewAlert, acknowledge: boolean) => {
    if (!alert.key) return;
    const res = await fetch(vendorApiUrl(vendor, acknowledge ? '/alerts/ack' : '/alerts/unack'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ key: alert.key }),
    });
    if (res.ok) {
      const data = (await res.json()) as { overview?: AuditOverview };
      if (data.overview) onOverviewUpdated(data.overview);
    }
  };

  useEffect(() => {
    setDismissedKeys(loadDismissedAlertKeys(vendor));
    setCategoryFilter('all');
    setShowAllAlerts(false);
    setShowConfig(false);
    setConfigFeedback(null);
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
    if (openConfigSignal > 0) {
      setShowConfig(true);
      setTimeout(() => {
        sectionRef.current?.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      }, 60);
    }
  }, [openConfigSignal]);

  useEffect(() => {
    setDraftSettings(overview.alertSettings);
  }, [overview.alertSettings]);

  const allAlerts = overview.alerts ?? [];
  const dismissedSet = new Set(dismissedKeys);
  // Reconhecidos (no servidor, valem para todos os usuários) saem da lista principal
  const ackedAlerts = allAlerts.filter((a) => a.status === 'acknowledged');
  const openAlerts = allAlerts.filter((a) => a.status !== 'acknowledged');
  const activeAlerts = openAlerts.filter((a) => !dismissedSet.has(getAlertFingerprint(a)));
  const dismissedActiveCount = openAlerts.length - activeAlerts.length;
  const listedAlerts = showAcked ? [...activeAlerts, ...ackedAlerts] : activeAlerts;

  const filteredAlerts = listedAlerts.filter((a) => {
    if (categoryFilter === 'all') return true;
    if (categoryFilter === 'bandwidth') {
      return a.category === 'bandwidth' || a.category === 'link-down';
    }
    if (categoryFilter === 'traffic-anomaly') {
      return a.category === 'traffic-volume' || a.category === 'anomaly';
    }
    if (categoryFilter === 'ips-malware') {
      return a.category === 'ips' || a.category === 'malware';
    }
    if (categoryFilter === 'infra') return INFRA_CATEGORIES.has(a.category);
    return LOG_CATEGORIES.has(a.category);
  });

  const criticalCount = activeAlerts.filter((a) => a.severity === 'critical').length;
  const warningCount = activeAlerts.filter((a) => a.severity === 'warning').length;

  const visibleAlerts = showAllAlerts ? filteredAlerts : filteredAlerts.slice(0, 4);

  const handleDismiss = (alert: OverviewAlert) => {
    if (alert.key) {
      void setAck(alert, true);
      return;
    }
    const key = getAlertFingerprint(alert);
    setDismissedKeys(dismissAlertKey(vendor, key));
  };

  const handleRestoreDismissed = () => {
    setDismissedKeys(restoreAllDismissedAlerts(vendor));
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
          window.dispatchEvent(new CustomEvent(REEVALUATE_TOASTS_EVENT));
          onOverviewUpdated(data.overview);
          const count = data.overview.alerts?.length ?? 0;
          setConfigFeedback(
            count > 0
              ? `Regras salvas — ${count} alerta(s) ativo(s) notificados na interface.`
              : 'Regras salvas — nenhum limite ou anomalia atingido.'
          );
        } else {
          setConfigFeedback('Limites aplicados e alertas reavaliados.');
        }
        setTimeout(() => setConfigFeedback(null), 4000);
      }
    } finally {
      setSavingConfig(false);
    }
  };

  const hasCritical = criticalCount > 0;
  const hasAnyAlert = activeAlerts.length > 0;
  const cfg = overview.alertSettings;

  const containerStyle = hasCritical
    ? 'bg-red-50/90 border-red-300'
    : hasAnyAlert
      ? 'bg-amber-50/90 border-amber-300'
      : 'bg-[var(--fw-surface)] border-[var(--fw-border-strong)]';

  return (
    <section
      ref={sectionRef}
      aria-label="Notificações, Limites de Tráfego e Detecção de Anomalias"
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
                  ? 'Notificações de Tráfego, Anomalias e Segurança'
                  : 'Monitoramento Ativo — Sem Alertas ou Anomalias'}
              </h2>
              {hasAnyAlert && (
                <span className="text-xs font-mono tabular-nums font-semibold text-[var(--fw-heading)]">
                  ({criticalCount} crítico{criticalCount === 1 ? '' : 's'} · {warningCount} aviso
                  {warningCount === 1 ? '' : 's'})
                </span>
              )}
            </div>
            <p className="text-xs text-[var(--fw-text-muted)] mt-0.5 tabular-nums">
              Banda ≥{' '}
              <span className="font-mono font-medium">{cfg.bandwidthUtilizationLimitPercent}%</span>
              {cfg.bandwidthMbpsLimit > 0 ? ` / ${cfg.bandwidthMbpsLimit} Mbps` : ''}
              {cfg.hourlyLogVolumeLimit > 0
                ? ` · Logs/h ≥ ${cfg.hourlyLogVolumeLimit.toLocaleString('pt-BR')}`
                : ''}
              {cfg.syslogTrafficMbLimit > 0 ? ` · Volume ≥ ${cfg.syslogTrafficMbLimit} MB` : ''}
              {' · '}Anomalias:{' '}
              <span className="font-mono font-medium">
                {cfg.anomalyDetectionEnabled
                  ? `pico ${cfg.anomalySpikeMultiplier}x`
                  : 'desligada'}
              </span>
              {cfg.blockedTrafficRatioLimitPercent > 0
                ? ` / bloqueio ≥ ${cfg.blockedTrafficRatioLimitPercent}%`
                : ''}
              {cfg.portScanUniquePortsThreshold > 0
                ? ` / scan ≥ ${cfg.portScanUniquePortsThreshold} portas`
                : ''}
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2 shrink-0">
          {dismissedActiveCount > 0 && (
            <button
              type="button"
              onClick={handleRestoreDismissed}
              className="inline-flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-medium text-[var(--fw-text-body)] bg-white border border-[var(--fw-border-strong)] rounded-md hover:bg-[var(--fw-bg)] whitespace-nowrap"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              Reexibir {dismissedActiveCount} silenciado(s)
            </button>
          )}
          {ackedAlerts.length > 0 && (
            <button
              type="button"
              onClick={() => setShowAcked((v) => !v)}
              className="inline-flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-medium text-[var(--fw-text-body)] bg-white border border-[var(--fw-border-strong)] rounded-md hover:bg-[var(--fw-bg)] whitespace-nowrap"
            >
              <Check className="w-3.5 h-3.5" />
              {showAcked ? 'Ocultar' : 'Ver'} {ackedAlerts.length} reconhecido(s)
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
            Limites &amp; Anomalias
          </button>
        </div>
      </div>

      {showConfig && (
        <div className="bg-white border border-[var(--fw-border)] rounded-md p-4 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[var(--fw-border-soft)] pb-2.5">
            <span className="text-xs font-semibold text-[var(--fw-heading)] inline-flex items-center gap-1.5">
              <Bell className="w-3.5 h-3.5 text-[var(--fw-accent)]" />
              Configurar Limites de Tráfego e Regras de Anomalia nos Logs
            </span>
            {configFeedback && (
              <span className="text-xs font-medium text-emerald-800">{configFeedback}</span>
            )}
          </div>

          <div className="space-y-2.5">
            <p className="text-[11px] font-semibold uppercase tracking-wider text-[var(--fw-text-subtle)]">
              1. Limites de Tráfego &amp; Volume de Logs
            </p>
            <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4 text-xs">
              <label className="block space-y-1.5">
                <span className="font-medium text-[var(--fw-text-body)]">
                  Uso do Link (%)
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
                    className="w-16 px-2 py-1 border border-[var(--fw-border-strong)] rounded font-mono text-right tabular-nums text-[var(--fw-heading)] bg-[var(--fw-bg-input)]"
                  />
                </div>
              </label>

              <label className="block space-y-1.5">
                <span className="font-medium text-[var(--fw-text-body)]">
                  Banda Absoluta (Mbps, 0 = off)
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
                  className="w-full px-3 py-1.5 border border-[var(--fw-border-strong)] rounded font-mono tabular-nums text-[var(--fw-heading)] bg-[var(--fw-bg-input)]"
                />
              </label>

              <label className="block space-y-1.5">
                <span className="font-medium text-[var(--fw-text-body)]">
                  Volume em Syslogs (MB, 0 = off)
                </span>
                <input
                  type="number"
                  min={0}
                  max={1000000}
                  step={0.5}
                  value={draftSettings.syslogTrafficMbLimit}
                  onChange={(e) =>
                    setDraftSettings((s) => ({
                      ...s,
                      syslogTrafficMbLimit: Math.max(0, Number(e.target.value) || 0),
                    }))
                  }
                  placeholder="Ex: 50"
                  className="w-full px-3 py-1.5 border border-[var(--fw-border-strong)] rounded font-mono tabular-nums text-[var(--fw-heading)] bg-[var(--fw-bg-input)]"
                />
              </label>

              <label className="block space-y-1.5">
                <span className="font-medium text-[var(--fw-text-body)]">
                  Limite de Logs por Hora (0 = off)
                </span>
                <input
                  type="number"
                  min={0}
                  max={100000000}
                  step={1000}
                  value={draftSettings.hourlyLogVolumeLimit}
                  onChange={(e) =>
                    setDraftSettings((s) => ({
                      ...s,
                      hourlyLogVolumeLimit: Math.max(0, Number(e.target.value) || 0),
                    }))
                  }
                  placeholder="Ex: 500"
                  className="w-full px-3 py-1.5 border border-[var(--fw-border-strong)] rounded font-mono tabular-nums text-[var(--fw-heading)] bg-[var(--fw-bg-input)]"
                />
              </label>
            </div>
          </div>

          <div className="pt-3 border-t border-[var(--fw-border-soft)] space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <p className="text-[11px] font-semibold uppercase tracking-wider text-[var(--fw-text-subtle)]">
                2. Detecção de Anomalias nos Logs
              </p>
              <label className="inline-flex items-center gap-2 text-xs font-medium text-[var(--fw-heading)] cursor-pointer">
                <input
                  type="checkbox"
                  checked={draftSettings.anomalyDetectionEnabled}
                  onChange={(e) =>
                    setDraftSettings((s) => ({
                      ...s,
                      anomalyDetectionEnabled: e.target.checked,
                    }))
                  }
                  className="rounded border-[var(--fw-border-strong)] accent-[var(--fw-accent)]"
                />
                Ativar detecção automática de picos e varreduras multi-porta
              </label>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4 text-xs">
              <label className="block space-y-1.5">
                <span className="font-medium text-[var(--fw-text-body)]">
                  Multiplicador de Pico Horário (x)
                </span>
                <input
                  type="number"
                  min={1.2}
                  max={20}
                  step={0.5}
                  disabled={!draftSettings.anomalyDetectionEnabled}
                  value={draftSettings.anomalySpikeMultiplier}
                  onChange={(e) =>
                    setDraftSettings((s) => ({
                      ...s,
                      anomalySpikeMultiplier: Math.max(1.2, Number(e.target.value) || 3),
                    }))
                  }
                  className="w-full px-3 py-1.5 border border-[var(--fw-border-strong)] rounded font-mono tabular-nums text-[var(--fw-heading)] bg-[var(--fw-bg-input)] disabled:opacity-50"
                />
              </label>

              <label className="block space-y-1.5">
                <span className="font-medium text-[var(--fw-text-body)]">
                  Taxa de Bloqueio Anômala (%, 0 = off)
                </span>
                <input
                  type="number"
                  min={0}
                  max={100}
                  step={5}
                  value={draftSettings.blockedTrafficRatioLimitPercent}
                  onChange={(e) =>
                    setDraftSettings((s) => ({
                      ...s,
                      blockedTrafficRatioLimitPercent: Math.max(0, Number(e.target.value) || 0),
                    }))
                  }
                  className="w-full px-3 py-1.5 border border-[var(--fw-border-strong)] rounded font-mono tabular-nums text-[var(--fw-heading)] bg-[var(--fw-bg-input)]"
                />
              </label>

              <label className="block space-y-1.5">
                <span className="font-medium text-[var(--fw-text-body)]">
                  Port Scan: Portas Únicas/IP (0 = off)
                </span>
                <input
                  type="number"
                  min={0}
                  max={10000}
                  step={1}
                  disabled={!draftSettings.anomalyDetectionEnabled}
                  value={draftSettings.portScanUniquePortsThreshold}
                  onChange={(e) =>
                    setDraftSettings((s) => ({
                      ...s,
                      portScanUniquePortsThreshold: Math.max(0, Number(e.target.value) || 0),
                    }))
                  }
                  className="w-full px-3 py-1.5 border border-[var(--fw-border-strong)] rounded font-mono tabular-nums text-[var(--fw-heading)] bg-[var(--fw-bg-input)] disabled:opacity-50"
                />
              </label>

              <label className="block space-y-1.5">
                <span className="font-medium text-[var(--fw-text-body)]">
                  Bloqueios Suspeitos por IP
                </span>
                <input
                  type="number"
                  min={1}
                  max={1000000}
                  value={draftSettings.suspiciousBlockThreshold}
                  onChange={(e) =>
                    setDraftSettings((s) => ({
                      ...s,
                      suspiciousBlockThreshold: Math.max(1, Number(e.target.value) || 1),
                    }))
                  }
                  className="w-full px-3 py-1.5 border border-[var(--fw-border-strong)] rounded font-mono tabular-nums text-[var(--fw-heading)] bg-[var(--fw-bg-input)]"
                />
              </label>
            </div>
          </div>

          <div className="pt-3 border-t border-[var(--fw-border-soft)] space-y-3">
            <p className="text-[11px] font-semibold uppercase tracking-wider text-[var(--fw-text-subtle)]">
              3. Saúde do Firewall e da Coleta
            </p>
            <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-5 gap-4 text-xs">
              <label className="block space-y-1.5">
                <span className="font-medium text-[var(--fw-text-body)]">Janela de Análise (min)</span>
                <input
                  type="number"
                  min={5}
                  max={1440}
                  step={5}
                  value={draftSettings.alertWindowMinutes}
                  onChange={(e) =>
                    setDraftSettings((s) => ({ ...s, alertWindowMinutes: Math.max(0, Number(e.target.value) || 0) }))
                  }
                  className={numberInputClass}
                />
              </label>
              <label className="block space-y-1.5">
                <span className="font-medium text-[var(--fw-text-body)]">CPU (%, 0 = off)</span>
                <input
                  type="number"
                  min={0}
                  max={100}
                  step={5}
                  value={draftSettings.cpuLimitPercent}
                  onChange={(e) =>
                    setDraftSettings((s) => ({ ...s, cpuLimitPercent: Math.max(0, Number(e.target.value) || 0) }))
                  }
                  className={numberInputClass}
                />
              </label>
              <label className="block space-y-1.5">
                <span className="font-medium text-[var(--fw-text-body)]">Memória (%, 0 = off)</span>
                <input
                  type="number"
                  min={0}
                  max={100}
                  step={5}
                  value={draftSettings.memoryLimitPercent}
                  onChange={(e) =>
                    setDraftSettings((s) => ({ ...s, memoryLimitPercent: Math.max(0, Number(e.target.value) || 0) }))
                  }
                  className={numberInputClass}
                />
              </label>
              <label className="block space-y-1.5">
                <span className="font-medium text-[var(--fw-text-body)]">Sem Logs há (min, 0 = off)</span>
                <input
                  type="number"
                  min={0}
                  max={1440}
                  step={1}
                  value={draftSettings.silenceMinutes}
                  onChange={(e) =>
                    setDraftSettings((s) => ({ ...s, silenceMinutes: Math.max(0, Number(e.target.value) || 0) }))
                  }
                  className={numberInputClass}
                />
              </label>
              <label className="block space-y-1.5">
                <span className="font-medium text-[var(--fw-text-body)]">Falhas de Login (0 = off)</span>
                <input
                  type="number"
                  min={0}
                  max={10000}
                  step={1}
                  value={draftSettings.adminLoginFailureThreshold}
                  onChange={(e) =>
                    setDraftSettings((s) => ({ ...s, adminLoginFailureThreshold: Math.max(0, Number(e.target.value) || 0) }))
                  }
                  className={numberInputClass}
                />
              </label>
            </div>
            <div className="flex flex-wrap items-center gap-5 text-xs">
              <label className="inline-flex items-center gap-2 text-[var(--fw-text-body)] cursor-pointer">
                <input
                  type="checkbox"
                  checked={draftSettings.alertOnVpnDown}
                  onChange={(e) => setDraftSettings((s) => ({ ...s, alertOnVpnDown: e.target.checked }))}
                  className="rounded border-[var(--fw-border-strong)] accent-[var(--fw-accent)]"
                />
                Túnel VPN fora do ar
              </label>
              <label className="inline-flex items-center gap-2 text-[var(--fw-text-body)] cursor-pointer">
                <input
                  type="checkbox"
                  checked={draftSettings.alertOnLicense}
                  onChange={(e) => setDraftSettings((s) => ({ ...s, alertOnLicense: e.target.checked }))}
                  className="rounded border-[var(--fw-border-strong)] accent-[var(--fw-accent)]"
                />
                Licença vencida ou vencendo
              </label>
              <label className="inline-flex items-center gap-2 text-[var(--fw-text-body)] cursor-pointer">
                <input
                  type="checkbox"
                  checked={draftSettings.alertOnConfigChange}
                  onChange={(e) => setDraftSettings((s) => ({ ...s, alertOnConfigChange: e.target.checked }))}
                  className="rounded border-[var(--fw-border-strong)] accent-[var(--fw-accent)]"
                />
                Mudança de regras / NAT entre coletas
              </label>
            </div>
          </div>

          <div className="pt-3 border-t border-[var(--fw-border-soft)] space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <p className="text-[11px] font-semibold uppercase tracking-wider text-[var(--fw-text-subtle)]">
                4. Notificações Externas (todos os firewalls)
              </p>
              {notifFeedback && (
                <span
                  className={`text-xs font-medium ${
                    notifFeedback.type === 'ok' ? 'text-emerald-800' : 'text-red-700'
                  }`}
                >
                  {notifFeedback.text}
                </span>
              )}
            </div>
            {notifConfig ? (
              <div className="space-y-3 text-xs">
                <div className="flex flex-wrap items-center gap-5">
                  <label className="inline-flex items-center gap-2 font-medium text-[var(--fw-heading)] cursor-pointer">
                    <input
                      type="checkbox"
                      checked={notifConfig.enabled}
                      disabled={notifBusy}
                      onChange={(e) => void saveNotifications({ enabled: e.target.checked })}
                      className="rounded border-[var(--fw-border-strong)] accent-[var(--fw-accent)]"
                    />
                    Enviar novos alertas para os canais abaixo
                  </label>
                  <label className="inline-flex items-center gap-2 text-[var(--fw-text-body)]">
                    Severidade mínima
                    <select
                      value={notifConfig.minSeverity}
                      disabled={notifBusy}
                      onChange={(e) => void saveNotifications({ minSeverity: e.target.value })}
                      className="px-2 py-1 border border-[var(--fw-border-strong)] rounded bg-[var(--fw-bg-input)] text-[var(--fw-heading)]"
                    >
                      <option value="critical">Somente críticos</option>
                      <option value="warning">Críticos e avisos</option>
                    </select>
                  </label>
                  <label className="inline-flex items-center gap-2 text-[var(--fw-text-body)] cursor-pointer">
                    <input
                      type="checkbox"
                      checked={notifConfig.notifyOnResolve}
                      disabled={notifBusy}
                      onChange={(e) => void saveNotifications({ notifyOnResolve: e.target.checked })}
                      className="rounded border-[var(--fw-border-strong)] accent-[var(--fw-accent)]"
                    />
                    Avisar quando resolver
                  </label>
                </div>
                <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
                  <label className="block space-y-1.5">
                    <span className="font-medium text-[var(--fw-text-body)]">
                      Webhook (Slack, Teams, Discord, n8n){' '}
                      {notifConfig.hasWebhook && <span className="text-emerald-800">· configurado</span>}
                    </span>
                    <input
                      type="url"
                      value={notifWebhook}
                      onChange={(e) => setNotifWebhook(e.target.value)}
                      placeholder={notifConfig.hasWebhook ? 'Informe para substituir' : 'https://...'}
                      className={numberInputClass}
                    />
                  </label>
                  <label className="block space-y-1.5">
                    <span className="font-medium text-[var(--fw-text-body)]">
                      Telegram: token do bot{' '}
                      {notifConfig.hasTelegram && <span className="text-emerald-800">· configurado</span>}
                    </span>
                    <input
                      type="password"
                      autoComplete="off"
                      value={notifTgToken}
                      onChange={(e) => setNotifTgToken(e.target.value)}
                      placeholder={notifConfig.hasTelegram ? 'Informe para substituir' : '123456:ABC...'}
                      className={numberInputClass}
                    />
                  </label>
                  <label className="block space-y-1.5">
                    <span className="font-medium text-[var(--fw-text-body)]">Telegram: chat ID</span>
                    <input
                      type="text"
                      value={notifTgChat}
                      onChange={(e) => setNotifTgChat(e.target.value)}
                      placeholder="-1001234567890"
                      className={numberInputClass}
                    />
                  </label>
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <button
                    type="button"
                    disabled={notifBusy}
                    onClick={() =>
                      void saveNotifications({
                        webhookUrl: notifWebhook,
                        telegramBotToken: notifTgToken,
                        telegramChatId: notifTgChat,
                      })
                    }
                    className="px-3 py-1.5 text-xs font-medium text-white bg-[var(--fw-accent)] rounded-md hover:bg-[var(--fw-accent-hover)] disabled:opacity-50"
                  >
                    Salvar Canais
                  </button>
                  <button
                    type="button"
                    disabled={notifBusy || (!notifConfig.hasWebhook && !notifConfig.hasTelegram)}
                    onClick={() => void testNotifications()}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-[var(--fw-text-body)] bg-white border border-[var(--fw-border-strong)] rounded-md hover:bg-[var(--fw-bg)] disabled:opacity-50"
                  >
                    <Send className="w-3.5 h-3.5" />
                    Enviar Teste
                  </button>
                  {notifConfig.hasWebhook && (
                    <button
                      type="button"
                      disabled={notifBusy}
                      onClick={() => void saveNotifications({ clearWebhook: true })}
                      className="px-3 py-1.5 text-xs font-medium text-red-700 hover:underline"
                    >
                      Remover webhook
                    </button>
                  )}
                  {notifConfig.hasTelegram && (
                    <button
                      type="button"
                      disabled={notifBusy}
                      onClick={() => void saveNotifications({ clearTelegram: true })}
                      className="px-3 py-1.5 text-xs font-medium text-red-700 hover:underline"
                    >
                      Remover Telegram
                    </button>
                  )}
                </div>
              </div>
            ) : (
              <p className="text-xs text-[var(--fw-text-muted)]">Carregando configuração...</p>
            )}
          </div>

          <div className="flex flex-wrap items-center justify-between gap-4 pt-3 border-t border-[var(--fw-border-soft)] text-xs">
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
              className="px-4 py-1.5 text-xs font-medium text-white bg-[var(--fw-accent)] rounded-md hover:bg-[var(--fw-accent-hover)] disabled:opacity-50 whitespace-nowrap"
            >
              {savingConfig ? 'Aplicando...' : 'Aplicar Limites'}
            </button>
          </div>
        </div>
      )}

      {listedAlerts.length > 0 && (
        <>
          <div className="flex flex-wrap items-center gap-1.5 text-xs">
            {(
              [
                { id: 'all', label: `Todos (${activeAlerts.length})` },
                {
                  id: 'traffic-anomaly',
                  label: `Tráfego & Anomalias (${activeAlerts.filter((a) => a.category === 'traffic-volume' || a.category === 'anomaly').length})`,
                },
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
                  label: `Falhas & Suspeitos (${activeAlerts.filter((a) => LOG_CATEGORIES.has(a.category)).length})`,
                },
                {
                  id: 'infra',
                  label: `Infra & Coleta (${activeAlerts.filter((a) => INFRA_CATEGORIES.has(a.category)).length})`,
                },
              ] as Array<{ id: CategoryFilter; label: string }>
            ).map((tab) => (
              <button
                key={tab.id}
                type="button"
                onClick={() => setCategoryFilter(tab.id)}
                className={`px-2.5 py-1 rounded border text-xs font-medium transition-colors whitespace-nowrap ${
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
                const isAcked = alert.status === 'acknowledged';
                return (
                  <div
                    key={alert.key ?? alert.id}
                    className={`bg-white border rounded-md px-4 py-3 flex flex-wrap items-start justify-between gap-3 ${
                      isAcked ? 'border-[var(--fw-border)] opacity-70' : isCritical ? 'border-red-300' : 'border-amber-300'
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
                            {getAlertCategoryLabel(alert.category)}
                          </span>
                          <span className="text-[var(--fw-text-faint)]" aria-hidden="true">
                            ·
                          </span>
                          <span className="font-mono tabular-nums font-semibold text-[var(--fw-heading)]">
                            {alert.metricValue}
                          </span>
                          {(alert.firstSeenAt || alert.lastSeenAt) && (
                            <>
                              <span className="text-[var(--fw-text-faint)]" aria-hidden="true">
                                ·
                              </span>
                              <span className="font-mono text-[11px] text-[var(--fw-text-subtle)] tabular-nums">
                                {alert.firstSeenAt
                                  ? `desde ${formatAlertTime(alert.firstSeenAt)}`
                                  : alert.lastSeenAt}
                              </span>
                            </>
                          )}
                          {isAcked && (
                            <span className="text-[11px] font-medium text-[var(--fw-text-subtle)]">
                              · reconhecido por {alert.acknowledgedBy || 'admin'}
                            </span>
                          )}
                        </div>
                        <p className="text-xs font-semibold text-[var(--fw-heading)]">
                          {alert.title}
                        </p>
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
                          className="inline-flex items-center gap-1 px-2.5 py-1.5 text-xs font-medium text-[var(--fw-text-body)] bg-[var(--fw-bg)] border border-[var(--fw-border-strong)] rounded hover:bg-[var(--fw-surface)] whitespace-nowrap"
                        >
                          <Search className="w-3.5 h-3.5" />
                          Ver Logs
                        </button>
                      )}
                      {alert.aiPrompt && (
                        <button
                          type="button"
                          onClick={() => onAnalyzeWithAi(alert.aiPrompt || '')}
                          className="inline-flex items-center gap-1 px-2.5 py-1.5 text-xs font-medium text-white bg-[var(--fw-accent)] rounded hover:bg-[var(--fw-accent-hover)] whitespace-nowrap"
                        >
                          <Bot className="w-3.5 h-3.5" />
                          Analisar IA
                        </button>
                      )}
                      {(alert.category === 'bandwidth' ||
                        alert.category === 'link-down' ||
                        alert.category === 'traffic-volume' ||
                        alert.category === 'anomaly') && (
                        <button
                          type="button"
                          onClick={() => setShowConfig(true)}
                          className="inline-flex items-center gap-1 px-2.5 py-1.5 text-xs font-medium text-[var(--fw-text-body)] bg-[var(--fw-bg)] border border-[var(--fw-border-strong)] rounded hover:bg-[var(--fw-surface)] whitespace-nowrap"
                        >
                          <Settings2 className="w-3.5 h-3.5" />
                          Ajustar Critério
                        </button>
                      )}
                      {isAcked ? (
                        <button
                          type="button"
                          onClick={() => void setAck(alert, false)}
                          className="inline-flex items-center gap-1 px-2.5 py-1.5 text-xs font-medium text-[var(--fw-text-body)] bg-[var(--fw-bg)] border border-[var(--fw-border-strong)] rounded hover:bg-[var(--fw-surface)] whitespace-nowrap"
                        >
                          <RotateCcw className="w-3.5 h-3.5" />
                          Reabrir
                        </button>
                      ) : (
                        <button
                          type="button"
                          onClick={() => handleDismiss(alert)}
                          title="Reconhecer: sai da lista até ser resolvido (vale para todos os usuários)"
                          aria-label={`Reconhecer ${alert.title}`}
                          className="inline-flex items-center gap-1 px-2.5 py-1.5 text-xs font-medium text-[var(--fw-text-body)] bg-[var(--fw-bg)] border border-[var(--fw-border-strong)] rounded hover:bg-[var(--fw-surface)] whitespace-nowrap"
                        >
                          {alert.key ? <Check className="w-3.5 h-3.5" /> : <X className="w-3.5 h-3.5" />}
                          Reconhecer
                        </button>
                      )}
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
