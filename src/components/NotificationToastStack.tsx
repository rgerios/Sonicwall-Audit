import { useEffect, useRef, useState } from 'react';
import {
  Activity,
  AlertOctagon,
  AlertTriangle,
  BarChart3,
  BellOff,
  Bot,
  Bug,
  Gauge,
  Radar,
  Search,
  ShieldAlert,
  TrendingUp,
  WifiOff,
  X,
} from 'lucide-react';
import type { AuditOverview, FirewallVendor, OverviewAlert } from '../types.ts';
import {
  DISMISSED_ALERTS_EVENT,
  REEVALUATE_TOASTS_EVENT,
  dismissAlertKey,
  getAlertCategoryLabel,
  getAlertFingerprint,
  loadDismissedAlertKeys,
} from '../utils/alertHelpers.ts';

interface NotificationToastStackProps {
  vendor: FirewallVendor;
  overview: AuditOverview | null;
  onViewAlerts: () => void;
  onInvestigateSyslog: (query: string) => void;
  onAnalyzeWithAi: (prompt: string) => void;
}

interface ToastEntry {
  toastId: string;
  alert: OverviewAlert;
  createdAt: number;
}

function renderToastIcon(alert: OverviewAlert) {
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

export function NotificationToastStack({
  vendor,
  overview,
  onViewAlerts,
  onInvestigateSyslog,
  onAnalyzeWithAi,
}: NotificationToastStackProps) {
  const [dismissedKeys, setDismissedKeys] = useState<string[]>(() => loadDismissedAlertKeys(vendor));
  const [toasts, setToasts] = useState<ToastEntry[]>([]);
  const [hiddenOverflowCount, setHiddenOverflowCount] = useState(0);
  const [isHovering, setIsHovering] = useState(false);

  const seenScopedFingerprintsRef = useRef<Set<string>>(new Set());
  const currentScope = `${vendor}:${overview?.activeSite?.id ?? 'none'}`;

  useEffect(() => {
    setDismissedKeys(loadDismissedAlertKeys(vendor));
    setToasts([]);
    setHiddenOverflowCount(0);
  }, [vendor, overview?.activeSite?.id]);

  useEffect(() => {
    const onDismissedSync = (event: Event) => {
      const detail = (event as CustomEvent<{ vendor: FirewallVendor; keys: string[] }>).detail;
      if (detail?.vendor === vendor) {
        setDismissedKeys(detail.keys);
        const dismissedSet = new Set(detail.keys);
        setToasts((prev) => prev.filter((t) => !dismissedSet.has(getAlertFingerprint(t.alert))));
      }
    };
    window.addEventListener(DISMISSED_ALERTS_EVENT, onDismissedSync);
    return () => window.removeEventListener(DISMISSED_ALERTS_EVENT, onDismissedSync);
  }, [vendor]);

  useEffect(() => {
    const onForceReevaluate = () => {
      // Clear seen alerts for current scope so breached rules immediately pop as visual notifications
      const prefix = `${currentScope}|`;
      for (const key of Array.from(seenScopedFingerprintsRef.current)) {
        if (key.startsWith(prefix)) {
          seenScopedFingerprintsRef.current.delete(key);
        }
      }
    };
    window.addEventListener(REEVALUATE_TOASTS_EVENT, onForceReevaluate);
    return () => window.removeEventListener(REEVALUATE_TOASTS_EVENT, onForceReevaluate);
  }, [currentScope]);

  useEffect(() => {
    if (!overview) return;
    const alerts = overview.alerts ?? [];
    const dismissedSet = new Set(dismissedKeys);
    const activeAlerts = alerts.filter(
      (a) => a.status !== 'acknowledged' && !dismissedSet.has(getAlertFingerprint(a))
    );

    const newlyTriggered: OverviewAlert[] = [];
    for (const alert of activeAlerts) {
      const scopedKey = `${currentScope}|${getAlertFingerprint(alert)}`;
      if (!seenScopedFingerprintsRef.current.has(scopedKey)) {
        seenScopedFingerprintsRef.current.add(scopedKey);
        newlyTriggered.push(alert);
      }
    }

    if (newlyTriggered.length === 0) return;

    const topIncoming = newlyTriggered.slice(0, 3);
    const overflow = Math.max(0, newlyTriggered.length - 3);
    setHiddenOverflowCount(overflow);

    setToasts((prev) => {
      const now = Date.now();
      const existingIds = new Set(prev.map((t) => t.alert.id));
      const additions: ToastEntry[] = topIncoming
        .filter((a) => !existingIds.has(a.id))
        .map((alert) => ({
          toastId: `${currentScope}|${getAlertFingerprint(alert)}|${now}`,
          alert,
          createdAt: now,
        }));
      const updatedPrev = prev.map((entry) => {
        const refreshed = topIncoming.find((a) => a.id === entry.alert.id);
        return refreshed ? { ...entry, alert: refreshed, createdAt: now } : entry;
      });
      return [...additions, ...updatedPrev].slice(0, 3);
    });
  }, [overview, currentScope, dismissedKeys]);

  // Auto-dismiss toasts after 12 seconds unless hovered
  useEffect(() => {
    if (toasts.length === 0 || isHovering) return;
    const timer = setInterval(() => {
      const now = Date.now();
      setToasts((prev) => prev.filter((t) => now - t.createdAt < 12000));
    }, 1000);
    return () => clearInterval(timer);
  }, [toasts.length, isHovering]);

  if (toasts.length === 0) return null;

  const closeToast = (toastId: string) => {
    setToasts((prev) => prev.filter((t) => t.toastId !== toastId));
  };

  const silenceToast = (toast: ToastEntry) => {
    dismissAlertKey(vendor, getAlertFingerprint(toast.alert));
    closeToast(toast.toastId);
  };

  return (
    <div
      role="region"
      aria-label="Notificações visuais de tráfego e anomalias"
      onMouseEnter={() => setIsHovering(true)}
      onMouseLeave={() => setIsHovering(false)}
      className="fixed bottom-5 right-5 z-40 w-[min(25rem,calc(100vw-2rem))] space-y-2.5 pointer-events-none"
    >
      {toasts.length > 1 && (
        <div className="flex items-center justify-end pointer-events-auto">
          <button
            type="button"
            onClick={() => {
              setToasts([]);
              setHiddenOverflowCount(0);
            }}
            className="px-2.5 py-1 text-[11px] font-medium bg-white border border-[var(--fw-border-strong)] rounded-md text-[var(--fw-text-body)] hover:bg-[var(--fw-surface)] shadow-sm"
          >
            Dispensar todas ({toasts.length})
          </button>
        </div>
      )}

      {toasts.map((entry) => {
        const { alert } = entry;
        const isCritical = alert.severity === 'critical';
        return (
          <div
            key={entry.toastId}
            role={isCritical ? 'alert' : 'status'}
            className={`pointer-events-auto bg-white border rounded-lg p-3.5 shadow-lg space-y-2 ${
              isCritical ? 'border-red-300' : 'border-amber-300'
            }`}
          >
            <div className="flex items-start justify-between gap-2">
              <div className="flex items-center gap-2 min-w-0 text-xs">
                {renderToastIcon(alert)}
                <span
                  className={`font-mono font-bold tracking-wide shrink-0 ${
                    isCritical ? 'text-red-700' : 'text-amber-800'
                  }`}
                >
                  {isCritical ? 'CRÍTICO' : 'AVISO'}
                </span>
                <span className="text-[var(--fw-text-faint)]" aria-hidden="true">
                  ·
                </span>
                <span className="font-medium text-[var(--fw-text-body)] truncate">
                  {getAlertCategoryLabel(alert.category)}
                </span>
              </div>

              <div className="flex items-center gap-1.5 shrink-0">
                <span className="font-mono text-[11px] font-semibold text-[var(--fw-heading)] tabular-nums">
                  {alert.metricValue}
                </span>
                <button
                  type="button"
                  onClick={() => closeToast(entry.toastId)}
                  aria-label="Fechar notificação"
                  className="p-1 text-[var(--fw-text-subtle)] hover:text-[var(--fw-heading)] rounded hover:bg-[var(--fw-surface)]"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>

            <div className="space-y-1">
              <p className="text-xs font-semibold text-[var(--fw-heading)] leading-snug">
                {alert.title}
              </p>
              <p className="text-[11px] text-[var(--fw-text-muted)] leading-relaxed line-clamp-2">
                {alert.description}
              </p>
            </div>

            <div className="flex flex-wrap items-center justify-between gap-2 pt-1 border-t border-[var(--fw-border-soft)]">
              <div className="flex items-center gap-1.5">
                {alert.syslogFilterQuery && (
                  <button
                    type="button"
                    onClick={() => {
                      onInvestigateSyslog(alert.syslogFilterQuery || '');
                      closeToast(entry.toastId);
                    }}
                    className="inline-flex items-center gap-1 px-2 py-1 text-[11px] font-medium text-[var(--fw-text-body)] bg-[var(--fw-bg)] border border-[var(--fw-border-strong)] rounded hover:bg-[var(--fw-surface)]"
                  >
                    <Search className="w-3 h-3" />
                    Ver Logs
                  </button>
                )}
                {alert.aiPrompt && (
                  <button
                    type="button"
                    onClick={() => {
                      onAnalyzeWithAi(alert.aiPrompt || '');
                      closeToast(entry.toastId);
                    }}
                    className="inline-flex items-center gap-1 px-2 py-1 text-[11px] font-medium text-white bg-[var(--fw-accent)] rounded hover:bg-[var(--fw-accent-hover)]"
                  >
                    <Bot className="w-3 h-3" />
                    IA
                  </button>
                )}
                <button
                  type="button"
                  onClick={() => {
                    onViewAlerts();
                    closeToast(entry.toastId);
                  }}
                  className="inline-flex items-center gap-1 px-2 py-1 text-[11px] font-medium text-[var(--fw-accent)] hover:underline"
                >
                  <AlertTriangle className="w-3 h-3" />
                  Painel
                </button>
              </div>

              <button
                type="button"
                onClick={() => silenceToast(toastToSilence(entry))}
                title="Silenciar alerta recorrente"
                className="inline-flex items-center gap-1 text-[11px] text-[var(--fw-text-subtle)] hover:text-[var(--fw-heading)]"
              >
                <BellOff className="w-3 h-3" />
                Silenciar
              </button>
            </div>
          </div>
        );
      })}

      {hiddenOverflowCount > 0 && (
        <div className="pointer-events-auto bg-white border border-[var(--fw-border-strong)] rounded-md px-3 py-2 shadow-sm flex items-center justify-between text-[11px]">
          <span className="text-[var(--fw-text-muted)] font-mono tabular-nums">
            +{hiddenOverflowCount} outro(s) alerta(s) ativo(s)
          </span>
          <button
            type="button"
            onClick={() => {
              onViewAlerts();
              setHiddenOverflowCount(0);
            }}
            className="font-semibold text-[var(--fw-accent)] hover:underline"
          >
            Ver todos
          </button>
        </div>
      )}
    </div>
  );
}

function toastToSilence(entry: ToastEntry): ToastEntry {
  return entry;
}
