import type { AlertCategory, FirewallVendor, OverviewAlert } from '../types.ts';

export const DISMISSED_ALERTS_EVENT = 'fwaudit:alerts-dismissed';
export const REEVALUATE_TOASTS_EVENT = 'fwaudit:reevaluate-toasts';

export function getDismissedStorageKey(vendor: FirewallVendor): string {
  return `fwaudit_dismissed_alerts_v1_${vendor}`;
}

export function getAlertFingerprint(alert: OverviewAlert): string {
  return `${alert.id}|${alert.metricValue}`;
}

export function loadDismissedAlertKeys(vendor: FirewallVendor): string[] {
  try {
    const raw = localStorage.getItem(getDismissedStorageKey(vendor));
    if (!raw) return [];
    const parsed = JSON.parse(raw) as unknown;
    return Array.isArray(parsed) ? parsed.filter((x): x is string => typeof x === 'string') : [];
  } catch {
    return [];
  }
}

export function saveDismissedAlertKeys(vendor: FirewallVendor, keys: string[]): void {
  try {
    localStorage.setItem(getDismissedStorageKey(vendor), JSON.stringify(keys));
  } catch {
    // Ignore storage quota / private mode issues
  }
  window.dispatchEvent(new CustomEvent(DISMISSED_ALERTS_EVENT, { detail: { vendor, keys } }));
}

export function dismissAlertKey(vendor: FirewallVendor, key: string): string[] {
  const current = loadDismissedAlertKeys(vendor);
  if (current.includes(key)) return current;
  const next = [...current, key];
  saveDismissedAlertKeys(vendor, next);
  return next;
}

export function restoreAllDismissedAlerts(vendor: FirewallVendor): string[] {
  saveDismissedAlertKeys(vendor, []);
  return [];
}

export function getAlertCategoryLabel(cat: AlertCategory): string {
  switch (cat) {
    case 'bandwidth':
      return 'Uso de Banda';
    case 'link-down':
      return 'Link Offline';
    case 'traffic-volume':
      return 'Limite de Tráfego';
    case 'anomaly':
      return 'Anomalia nos Logs';
    case 'ips':
      return 'IPS / Origem Maliciosa';
    case 'malware':
      return 'Malware / Antivírus';
    case 'critical-log':
      return 'Falha Crítica';
    case 'suspicious-traffic':
      return 'Log Suspeito';
    case 'vpn':
      return 'VPN';
    case 'license':
      return 'Licenciamento';
    case 'resource':
      return 'Recursos do Appliance';
    case 'collector':
      return 'Coleta';
    case 'config-change':
      return 'Mudança de Configuração';
    case 'auth':
      return 'Autenticação';
    default:
      return 'Alerta';
  }
}
