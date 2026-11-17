import http from 'node:http';
import https from 'node:https';

const httpKeepAliveAgent = new http.Agent({ keepAlive: true, maxSockets: 16 });
const httpsStrictAgent = new https.Agent({
  keepAlive: true,
  maxSockets: 16,
  rejectUnauthorized: true,
});
const httpsInsecureAgent = new https.Agent({
  keepAlive: true,
  maxSockets: 16,
  rejectUnauthorized: false,
});

export function getTransportAgent(
  isHttps: boolean,
  ignoreTlsErrors: boolean
): http.Agent | https.Agent {
  if (!isHttps) return httpKeepAliveAgent;
  return ignoreTlsErrors ? httpsInsecureAgent : httpsStrictAgent;
}

export function asRecord(val: unknown): Record<string, unknown> {
  return val && typeof val === 'object' && !Array.isArray(val)
    ? (val as Record<string, unknown>)
    : {};
}

export function pickNumber(obj: Record<string, unknown>, keys: string[]): number | null {
  for (const k of keys) {
    const raw = obj[k];
    if (typeof raw === 'number' && Number.isFinite(raw)) return raw;
    if (typeof raw === 'string' && raw.trim()) {
      const cleaned = raw.replace(/[^0-9.\-]/g, '');
      if (cleaned) {
        const num = Number(cleaned);
        if (Number.isFinite(num)) return num;
      }
    }
  }
  return null;
}

export function pickString(obj: Record<string, unknown>, keys: string[]): string {
  for (const k of keys) {
    const raw = obj[k];
    if (typeof raw === 'string' && raw.trim()) return raw.trim();
  }
  return '';
}

export function formatUptimeSeconds(totalSeconds: number): string {
  if (!Number.isFinite(totalSeconds) || totalSeconds <= 0) return '-';
  const days = Math.floor(totalSeconds / 86400);
  const hours = Math.floor((totalSeconds % 86400) / 3600);
  const mins = Math.floor((totalSeconds % 3600) / 60);
  const parts: string[] = [];
  if (days > 0) parts.push(`${days}d`);
  parts.push(`${hours}h`);
  parts.push(`${mins}m`);
  return parts.join(' ');
}
