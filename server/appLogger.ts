import crypto from 'node:crypto';
import type { AppLogEntry, AppLogLevel, FirewallVendor } from './types.ts';

const MAX_APP_LOGS = 300;

class AppLogger {
  private entries: AppLogEntry[] = [];

  log(
    level: AppLogLevel,
    vendor: FirewallVendor | 'system',
    scope: string,
    message: string,
    detail?: string
  ): void {
    const entry: AppLogEntry = {
      id: crypto.randomUUID(),
      ts: new Date().toISOString(),
      level,
      vendor,
      scope,
      message,
      ...(detail ? { detail: detail.slice(0, 1000) } : {}),
    };
    this.entries.unshift(entry);
    if (this.entries.length > MAX_APP_LOGS) {
      this.entries.length = MAX_APP_LOGS;
    }

    const prefix = `[${vendor}][${scope}] ${message}${detail ? ` — ${detail}` : ''}`;
    if (level === 'error') console.error(prefix);
    else if (level === 'warn') console.warn(prefix);
    else console.log(prefix);
  }

  info(vendor: FirewallVendor | 'system', scope: string, message: string, detail?: string): void {
    this.log('info', vendor, scope, message, detail);
  }

  warn(vendor: FirewallVendor | 'system', scope: string, message: string, detail?: string): void {
    this.log('warn', vendor, scope, message, detail);
  }

  error(vendor: FirewallVendor | 'system', scope: string, message: string, detail?: string): void {
    this.log('error', vendor, scope, message, detail);
  }

  list(opts?: {
    vendor?: FirewallVendor;
    level?: AppLogLevel | 'all';
    search?: string;
    limit?: number;
  }): AppLogEntry[] {
    const level = opts?.level || 'all';
    const search = (opts?.search || '').trim().toLowerCase();
    const limit = Math.max(1, Math.min(300, opts?.limit ?? 150));

    return this.entries
      .filter((e) => {
        if (opts?.vendor && e.vendor !== opts.vendor && e.vendor !== 'system') return false;
        if (level !== 'all' && e.level !== level) return false;
        if (search) {
          const hay = `${e.scope} ${e.message} ${e.detail || ''}`.toLowerCase();
          if (!hay.includes(search)) return false;
        }
        return true;
      })
      .slice(0, limit);
  }

  clear(vendor?: FirewallVendor): void {
    if (!vendor) {
      this.entries = [];
      return;
    }
    this.entries = this.entries.filter((e) => e.vendor !== vendor);
  }
}

export const appLog = new AppLogger();
