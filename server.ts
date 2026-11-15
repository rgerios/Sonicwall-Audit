import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import express from 'express';
import dotenv from 'dotenv';
import {
  DEFAULT_AI_SETTINGS,
  runAiLogAnalysis,
  toPublicAiConfig,
} from './server/aiClient.ts';
import {
  DEFAULT_ALERT_SETTINGS,
  evaluateOverviewAlerts,
  normalizeAlertSettings,
} from './server/alertsEngine.ts';
import { AuthManager } from './server/authManager.ts';
import { PostgresStore } from './server/database.ts';
import {
  correlateTrafficAndRules,
  generateSonicOsCli,
  parseSonicOsJson,
  parseSonicWallExp,
  parseSonicWallSyslog,
} from './server/parsers.ts';
import {
  buildAuditReport,
  renderReportHtml,
  renderReportMarkdown,
} from './server/reportBuilder.ts';
import { createSampleDataset } from './server/sampleData.ts';
import { fetchSonicOsAudit } from './server/sonicosClient.ts';
import { SyslogUdpReceiver } from './server/syslogUdp.ts';
import type {
  AiChatMessage,
  AiProviderSettings,
  AiProviderType,
  ApplianceMetadata,
  AuditOverview,
  DataStore,
  FirewallConnectionPublic,
  FirewallSiteRecord,
  FirewallSiteSummary,
  NatPolicy,
  FirewallRule,
  SyslogEvent,
  TelemetrySnapshot,
} from './server/types.ts';

dotenv.config();

const PORT = Number(process.env.PORT || 3000);
const DATA_DIR = path.resolve(process.cwd(), 'data');
const STORE_FILE = path.join(DATA_DIR, 'store.json');
const MAX_SYSLOG_RETENTION = 15000;
const DEFAULT_RETENTION_DAYS = 10;

const EMPTY_TELEMETRY: TelemetrySnapshot = {
  interfaces: [],
  vpns: [],
  licenses: [],
};

function createEmptySite(id: string, name = 'Localidade Principal', location = 'Matriz'): FirewallSiteRecord {
  const now = new Date().toISOString();
  return {
    id,
    name,
    location,
    notes: '',
    connection: {
      host: '',
      port: 443,
      protocol: 'https',
      username: 'admin',
      ignoreTlsErrors: true,
    },
    appliance: {
      model: 'Nenhum appliance sincronizado',
      serialNumber: '-',
      firmware: '-',
      host: '-',
      lastSyncAt: null,
      dataSource: 'none',
    },
    retentionDays: DEFAULT_RETENTION_DAYS,
    lastPurgeAt: null,
    lastPurgedCount: 0,
    syslogs: [],
    rules: [],
    nats: [],
    telemetry: { ...EMPTY_TELEMETRY },
    alertSettings: { ...DEFAULT_ALERT_SETTINGS },
    createdAt: now,
    updatedAt: now,
  };
}

const DEFAULT_SITE_ID = 'site-default';
let store: DataStore = {
  activeSiteId: DEFAULT_SITE_ID,
  sites: {
    [DEFAULT_SITE_ID]: createEmptySite(DEFAULT_SITE_ID),
  },
  aiSettings: { ...DEFAULT_AI_SETTINGS },
};

const pgStore = new PostgresStore();
const authManager = new AuthManager(DATA_DIR, pgStore);
let cachedStoreSizeBytes = 0;

function getActiveSite(): FirewallSiteRecord {
  const active = store.sites[store.activeSiteId];
  if (active) return active;
  const firstKey = Object.keys(store.sites)[0];
  if (firstKey) {
    store.activeSiteId = firstKey;
    return store.sites[firstKey];
  }
  const fallback = createEmptySite(DEFAULT_SITE_ID);
  store.sites[DEFAULT_SITE_ID] = fallback;
  store.activeSiteId = DEFAULT_SITE_ID;
  return fallback;
}

function toPublicConnection(site: FirewallSiteRecord): FirewallConnectionPublic {
  return {
    host: site.connection.host,
    port: site.connection.port,
    protocol: site.connection.protocol,
    username: site.connection.username,
    hasSavedPassword: Boolean(site.connection.passwordEncrypted),
    ignoreTlsErrors: site.connection.ignoreTlsErrors,
  };
}

function toSiteSummary(site: FirewallSiteRecord): FirewallSiteSummary {
  const alerts = evaluateOverviewAlerts(
    site.telemetry || EMPTY_TELEMETRY,
    site.syslogs,
    normalizeAlertSettings(site.alertSettings)
  );
  return {
    id: site.id,
    name: site.name,
    location: site.location,
    notes: site.notes,
    appliance: site.appliance,
    connection: toPublicConnection(site),
    totalSyslogs: site.syslogs.length,
    rulesCount: site.rules.length,
    natsCount: site.nats.length,
    alertsCount: alerts.length,
    criticalAlertsCount: alerts.filter((a) => a.severity === 'critical').length,
    createdAt: site.createdAt,
    updatedAt: site.updatedAt,
  };
}

function listAllSiteSummaries(): FirewallSiteSummary[] {
  return Object.values(store.sites)
    .map(toSiteSummary)
    .sort((a, b) => a.createdAt.localeCompare(b.createdAt));
}

async function refreshStoreSize(): Promise<void> {
  if (pgStore.isEnabled()) {
    cachedStoreSizeBytes = await pgStore.getDatabaseSizeBytes();
    return;
  }
  try {
    const stat = await fs.stat(STORE_FILE);
    cachedStoreSizeBytes = stat.size;
  } catch {
    cachedStoreSizeBytes = Buffer.byteLength(JSON.stringify(store), 'utf8');
  }
}

function getEventAgeMs(ev: SyslogEvent): number {
  const ingestedMs = Date.parse(ev.ingestedAt || '');
  if (Number.isFinite(ingestedMs)) return ingestedMs;
  const parsedTs = Date.parse(ev.timestamp);
  if (Number.isFinite(parsedTs)) return parsedTs;
  return Date.now();
}

function recomputeCorrelations(site: FirewallSiteRecord): void {
  const correlated = correlateTrafficAndRules(site.rules, site.nats, site.syslogs);
  site.rules = correlated.rules;
  site.nats = correlated.nats;
}

function purgeExpiredSyslogsForSite(site: FirewallSiteRecord, forceTimestampUpdate = false): number {
  const days = Math.max(1, site.retentionDays || DEFAULT_RETENTION_DAYS);
  const cutoffMs = Date.now() - days * 24 * 60 * 60 * 1000;
  const beforeCount = site.syslogs.length;

  const remaining = site.syslogs.filter((ev) => getEventAgeMs(ev) >= cutoffMs);
  const purged = beforeCount - remaining.length;

  if (purged > 0 || forceTimestampUpdate) {
    site.syslogs = remaining;
    site.lastPurgeAt = new Date().toISOString();
    site.lastPurgedCount = purged;
    if (purged > 0) {
      recomputeCorrelations(site);
      schedulePersist({ syslogSiteId: site.id, policySiteId: site.id });
    }
  }
  return purged;
}

function purgeExpiredAcrossAllSites(): void {
  for (const site of Object.values(store.sites)) {
    purgeExpiredSyslogsForSite(site, false);
  }
}

function normalizeLoadedSite(raw: Partial<FirewallSiteRecord>, fallbackId: string): FirewallSiteRecord {
  const base = createEmptySite(raw.id || fallbackId, raw.name || 'Localidade Principal', raw.location || '');
  const normalizedLogs = Array.isArray(raw.syslogs)
    ? raw.syslogs.slice(0, MAX_SYSLOG_RETENTION).map((ev) => ({
        ...ev,
        ingestedAt: ev.ingestedAt || new Date().toISOString(),
      }))
    : [];
  const site: FirewallSiteRecord = {
    ...base,
    id: raw.id || fallbackId,
    name: raw.name || base.name,
    location: typeof raw.location === 'string' ? raw.location : '',
    notes: typeof raw.notes === 'string' ? raw.notes : '',
    connection: raw.connection
      ? {
          host: String(raw.connection.host || ''),
          port: Number(raw.connection.port || 443),
          protocol: raw.connection.protocol === 'http' ? 'http' : 'https',
          username: String(raw.connection.username || 'admin'),
          passwordEncrypted: raw.connection.passwordEncrypted,
          ignoreTlsErrors: raw.connection.ignoreTlsErrors !== false,
        }
      : base.connection,
    appliance: raw.appliance || base.appliance,
    retentionDays:
      typeof raw.retentionDays === 'number' && raw.retentionDays >= 1
        ? raw.retentionDays
        : DEFAULT_RETENTION_DAYS,
    lastPurgeAt: raw.lastPurgeAt ?? null,
    lastPurgedCount: typeof raw.lastPurgedCount === 'number' ? raw.lastPurgedCount : 0,
    syslogs: normalizedLogs,
    rules: Array.isArray(raw.rules) ? raw.rules : [],
    nats: Array.isArray(raw.nats) ? raw.nats : [],
    telemetry: raw.telemetry
      ? {
          interfaces: Array.isArray(raw.telemetry.interfaces) ? raw.telemetry.interfaces : [],
          vpns: Array.isArray(raw.telemetry.vpns) ? raw.telemetry.vpns : [],
          licenses: Array.isArray(raw.telemetry.licenses) ? raw.telemetry.licenses : [],
        }
      : { ...EMPTY_TELEMETRY },
    alertSettings: normalizeAlertSettings(raw.alertSettings),
    createdAt: raw.createdAt || base.createdAt,
    updatedAt: raw.updatedAt || base.updatedAt,
  };
  purgeExpiredSyslogsForSite(site, false);
  recomputeCorrelations(site);
  return site;
}

function hydrateParsedStore(parsed: Record<string, unknown>): void {
  if (parsed && parsed.sites && typeof parsed.sites === 'object' && !Array.isArray(parsed.sites)) {
    const sitesMap: Record<string, FirewallSiteRecord> = {};
    for (const [siteId, rawSite] of Object.entries(parsed.sites as Record<string, Partial<FirewallSiteRecord>>)) {
      if (rawSite && typeof rawSite === 'object') {
        const normalized = normalizeLoadedSite(rawSite, siteId);
        sitesMap[normalized.id] = normalized;
      }
    }
    if (Object.keys(sitesMap).length === 0) {
      sitesMap[DEFAULT_SITE_ID] = createEmptySite(DEFAULT_SITE_ID);
    }
    const activeId =
      typeof parsed.activeSiteId === 'string' && sitesMap[parsed.activeSiteId]
        ? parsed.activeSiteId
        : Object.keys(sitesMap)[0];

    store = {
      activeSiteId: activeId,
      sites: sitesMap,
      aiSettings:
        parsed.aiSettings && typeof parsed.aiSettings === 'object'
          ? { ...DEFAULT_AI_SETTINGS, ...(parsed.aiSettings as Partial<AiProviderSettings>) }
          : { ...DEFAULT_AI_SETTINGS },
    };
  } else if (
    parsed &&
    Array.isArray(parsed.syslogs) &&
    Array.isArray(parsed.rules) &&
    Array.isArray(parsed.nats)
  ) {
    // Seamless migration from legacy single-site store.json
    const migrated = normalizeLoadedSite(
      {
        id: DEFAULT_SITE_ID,
        name: 'Localidade Principal',
        location: 'Matriz',
        appliance: parsed.appliance as ApplianceMetadata | undefined,
        retentionDays: parsed.retentionDays as number | undefined,
        lastPurgeAt: (parsed.lastPurgeAt as string | null) ?? null,
        lastPurgedCount: (parsed.lastPurgedCount as number | undefined) ?? 0,
        syslogs: parsed.syslogs as SyslogEvent[],
        rules: parsed.rules as FirewallRule[],
        nats: parsed.nats as NatPolicy[],
        telemetry: parsed.telemetry as TelemetrySnapshot | undefined,
        alertSettings: parsed.alertSettings as DataStore['sites'][string]['alertSettings'] | undefined,
      },
      DEFAULT_SITE_ID
    );
    store = {
      activeSiteId: DEFAULT_SITE_ID,
      sites: { [DEFAULT_SITE_ID]: migrated },
      aiSettings:
        parsed.aiSettings && typeof parsed.aiSettings === 'object'
          ? { ...DEFAULT_AI_SETTINGS, ...(parsed.aiSettings as Partial<AiProviderSettings>) }
          : { ...DEFAULT_AI_SETTINGS },
    };
  }
}

async function loadStoreFromStorage(): Promise<void> {
  if (pgStore.isEnabled()) {
    const hasSites = await pgStore.hasAnySites();
    if (hasSites) {
      const pgLoaded = await pgStore.loadStore();
      hydrateParsedStore({
        activeSiteId: pgLoaded.activeSiteId ?? undefined,
        aiSettings: pgLoaded.aiSettings ?? undefined,
        sites: pgLoaded.sites,
      });
    } else {
      // Optional one-time migration from ./data/store.json if upgrading to PostgreSQL
      const legacy = await pgStore.maybeReadLegacyJsonFile<Record<string, unknown>>(STORE_FILE);
      if (legacy) {
        hydrateParsedStore(legacy);
      }
      await pgStore.saveFullStore(store);
    }
    await refreshStoreSize();
    return;
  }

  try {
    const content = await fs.readFile(STORE_FILE, 'utf8');
    const parsed = JSON.parse(content) as Record<string, unknown>;
    hydrateParsedStore(parsed);
    await refreshStoreSize();
  } catch {
    await refreshStoreSize();
  }
}

let saveTimer: NodeJS.Timeout | null = null;
const pendingSyslogSiteIds = new Set<string>();
const pendingPolicySiteIds = new Set<string>();

function schedulePersist(opts?: { syslogSiteId?: string; policySiteId?: string }): void {
  if (opts?.syslogSiteId) pendingSyslogSiteIds.add(opts.syslogSiteId);
  if (opts?.policySiteId) pendingPolicySiteIds.add(opts.policySiteId);

  if (saveTimer) clearTimeout(saveTimer);
  saveTimer = setTimeout(async () => {
    const dirtySyslogs = new Set(pendingSyslogSiteIds);
    const dirtyPolicies = new Set(pendingPolicySiteIds);
    pendingSyslogSiteIds.clear();
    pendingPolicySiteIds.clear();

    try {
      if (pgStore.isEnabled()) {
        await pgStore.saveFullStore(store, dirtySyslogs, dirtyPolicies);
        cachedStoreSizeBytes = await pgStore.getDatabaseSizeBytes();
        return;
      }

      await fs.mkdir(DATA_DIR, { recursive: true });
      const serialized = JSON.stringify(store, null, 2);
      await fs.writeFile(STORE_FILE, serialized, { encoding: 'utf8', mode: 0o600 });
      cachedStoreSizeBytes = Buffer.byteLength(serialized, 'utf8');
    } catch (err) {
      console.error('Erro ao persistir estado do SonicAudit:', err);
    }
  }, 400);
}

function appendSyslogsToSite(site: FirewallSiteRecord, newEvents: SyslogEvent[]): number {
  if (newEvents.length === 0) return 0;
  site.syslogs = [...newEvents.reverse(), ...site.syslogs].slice(0, MAX_SYSLOG_RETENTION);
  site.updatedAt = new Date().toISOString();
  purgeExpiredSyslogsForSite(site, false);
  recomputeCorrelations(site);
  schedulePersist({ syslogSiteId: site.id, policySiteId: site.id });
  return newEvents.length;
}

function findMatchingSiteForUdpEvent(ev: SyslogEvent): FirewallSiteRecord | null {
  const sn = (ev.serialNumber || '').trim().toLowerCase();
  const fw = (ev.firewallHost || '').trim().toLowerCase();
  const sites = Object.values(store.sites);

  if (sn && sn !== '-') {
    const bySerial = sites.find((s) => s.appliance.serialNumber.trim().toLowerCase() === sn);
    if (bySerial) return bySerial;
  }

  if (fw && fw !== '-' && fw !== 'sonicwall') {
    const byHost = sites.find(
      (s) =>
        s.connection.host.trim().toLowerCase() === fw ||
        s.appliance.host.split(':')[0].trim().toLowerCase() === fw
    );
    if (byHost) return byHost;
  }

  return null;
}

const udpReceiver = new SyslogUdpReceiver((events) => {
  const grouped = new Map<string, SyslogEvent[]>();
  const active = getActiveSite();

  for (const ev of events) {
    const target = findMatchingSiteForUdpEvent(ev) || active;
    const list = grouped.get(target.id) || [];
    list.push(ev);
    grouped.set(target.id, list);
  }

  for (const [siteId, siteEvents] of grouped.entries()) {
    const targetSite = store.sites[siteId] || active;
    appendSyslogsToSite(targetSite, siteEvents);
  }
});

function buildOverview(site: FirewallSiteRecord = getActiveSite()): AuditOverview {
  const allow = site.syslogs.filter((s) => s.action === 'allow').length;
  const blocked = site.syslogs.filter(
    (s) => s.action === 'drop' || s.action === 'deny' || s.action === 'reset'
  ).length;
  const system = site.syslogs.length - allow - blocked;

  const criticalAndError = site.syslogs.filter((s) =>
    ['emergency', 'alert', 'critical', 'error'].includes(s.severity)
  ).length;
  const warning = site.syslogs.filter((s) => s.severity === 'warning').length;
  const infoAndNotice = site.syslogs.length - criticalAndError - warning;

  const blockedSrcCounts = new Map<string, { count: number; zone: string }>();
  const portCounts = new Map<string, { port: string; protocol: string; count: number; blocked: number }>();
  const zoneCounts = new Map<string, { allow: number; blocked: number }>();

  const now = new Date();
  const currentHourStart = new Date(now);
  currentHourStart.setMinutes(0, 0, 0);

  const buckets: Array<{
    startMs: number;
    hourLabel: string;
    total: number;
    allow: number;
    blocked: number;
  }> = [];

  for (let offset = 23; offset >= 0; offset -= 1) {
    const d = new Date(currentHourStart.getTime() - offset * 60 * 60 * 1000);
    const hh = String(d.getHours()).padStart(2, '0');
    buckets.push({
      startMs: d.getTime(),
      hourLabel: `${hh}:00`,
      total: 0,
      allow: 0,
      blocked: 0,
    });
  }

  const windowStartMs = buckets[0].startMs;
  const windowEndMs = buckets[buckets.length - 1].startMs + 60 * 60 * 1000;

  let oldestEventAt: string | null = null;
  let newestEventAt: string | null = null;

  for (const ev of site.syslogs) {
    if (ev.ingestedAt) {
      if (!oldestEventAt || ev.ingestedAt < oldestEventAt) oldestEventAt = ev.ingestedAt;
      if (!newestEventAt || ev.ingestedAt > newestEventAt) newestEventAt = ev.ingestedAt;
    }

    const parsedTs = Date.parse(ev.timestamp.replace(' ', 'T'));
    const ingestedMs = Date.parse(ev.ingestedAt || '');
    const eventTimeMs =
      Number.isFinite(parsedTs) && parsedTs >= windowStartMs && parsedTs < windowEndMs
        ? parsedTs
        : Number.isFinite(ingestedMs) && ingestedMs >= windowStartMs && ingestedMs < windowEndMs
          ? ingestedMs
          : null;

    if (eventTimeMs !== null) {
      const idx = Math.floor((eventTimeMs - windowStartMs) / (60 * 60 * 1000));
      if (idx >= 0 && idx < buckets.length) {
        buckets[idx].total += 1;
        if (ev.action === 'allow') {
          buckets[idx].allow += 1;
        } else if (ev.action === 'drop' || ev.action === 'deny' || ev.action === 'reset') {
          buckets[idx].blocked += 1;
        }
      }
    }

    if (ev.action === 'drop' || ev.action === 'deny') {
      const existing = blockedSrcCounts.get(ev.srcIp) || { count: 0, zone: ev.srcZone };
      existing.count += 1;
      blockedSrcCounts.set(ev.srcIp, existing);
    }

    if (ev.dstPort !== null) {
      const key = `${ev.protocol}/${ev.dstPort}`;
      const portEntry = portCounts.get(key) || {
        port: String(ev.dstPort),
        protocol: ev.protocol,
        count: 0,
        blocked: 0,
      };
      portEntry.count += 1;
      if (ev.action === 'drop' || ev.action === 'deny') {
        portEntry.blocked += 1;
      }
      portCounts.set(key, portEntry);
    }

    if (ev.srcZone !== '-' || ev.dstZone !== '-') {
      const pair = `${ev.srcZone} → ${ev.dstZone}`;
      const zEntry = zoneCounts.get(pair) || { allow: 0, blocked: 0 };
      if (ev.action === 'allow') zEntry.allow += 1;
      else if (ev.action === 'drop' || ev.action === 'deny') zEntry.blocked += 1;
      zoneCounts.set(pair, zEntry);
    }
  }

  const normalizedAlertSettings = normalizeAlertSettings(site.alertSettings);

  return {
    activeSite: {
      id: site.id,
      name: site.name,
      location: site.location,
      notes: site.notes,
      connection: toPublicConnection(site),
    },
    sites: listAllSiteSummaries(),
    appliance: site.appliance,
    totalSyslogs: site.syslogs.length,
    syslogBreakdown: {
      allow,
      blocked,
      system,
      criticalAndError,
      warning,
      infoAndNotice,
    },
    rulesSummary: {
      total: site.rules.length,
      active: site.rules.filter((r) => r.status === 'active').length,
      unused: site.rules.filter((r) => r.status === 'unused').length,
      shadowed: site.rules.filter((r) => r.status === 'shadowed').length,
      disabled: site.rules.filter((r) => r.status === 'disabled').length,
      overpermissive: site.rules.filter((r) => r.status === 'overpermissive').length,
    },
    natsSummary: {
      total: site.nats.length,
      active: site.nats.filter((n) => n.status === 'active').length,
      unused: site.nats.filter((n) => n.status === 'unused').length,
      disabled: site.nats.filter((n) => n.status === 'disabled').length,
      orphaned: site.nats.filter((n) => n.status === 'orphaned').length,
    },
    topBlockedSources: [...blockedSrcCounts.entries()]
      .map(([ip, meta]) => ({ ip, count: meta.count, zone: meta.zone }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 6),
    topTargetedPorts: [...portCounts.values()]
      .sort((a, b) => b.count - a.count)
      .slice(0, 6),
    zoneTraffic: [...zoneCounts.entries()]
      .map(([pair, counts]) => ({ pair, ...counts }))
      .sort((a, b) => b.allow + b.blocked - (a.allow + a.blocked))
      .slice(0, 6),
    hourlyLogVolume: buckets.map(({ hourLabel, total, allow: a, blocked: b }) => ({
      hourLabel,
      total,
      allow: a,
      blocked: b,
    })),
    telemetry: site.telemetry || EMPTY_TELEMETRY,
    alertSettings: normalizedAlertSettings,
    alerts: evaluateOverviewAlerts(
      site.telemetry || EMPTY_TELEMETRY,
      site.syslogs,
      normalizedAlertSettings
    ),
    udpStatus: udpReceiver.getStatus(),
    retention: {
      retentionDays: site.retentionDays,
      autoPurgeEnabled: true,
      lastPurgeAt: site.lastPurgeAt,
      lastPurgedCount: site.lastPurgedCount,
      oldestEventAt,
      newestEventAt,
      storeSizeBytes: cachedStoreSizeBytes,
    },
  };
}

async function syncSiteWithSonicOs(
  site: FirewallSiteRecord,
  overrides?: {
    host?: string;
    port?: number;
    protocol?: 'https' | 'http';
    username?: string;
    password?: string;
    ignoreTlsErrors?: boolean;
    savePassword?: boolean;
  }
): Promise<{ rulesCount: number; natsCount: number }> {
  const host = (overrides?.host ?? site.connection.host).trim();
  const port = Number(overrides?.port ?? site.connection.port ?? 443);
  const protocol = (overrides?.protocol ?? site.connection.protocol) === 'http' ? 'http' : 'https';
  const username = (overrides?.username ?? site.connection.username).trim();
  const ignoreTlsErrors = overrides?.ignoreTlsErrors ?? site.connection.ignoreTlsErrors ?? true;
  const rawPassword = overrides?.password ? String(overrides.password) : '';
  const effectivePassword =
    rawPassword || authManager.decryptSecret(site.connection.passwordEncrypted);

  if (!host || !username || !effectivePassword) {
    throw new Error(
      'Informe host/IP, usuário e senha do SonicWall (ou salve a senha nesta localidade).'
    );
  }

  const audit = await fetchSonicOsAudit({
    host,
    port,
    protocol,
    username,
    password: effectivePassword,
    ignoreTlsErrors,
  });

  site.connection = {
    host,
    port,
    protocol,
    username,
    ignoreTlsErrors,
    passwordEncrypted:
      overrides?.savePassword && rawPassword
        ? authManager.encryptSecret(rawPassword)
        : rawPassword && overrides?.savePassword === false
          ? undefined
          : site.connection.passwordEncrypted ||
            (overrides?.savePassword ? authManager.encryptSecret(effectivePassword) : undefined),
  };

  site.rules = audit.rules;
  site.nats = audit.nats;
  site.telemetry = audit.telemetry;
  site.appliance = {
    model: audit.model,
    serialNumber: audit.serialNumber,
    firmware: audit.firmware,
    romVersion: audit.romVersion,
    safemodeVersion: audit.safemodeVersion,
    uptimeFormatted: audit.uptimeFormatted,
    uptimeSeconds: audit.uptimeSeconds,
    cpuPercent: audit.cpuPercent,
    memoryPercent: audit.memoryPercent,
    activeConnections: audit.activeConnections,
    maxConnections: audit.maxConnections,
    haRole: audit.haRole,
    host: `${host}:${port}`,
    lastSyncAt: new Date().toISOString(),
    dataSource: 'api',
  };
  site.updatedAt = new Date().toISOString();

  recomputeCorrelations(site);
  schedulePersist({ policySiteId: site.id });

  return {
    rulesCount: site.rules.length,
    natsCount: site.nats.length,
  };
}

async function startApp(): Promise<void> {
  await pgStore.init();
  await authManager.init();
  await loadStoreFromStorage();

  // Automatic hourly purge across all persistent localities to prevent storage exhaustion
  setInterval(() => {
    purgeExpiredAcrossAllSites();
  }, 60 * 60 * 1000);

  const app = express();
  app.set('trust proxy', 1);
  app.use(express.json({ limit: '50mb' }));
  app.use(express.text({ limit: '50mb', type: ['text/plain', 'application/octet-stream'] }));

  // Public health check (no sensitive data)
  app.get('/api/health', (_req, res) => {
    res.json({
      ok: true,
      storage: pgStore.isEnabled() ? 'postgresql' : 'local-json',
    });
  });

  // Authentication endpoints (public before auth guard)
  app.get('/api/auth/status', (req, res) => {
    res.json(authManager.getStatus(req));
  });

  app.post('/api/auth/setup', async (req, res) => {
    try {
      const username = String(req.body?.username || '').trim();
      const password = String(req.body?.password || '');
      const createdUser = await authManager.createInitialUser(username, password);
      authManager.setSessionCookie(req, res, createdUser);
      res.json({ ok: true, username: createdUser });
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Falha ao configurar acesso inicial.';
      res.status(400).json({ error: msg });
    }
  });

  app.post('/api/auth/login', (req, res) => {
    if (authManager.needsSetup()) {
      res.status(409).json({ error: 'Configure o usuário administrador inicial primeiro.' });
      return;
    }
    const username = String(req.body?.username || '').trim();
    const password = String(req.body?.password || '');
    const authedUser = authManager.authenticateUser(username, password);
    if (!authedUser) {
      res.status(401).json({ error: 'Usuário ou senha inválidos.' });
      return;
    }
    authManager.setSessionCookie(req, res, authedUser);
    res.json({ ok: true, username: authedUser });
  });

  app.post('/api/auth/logout', (req, res) => {
    authManager.clearSessionCookie(req, res);
    res.json({ ok: true });
  });

  // Protect all remaining /api/* routes behind authenticated session cookie
  app.use('/api', (req, res, next) => {
    const user = authManager.getAuthenticatedUser(req);
    if (!user) {
      res.status(401).json({ error: 'Sessão expirada ou não autenticada. Faça login.' });
      return;
    }
    next();
  });

  app.post('/api/auth/change-password', async (req, res) => {
    const user = authManager.getAuthenticatedUser(req);
    if (!user) {
      res.status(401).json({ error: 'Não autenticado.' });
      return;
    }
    try {
      const currentPassword = String(req.body?.currentPassword || '');
      const newPassword = String(req.body?.newPassword || '');
      await authManager.changePassword(user, currentPassword, newPassword);
      res.json({ ok: true });
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Não foi possível alterar a senha.';
      res.status(400).json({ error: msg });
    }
  });

  // Multi-locality firewall management routes
  app.get('/api/sites', (_req, res) => {
    res.json({
      activeSiteId: getActiveSite().id,
      sites: listAllSiteSummaries(),
    });
  });

  app.post('/api/sites', (req, res) => {
    const name = String(req.body?.name || '').trim();
    const location = String(req.body?.location || '').trim();
    const notes = String(req.body?.notes || '').trim();
    if (!name) {
      res.status(400).json({ error: 'Informe o nome da localidade ou firewall.' });
      return;
    }

    const id = `site-${crypto.randomUUID().slice(0, 8)}`;
    const site = createEmptySite(id, name, location);
    site.notes = notes;

    const conn = req.body?.connection;
    if (conn && typeof conn === 'object') {
      const rawHost = String(conn.host || '').trim();
      const rawPassword = typeof conn.password === 'string' ? conn.password : '';
      const savePassword = Boolean(conn.savePassword);
      site.connection = {
        host: rawHost,
        port: Number(conn.port || 443),
        protocol: conn.protocol === 'http' ? 'http' : 'https',
        username: String(conn.username || 'admin').trim() || 'admin',
        passwordEncrypted: savePassword && rawPassword ? authManager.encryptSecret(rawPassword) : undefined,
        ignoreTlsErrors: conn.ignoreTlsErrors !== false,
      };
      if (rawHost) {
        site.appliance.host = `${rawHost}:${site.connection.port}`;
      }
    }

    store.sites[site.id] = site;
    if (req.body?.select !== false) {
      store.activeSiteId = site.id;
    }
    schedulePersist();

    res.json({
      ok: true,
      site: toSiteSummary(site),
      overview: buildOverview(),
    });
  });

  app.put('/api/sites/:id', (req, res) => {
    const site = store.sites[req.params.id];
    if (!site) {
      res.status(404).json({ error: 'Localidade não encontrada.' });
      return;
    }

    const name = typeof req.body?.name === 'string' ? req.body.name.trim() : site.name;
    if (!name) {
      res.status(400).json({ error: 'O nome da localidade não pode ficar vazio.' });
      return;
    }

    site.name = name;
    if (typeof req.body?.location === 'string') site.location = req.body.location.trim();
    if (typeof req.body?.notes === 'string') site.notes = req.body.notes.trim();

    const conn = req.body?.connection;
    if (conn && typeof conn === 'object') {
      const rawPassword = typeof conn.password === 'string' ? conn.password : '';
      const clearSavedPassword = Boolean(conn.clearSavedPassword);
      const savePassword = Boolean(conn.savePassword);

      let nextEncrypted = site.connection.passwordEncrypted;
      if (clearSavedPassword) {
        nextEncrypted = undefined;
      } else if (rawPassword) {
        nextEncrypted = savePassword ? authManager.encryptSecret(rawPassword) : undefined;
      }

      site.connection = {
        host: typeof conn.host === 'string' ? conn.host.trim() : site.connection.host,
        port: Number(conn.port || site.connection.port || 443),
        protocol: conn.protocol === 'http' ? 'http' : 'https',
        username: typeof conn.username === 'string' ? conn.username.trim() : site.connection.username,
        passwordEncrypted: nextEncrypted,
        ignoreTlsErrors: conn.ignoreTlsErrors !== false,
      };
    }

    site.updatedAt = new Date().toISOString();
    schedulePersist();
    res.json({
      ok: true,
      site: toSiteSummary(site),
      overview: buildOverview(),
    });
  });

  app.post('/api/sites/:id/select', (req, res) => {
    const site = store.sites[req.params.id];
    if (!site) {
      res.status(404).json({ error: 'Localidade não encontrada.' });
      return;
    }
    store.activeSiteId = site.id;
    schedulePersist();
    res.json({ ok: true, overview: buildOverview(site) });
  });

  app.post('/api/sites/:id/sync', async (req, res) => {
    const site = store.sites[req.params.id];
    if (!site) {
      res.status(404).json({ error: 'Localidade não encontrada.' });
      return;
    }
    try {
      const result = await syncSiteWithSonicOs(site, {
        host: typeof req.body?.host === 'string' ? req.body.host : undefined,
        port: req.body?.port !== undefined ? Number(req.body.port) : undefined,
        protocol: req.body?.protocol === 'http' ? 'http' : req.body?.protocol === 'https' ? 'https' : undefined,
        username: typeof req.body?.username === 'string' ? req.body.username : undefined,
        password: typeof req.body?.password === 'string' ? req.body.password : undefined,
        ignoreTlsErrors:
          typeof req.body?.ignoreTlsErrors === 'boolean' ? req.body.ignoreTlsErrors : undefined,
        savePassword:
          typeof req.body?.savePassword === 'boolean' ? req.body.savePassword : undefined,
      });
      res.json({
        ok: true,
        ...result,
        overview: buildOverview(),
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Erro ao sincronizar localidade com SonicOS.';
      res.status(502).json({ error: message });
    }
  });

  app.delete('/api/sites/:id', (req, res) => {
    const ids = Object.keys(store.sites);
    if (ids.length <= 1) {
      res.status(400).json({ error: 'É necessário manter ao menos uma localidade configurada.' });
      return;
    }
    if (!store.sites[req.params.id]) {
      res.status(404).json({ error: 'Localidade não encontrada.' });
      return;
    }
    delete store.sites[req.params.id];
    if (store.activeSiteId === req.params.id) {
      store.activeSiteId = Object.keys(store.sites)[0];
    }
    schedulePersist();
    res.json({ ok: true, overview: buildOverview() });
  });

  // Active locality overview, alerts, retention & reports
  app.get('/api/overview', (_req, res) => {
    res.json(buildOverview());
  });

  app.get('/api/alerts/config', (_req, res) => {
    res.json(normalizeAlertSettings(getActiveSite().alertSettings));
  });

  app.post('/api/alerts/config', (req, res) => {
    const site = getActiveSite();
    const nextSettings = normalizeAlertSettings({
      ...normalizeAlertSettings(site.alertSettings),
      ...(req.body && typeof req.body === 'object' ? req.body : {}),
    });
    site.alertSettings = nextSettings;
    site.updatedAt = new Date().toISOString();
    schedulePersist();
    res.json({
      ok: true,
      alertSettings: nextSettings,
      overview: buildOverview(site),
    });
  });

  app.get('/api/retention', (_req, res) => {
    res.json(buildOverview().retention);
  });

  app.post('/api/retention', (req, res) => {
    const site = getActiveSite();
    const days = Number(req.body?.retentionDays);
    if (!Number.isInteger(days) || days < 1 || days > 365) {
      res.status(400).json({ error: 'Informe um período de retenção entre 1 e 365 dias.' });
      return;
    }
    site.retentionDays = days;
    site.updatedAt = new Date().toISOString();
    const purged = purgeExpiredSyslogsForSite(site, true);
    schedulePersist();
    res.json({
      ok: true,
      purged,
      retention: buildOverview(site).retention,
      overview: buildOverview(site),
    });
  });

  app.post('/api/retention/purge', (_req, res) => {
    const site = getActiveSite();
    const purged = purgeExpiredSyslogsForSite(site, true);
    schedulePersist();
    res.json({
      ok: true,
      purged,
      retention: buildOverview(site).retention,
      overview: buildOverview(site),
    });
  });

  app.get('/api/report', (_req, res) => {
    const site = getActiveSite();
    const overview = buildOverview(site);
    const report = buildAuditReport(overview, site.syslogs, site.rules, site.nats);
    res.json(report);
  });

  app.get('/api/report/download', (req, res) => {
    const site = getActiveSite();
    const format = String(req.query.format || 'html').toLowerCase();
    const overview = buildOverview(site);
    const report = buildAuditReport(overview, site.syslogs, site.rules, site.nats);
    const stamp = new Date().toISOString().slice(0, 10);

    if (format === 'md' || format === 'markdown') {
      const md = renderReportMarkdown(report);
      res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
      res.setHeader('Content-Disposition', `attachment; filename="relatorio-sonicwall-${stamp}.md"`);
      res.send(md);
      return;
    }

    if (format === 'json') {
      res.setHeader('Content-Type', 'application/json; charset=utf-8');
      res.setHeader('Content-Disposition', `attachment; filename="relatorio-sonicwall-${stamp}.json"`);
      res.send(JSON.stringify(report, null, 2));
      return;
    }

    const html = renderReportHtml(report);
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="relatorio-sonicwall-${stamp}.html"`);
    res.send(html);
  });

  app.get('/api/syslogs', (req, res) => {
    const site = getActiveSite();
    const search = String(req.query.q || '').trim().toLowerCase();
    const action = String(req.query.action || 'all').toLowerCase();
    const severity = String(req.query.severity || 'all').toLowerCase();
    const limit = Math.min(500, Math.max(10, Number(req.query.limit || 250)));

    const filtered = site.syslogs.filter((ev) => {
      if (action !== 'all') {
        if (action === 'blocked') {
          if (ev.action !== 'drop' && ev.action !== 'deny' && ev.action !== 'reset') return false;
        } else if (ev.action !== action) {
          return false;
        }
      }
      if (severity !== 'all' && ev.severity !== severity) return false;
      if (search) {
        const hay = `${ev.srcIp} ${ev.dstIp} ${ev.dstPort ?? ''} ${ev.protocol} ${ev.ruleRef ?? ''} ${ev.natRuleRef ?? ''} ${ev.message} ${ev.srcZone} ${ev.dstZone}`.toLowerCase();
        if (!hay.includes(search)) return false;
      }
      return true;
    });

    res.json({
      total: site.syslogs.length,
      matched: filtered.length,
      events: filtered.slice(0, limit),
    });
  });

  app.post('/api/syslogs/ingest', (req, res) => {
    const site = getActiveSite();
    const rawText = typeof req.body === 'string' ? req.body : String(req.body?.content || '');
    const source = (
      typeof req.body === 'object' && req.body?.source === 'paste' ? 'paste' : 'upload'
    ) as SyslogEvent['source'];
    const replace = Boolean(typeof req.body === 'object' && req.body?.replace);

    if (!rawText.trim()) {
      res.status(400).json({ error: 'Conteúdo de syslog vazio.' });
      return;
    }

    const parsed = parseSonicWallSyslog(rawText, source);
    if (parsed.length === 0) {
      res.status(422).json({
        error: 'Nenhuma linha válida de syslog SonicWall foi reconhecida. Verifique o formato do arquivo.',
      });
      return;
    }

    if (replace) {
      site.syslogs = [];
    }

    const added = appendSyslogsToSite(site, parsed);
    res.json({ added, total: site.syslogs.length, overview: buildOverview(site) });
  });

  app.delete('/api/syslogs', (_req, res) => {
    const site = getActiveSite();
    site.syslogs = [];
    site.updatedAt = new Date().toISOString();
    recomputeCorrelations(site);
    schedulePersist({ syslogSiteId: site.id, policySiteId: site.id });
    res.json({ ok: true, overview: buildOverview(site) });
  });

  app.get('/api/rules', (_req, res) => {
    const site = getActiveSite();
    res.json({ rules: site.rules, appliance: site.appliance });
  });

  app.get('/api/nats', (_req, res) => {
    const site = getActiveSite();
    res.json({ nats: site.nats, appliance: site.appliance });
  });

  app.post('/api/config/import', (req, res) => {
    const site = getActiveSite();
    const content = String(req.body?.content || '');
    const filename = String(req.body?.filename || 'config');
    if (!content.trim()) {
      res.status(400).json({ error: 'Arquivo de configuração vazio.' });
      return;
    }

    let rulesCount = 0;
    let natsCount = 0;

    const trimmed = content.trim();
    if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
      try {
        const parsedJson = JSON.parse(trimmed);
        const result = parseSonicOsJson(parsedJson, 'json');
        site.rules = result.rules;
        site.nats = result.nats;
        rulesCount = result.rules.length;
        natsCount = result.nats.length;
        site.appliance = {
          model: 'Exportação SonicOS JSON',
          serialNumber: '-',
          firmware: 'JSON Import',
          host: filename,
          lastSyncAt: new Date().toISOString(),
          dataSource: 'json',
        };
      } catch {
        res.status(400).json({ error: 'JSON inválido ao importar configuração.' });
        return;
      }
    } else {
      const expResult = parseSonicWallExp(content);
      if (expResult.rules.length === 0 && expResult.nats.length === 0) {
        res.status(422).json({
          error:
            'Não foram encontradas políticas de firewall ou NAT neste arquivo. Envie um arquivo .exp do SonicWall ou JSON exportado da API SonicOS.',
        });
        return;
      }
      site.rules = expResult.rules;
      site.nats = expResult.nats;
      rulesCount = expResult.rules.length;
      natsCount = expResult.nats.length;
      site.appliance = {
        model: expResult.model || 'Arquivo .exp SonicWall',
        serialNumber: expResult.serialNumber || '-',
        firmware: expResult.firmware || 'Config Export (.exp)',
        host: filename,
        lastSyncAt: new Date().toISOString(),
        dataSource: 'exp',
      };
    }

    site.telemetry = { ...EMPTY_TELEMETRY };
    site.updatedAt = new Date().toISOString();
    recomputeCorrelations(site);
    schedulePersist({ policySiteId: site.id });
    res.json({
      rulesCount,
      natsCount,
      overview: buildOverview(site),
    });
  });

  app.post('/api/sonicwall/audit', async (req, res) => {
    const targetSiteId = typeof req.body?.siteId === 'string' ? req.body.siteId : getActiveSite().id;
    const site = store.sites[targetSiteId] || getActiveSite();
    const host = String(req.body?.host ?? site.connection.host ?? '').trim();
    const port = Number(req.body?.port ?? site.connection.port ?? 443);
    const protocol = (req.body?.protocol ?? site.connection.protocol) === 'http' ? 'http' : 'https';
    const username = String(req.body?.username ?? site.connection.username ?? '').trim();
    const password = String(req.body?.password || '');
    const ignoreTlsErrors = req.body?.ignoreTlsErrors !== false;
    const savePassword = Boolean(req.body?.savePassword);

    try {
      const result = await syncSiteWithSonicOs(site, {
        host,
        port,
        protocol,
        username,
        password,
        ignoreTlsErrors,
        savePassword,
      });

      res.json({
        ok: true,
        rulesCount: result.rulesCount,
        natsCount: result.natsCount,
        overview: buildOverview(site),
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Erro desconhecido ao consultar API SonicOS.';
      res.status(502).json({ error: message });
    }
  });

  app.get('/api/syslog-server/status', (_req, res) => {
    res.json(udpReceiver.getStatus());
  });

  app.post('/api/syslog-server/start', async (req, res) => {
    const port = Number(req.body?.port || 5514);
    const bindAddress = String(req.body?.bindAddress || '0.0.0.0');
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      res.status(400).json({ error: 'Porta UDP inválida (1–65535).' });
      return;
    }
    try {
      const status = await udpReceiver.start(port, bindAddress);
      res.json(status);
    } catch (err) {
      const message =
        err instanceof Error
          ? `Não foi possível abrir a porta UDP ${port}: ${err.message}. No Linux, portas < 1024 exigem privilégio root/cap_net_bind_service (tente 5514).`
          : 'Falha ao iniciar receptor UDP.';
      res.status(500).json({ error: message });
    }
  });

  app.post('/api/syslog-server/stop', async (_req, res) => {
    const status = await udpReceiver.stop();
    res.json(status);
  });

  app.post('/api/syslog-server/test-packet', async (_req, res) => {
    try {
      await udpReceiver.sendTestPacket();
      await new Promise((r) => setTimeout(r, 80));
      res.json({ ok: true, status: udpReceiver.getStatus(), overview: buildOverview() });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Erro ao enviar pacote UDP de teste.';
      res.status(400).json({ error: message });
    }
  });

  app.post('/api/sample/load', (_req, res) => {
    const site = getActiveSite();
    const sample = createSampleDataset();
    site.appliance = sample.appliance;
    site.syslogs = sample.syslogs;
    site.rules = sample.rules;
    site.nats = sample.nats;
    site.telemetry = sample.telemetry;
    site.updatedAt = new Date().toISOString();
    recomputeCorrelations(site);
    schedulePersist({ syslogSiteId: site.id, policySiteId: site.id });
    res.json({ ok: true, overview: buildOverview(site) });
  });

  app.post('/api/data/clear', (_req, res) => {
    const site = getActiveSite();
    site.appliance = {
      model: 'Nenhum appliance sincronizado',
      serialNumber: '-',
      firmware: '-',
      host: site.connection.host ? `${site.connection.host}:${site.connection.port}` : '-',
      lastSyncAt: null,
      dataSource: 'none',
    };
    site.lastPurgedCount = 0;
    site.syslogs = [];
    site.rules = [];
    site.nats = [];
    site.telemetry = { ...EMPTY_TELEMETRY };
    site.updatedAt = new Date().toISOString();
    schedulePersist({ syslogSiteId: site.id, policySiteId: site.id });
    res.json({ ok: true, overview: buildOverview(site) });
  });

  app.post('/api/export/cli', (req, res) => {
    const site = getActiveSite();
    const ruleIds = Array.isArray(req.body?.ruleIds) ? (req.body.ruleIds as string[]) : [];
    const natIds = Array.isArray(req.body?.natIds) ? (req.body.natIds as string[]) : [];
    const mode = req.body?.mode === 'delete' ? 'delete' : 'disable';

    const selectedRules = site.rules.filter((r) => ruleIds.includes(r.id));
    const selectedNats = site.nats.filter((n) => natIds.includes(n.id));
    const script = generateSonicOsCli(selectedRules, selectedNats, mode);

    res.json({ script });
  });

  app.get('/api/ai/config', (_req, res) => {
    const current = store.aiSettings || DEFAULT_AI_SETTINGS;
    res.json(toPublicAiConfig(current));
  });

  app.post('/api/ai/config', (req, res) => {
    const allowedProviders = new Set<AiProviderType>(['gemini', 'openrouter', 'openai', 'local']);
    const providerRaw = String(req.body?.provider || 'gemini') as AiProviderType;
    const provider: AiProviderType = allowedProviders.has(providerRaw) ? providerRaw : 'gemini';
    const model = String(req.body?.model || '').trim();
    const baseUrl = String(req.body?.baseUrl || '').trim();
    const incomingKey = typeof req.body?.apiKey === 'string' ? req.body.apiKey.trim() : undefined;
    const clearKey = Boolean(req.body?.clearKey);

    const prev = store.aiSettings || DEFAULT_AI_SETTINGS;
    let nextKey = prev.apiKey;
    if (clearKey) {
      nextKey = '';
    } else if (incomingKey !== undefined && incomingKey.length > 0) {
      nextKey = incomingKey;
    }

    const updated: AiProviderSettings = {
      provider,
      model: model || (provider === 'gemini' ? 'gemini-4-hydrogen' : ''),
      baseUrl,
      apiKey: nextKey,
    };

    store.aiSettings = updated;
    schedulePersist();
    res.json(toPublicAiConfig(updated));
  });

  app.post('/api/ai/chat', async (req, res) => {
    const site = getActiveSite();
    const message = String(req.body?.message || '').trim();
    const history = Array.isArray(req.body?.history) ? (req.body.history as AiChatMessage[]) : [];
    const overrideModel = typeof req.body?.model === 'string' ? req.body.model.trim() : '';

    if (!message) {
      res.status(400).json({ error: 'Digite uma pergunta ou cole um trecho de log para análise.' });
      return;
    }

    const baseSettings = store.aiSettings || DEFAULT_AI_SETTINGS;
    const settings: AiProviderSettings = overrideModel
      ? { ...baseSettings, model: overrideModel }
      : baseSettings;

    try {
      const result = await runAiLogAnalysis({
        settings,
        overview: buildOverview(site),
        syslogs: site.syslogs,
        rules: site.rules,
        nats: site.nats,
        history,
        message,
      });

      res.json({
        reply: result.reply,
        modelUsed: result.modelUsed,
        provider: result.provider,
        timestamp: new Date().toISOString(),
      });
    } catch (err) {
      const errMsg = err instanceof Error ? err.message : 'Falha ao consultar o provedor de IA.';
      res.status(502).json({ error: errMsg });
    }
  });

  if (process.env.SERVE_STATIC === 'false') {
    app.get('/', (_req, res) => {
      res.json({
        service: 'SonicAudit Backend API',
        ok: true,
        storage: pgStore.isEnabled() ? 'postgresql' : 'local-json',
      });
    });
  } else if (process.env.NODE_ENV !== 'production') {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distDir));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distDir, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`SonicAudit ativo em http://0.0.0.0:${PORT}`);
  });
}

startApp().catch((err) => {
  console.error('Erro fatal ao iniciar servidor SonicAudit:', err);
  process.exit(1);
});
