import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import express, { type Router } from 'express';
import {
  DEFAULT_AI_SETTINGS,
  runAiLogAnalysis,
  toPublicAiConfig,
} from './aiClient.ts';
import {
  DEFAULT_ALERT_SETTINGS,
  evaluateOverviewAlerts,
  normalizeAlertSettings,
} from './alertsEngine.ts';
import type { AuthManager } from './authManager.ts';
import type { PostgresStore, SyslogStats } from './database.ts';
import { buildSyslogSearchText } from './database.ts';
import { fetchFortiOsAudit } from './fortigateClient.ts';
import { generateFortiOsCli, parseFortiGateSyslog } from './fortigateParsers.ts';
import { createFortiGateSampleDataset } from './fortigateSampleData.ts';
import {
  DEFAULT_NOTIFICATION_SETTINGS,
  normalizeNotificationSettings,
  sendNotification,
  severityPasses,
  toPublicNotificationConfig,
} from './notifier.ts';
import {
  accumulateSyslogHits,
  carryOverSyslogHits,
  classifyPolicies,
  generateSonicOsCli,
  parseSonicOsJson,
  parseSonicWallExp,
  parseSonicWallSyslog,
} from './parsers.ts';
import {
  buildAuditReport,
  renderReportHtml,
  renderReportMarkdown,
} from './reportBuilder.ts';
import { createSampleDataset } from './sampleData.ts';
import { fetchSonicOsAudit } from './sonicosClient.ts';
import { SyslogUdpReceiver } from './syslogUdp.ts';
import type {
  AiChatMessage,
  AiProviderSettings,
  AiProviderType,
  AlertRecord,
  ApplianceMetadata,
  AuditOverview,
  ConfigChangeEntry,
  DataStore,
  FirewallConnectionPublic,
  FirewallRule,
  FirewallSiteRecord,
  FirewallSiteSummary,
  FirewallVendor,
  MetricSample,
  NatPolicy,
  NotificationSettings,
  OverviewAlert,
  SyncStatus,
  SyslogEvent,
  TelemetrySnapshot,
  UdpListenerConfig,
  UdpListenerStatus,
  UdpUnmatchedSource,
} from './types.ts';

const DEFAULT_RETENTION_DAYS = 10;
const DEFAULT_AUTO_SYNC_MINUTES = 5;
const HOUR_MS = 60 * 60 * 1000;
const ENC_PREFIX = 'enc:';

/** Limite de eventos aguardando gravação no banco antes de começar a descartar. */
const MAX_PENDING_INSERTS = 200_000;
const MAX_RESOLVED_ALERTS = 300;
const MAX_CONFIG_CHANGES = 50;
const MAX_LOCAL_METRICS = 2016;

function envInt(name: string, fallback: number, min: number): number {
  const n = Number(process.env[name]);
  return Number.isFinite(n) && n >= min ? Math.floor(n) : fallback;
}

const EMPTY_TELEMETRY: TelemetrySnapshot = {
  interfaces: [],
  vpns: [],
  licenses: [],
};

export interface VendorEngineOptions {
  vendor: FirewallVendor;
  dataDir: string;
  pgStore: PostgresStore;
  authManager: AuthManager;
}

export interface VendorEngineInstance {
  vendor: FirewallVendor;
  router: Router;
  init: () => Promise<void>;
  purgeExpired: () => Promise<void>;
  shutdown: () => Promise<void>;
}

interface HourBucket {
  total: number;
  allow: number;
  blocked: number;
}

/** Contadores mantidos fora da janela em memória: valem para todo o histórico armazenado. */
interface SiteRuntime {
  total: number;
  oldestAt: string | null;
  newestAt: string | null;
  byAction: Record<string, number>;
  bySeverity: Record<string, number>;
  hourly: Map<number, HourBucket>;
  lastEventAtMs: number | null;
  syncing: boolean;
}

function isBlockedAction(action: string): boolean {
  return action === 'drop' || action === 'deny' || action === 'reset';
}

/**
 * Instante usado para posicionar o evento no gráfico por hora. Eventos UDP chegam em tempo
 * real (evita divergência de fuso do firewall); em uploads vale o horário do próprio log.
 */
export function resolveEventTimeMs(ev: SyslogEvent): number {
  const ingestedParsed = Date.parse(ev.ingestedAt || '');
  const ingestedMs = Number.isFinite(ingestedParsed) ? ingestedParsed : Date.now();
  if (ev.source === 'udp') return ingestedMs;
  const parsed = Date.parse((ev.timestamp || '').replace(' ', 'T'));
  if (
    Number.isFinite(parsed) &&
    parsed <= ingestedMs + 5 * 60 * 1000 &&
    parsed >= ingestedMs - 366 * 24 * HOUR_MS
  ) {
    return parsed;
  }
  return ingestedMs;
}

export function createVendorEngine(options: VendorEngineOptions): VendorEngineInstance {
  const { vendor, dataDir, pgStore, authManager } = options;
  const usePg = pgStore.isEnabled();

  // Janela recente mantida em memória para alertas, rankings e IA. Com PostgreSQL o
  // histórico completo fica no banco, limitado apenas pela retenção em dias.
  const MEMORY_WINDOW = envInt('SYSLOG_MEMORY_WINDOW', usePg ? 50_000 : 20_000, 1000);
  // Teto opcional de linhas por firewall (0 = sem teto) para proteger o disco.
  const MAX_ROWS_PER_SITE = envInt('SYSLOG_MAX_ROWS_PER_SITE', 0, 0);

  const defaultSiteId = vendor === 'fortigate' ? 'fgt-site-default' : 'site-default';
  const defaultSiteName =
    vendor === 'fortigate' ? 'FortiGate Principal' : 'Localidade Principal';
  const defaultPort = vendor === 'fortigate' ? 5515 : 5514;
  const vendorLabel = vendor === 'fortigate' ? 'FortiGate' : 'SonicWall';
  const storeFile = path.join(
    dataDir,
    vendor === 'fortigate' ? 'store.fortigate.json' : 'store.sonicwall.json'
  );
  const legacyStoreFile = path.join(dataDir, 'store.json');

  function defaultUdpConfig(): UdpListenerConfig {
    return {
      enabled: process.env.SYSLOG_UDP_AUTOSTART !== 'false',
      port: defaultPort,
      bindAddress: '0.0.0.0',
    };
  }

  function createEmptySite(
    id: string,
    name = defaultSiteName,
    location = 'Matriz'
  ): FirewallSiteRecord {
    const now = new Date().toISOString();
    return {
      id,
      vendor,
      name,
      location,
      notes: '',
      connection: {
        host: '',
        port: 443,
        protocol: 'https',
        username: vendor === 'fortigate' ? 'api-readonly' : 'admin',
        authMode: vendor === 'fortigate' ? 'token' : 'basic',
        vdom: vendor === 'fortigate' ? 'root' : undefined,
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
      alertRecords: [],
      autoSyncMinutes: DEFAULT_AUTO_SYNC_MINUTES,
      lastSyncAttemptAt: null,
      lastSyncError: null,
      consecutiveSyncFailures: 0,
      configChanges: [],
      hitsObservedSince: null,
      metrics: [],
      createdAt: now,
      updatedAt: now,
    };
  }

  let store: DataStore = {
    vendor,
    activeSiteId: defaultSiteId,
    sites: {
      [defaultSiteId]: createEmptySite(defaultSiteId),
    },
    aiSettings: { ...DEFAULT_AI_SETTINGS },
    notificationSettings: { ...DEFAULT_NOTIFICATION_SETTINGS },
    udpListener: defaultUdpConfig(),
  };

  let cachedStoreSizeBytes = 0;

  // ---------------------------------------------------------------------------
  // Seleção de site
  // ---------------------------------------------------------------------------

  function getActiveSite(): FirewallSiteRecord {
    const active = store.sites[store.activeSiteId];
    if (active) return active;
    const firstKey = Object.keys(store.sites)[0];
    if (firstKey) {
      store.activeSiteId = firstKey;
      return store.sites[firstKey];
    }
    const fallback = createEmptySite(defaultSiteId);
    store.sites[defaultSiteId] = fallback;
    store.activeSiteId = defaultSiteId;
    return fallback;
  }

  /**
   * Site da requisição: cada aba/usuário informa o seu (?site= ou X-Site-Id), de modo que a
   * seleção de um não interfere na do outro. Sem o parâmetro, usa o padrão do servidor.
   */
  function siteFor(req: express.Request): FirewallSiteRecord {
    const fromQuery = typeof req.query.site === 'string' ? req.query.site : '';
    const fromHeader = typeof req.headers['x-site-id'] === 'string' ? req.headers['x-site-id'] : '';
    const id = fromQuery || fromHeader;
    if (id && store.sites[id]) return store.sites[id];
    return getActiveSite();
  }

  // ---------------------------------------------------------------------------
  // Contadores em tempo de execução
  // ---------------------------------------------------------------------------

  const runtimes = new Map<string, SiteRuntime>();

  function emptyRuntime(): SiteRuntime {
    return {
      total: 0,
      oldestAt: null,
      newestAt: null,
      byAction: {},
      bySeverity: {},
      hourly: new Map(),
      lastEventAtMs: null,
      syncing: false,
    };
  }

  function addEventsToRuntime(rt: SiteRuntime, events: SyslogEvent[]): void {
    for (const ev of events) {
      rt.total += 1;
      rt.byAction[ev.action] = (rt.byAction[ev.action] || 0) + 1;
      rt.bySeverity[ev.severity] = (rt.bySeverity[ev.severity] || 0) + 1;

      const bucketStart = Math.floor(resolveEventTimeMs(ev) / HOUR_MS) * HOUR_MS;
      const bucket = rt.hourly.get(bucketStart) || { total: 0, allow: 0, blocked: 0 };
      bucket.total += 1;
      if (ev.action === 'allow') bucket.allow += 1;
      else if (isBlockedAction(ev.action)) bucket.blocked += 1;
      rt.hourly.set(bucketStart, bucket);

      if (ev.ingestedAt) {
        if (!rt.oldestAt || ev.ingestedAt < rt.oldestAt) rt.oldestAt = ev.ingestedAt;
        if (!rt.newestAt || ev.ingestedAt > rt.newestAt) rt.newestAt = ev.ingestedAt;
        const ms = Date.parse(ev.ingestedAt);
        if (Number.isFinite(ms) && (rt.lastEventAtMs === null || ms > rt.lastEventAtMs)) {
          rt.lastEventAtMs = ms;
        }
      }
    }
    if (rt.hourly.size > 60) {
      const cutoff = Date.now() - 50 * HOUR_MS;
      for (const key of rt.hourly.keys()) {
        if (key < cutoff) rt.hourly.delete(key);
      }
    }
  }

  function getRuntime(site: FirewallSiteRecord): SiteRuntime {
    let rt = runtimes.get(site.id);
    if (!rt) {
      rt = emptyRuntime();
      addEventsToRuntime(rt, site.syslogs);
      runtimes.set(site.id, rt);
    }
    return rt;
  }

  function applyDbStats(rt: SiteRuntime, stats: SyslogStats): void {
    rt.total = stats.total;
    rt.oldestAt = stats.oldestAt;
    rt.newestAt = stats.newestAt;
    rt.byAction = stats.byAction;
    rt.bySeverity = stats.bySeverity;
    rt.hourly = new Map(
      stats.hourly.map((h) => [h.startMs, { total: h.total, allow: h.allow, blocked: h.blocked }])
    );
    const newestMs = stats.newestAt ? Date.parse(stats.newestAt) : Number.NaN;
    rt.lastEventAtMs = Number.isFinite(newestMs) ? newestMs : null;
  }

  /** Recalcula os contadores a partir da fonte da verdade (banco ou memória). */
  async function rebuildRuntime(site: FirewallSiteRecord): Promise<void> {
    const previous = runtimes.get(site.id);
    const rt = emptyRuntime();
    rt.syncing = previous?.syncing ?? false;
    if (usePg) {
      await flushPendingInserts();
      applyDbStats(rt, await pgStore.loadSyslogStats(site.id));
    } else {
      addEventsToRuntime(rt, site.syslogs);
    }
    runtimes.set(site.id, rt);
  }

  // ---------------------------------------------------------------------------
  // Classificação de políticas (preguiçosa: só quando alguém vai ler)
  // ---------------------------------------------------------------------------

  const classifyDirty = new Set<string>();

  function ensureClassified(site: FirewallSiteRecord): void {
    if (!classifyDirty.has(site.id)) return;
    classifyDirty.delete(site.id);
    const classified = classifyPolicies(site.rules, site.nats, {
      observedSince: site.hitsObservedSince,
      uptimeSeconds: site.appliance.uptimeSeconds,
    });
    site.rules = classified.rules;
    site.nats = classified.nats;
  }

  function resetSyslogHits(site: FirewallSiteRecord): void {
    for (const r of site.rules) {
      r.syslogHits = 0;
      r.lastHitAt = null;
    }
    for (const n of site.nats) {
      n.syslogHits = 0;
      n.lastHitAt = null;
    }
    site.hitsObservedSince = null;
    classifyDirty.add(site.id);
  }

  // ---------------------------------------------------------------------------
  // Persistência
  // ---------------------------------------------------------------------------

  let saveTimer: NodeJS.Timeout | null = null;
  let saveDueAt = 0;
  let persistChain: Promise<void> = Promise.resolve();
  const pendingPolicySiteIds = new Set<string>();
  const pendingAlertSiteIds = new Set<string>();

  async function persistNow(): Promise<void> {
    if (saveTimer) {
      clearTimeout(saveTimer);
      saveTimer = null;
    }
    const dirtyPolicies = new Set(pendingPolicySiteIds);
    const dirtyAlerts = new Set(pendingAlertSiteIds);
    pendingPolicySiteIds.clear();
    pendingAlertSiteIds.clear();

    persistChain = persistChain.then(async () => {
      try {
        for (const id of dirtyPolicies) {
          const site = store.sites[id];
          if (site) ensureClassified(site);
        }
        if (usePg) {
          await pgStore.saveFullStore(vendor, store, dirtyPolicies, dirtyAlerts);
          cachedStoreSizeBytes = await pgStore.getDatabaseSizeBytes();
          return;
        }
        for (const site of Object.values(store.sites)) ensureClassified(site);
        await fs.mkdir(dataDir, { recursive: true });
        const serialized = JSON.stringify(store);
        const tmpFile = `${storeFile}.tmp`;
        await fs.writeFile(tmpFile, serialized, { encoding: 'utf8', mode: 0o600 });
        await fs.rename(tmpFile, storeFile);
        cachedStoreSizeBytes = Buffer.byteLength(serialized, 'utf8');
      } catch (err) {
        // Recoloca na fila para a próxima tentativa
        for (const id of dirtyPolicies) pendingPolicySiteIds.add(id);
        for (const id of dirtyAlerts) pendingAlertSiteIds.add(id);
        console.error(`[${vendor}] Erro ao persistir estado:`, err);
      }
    });
    await persistChain;
  }

  function schedulePersist(opts?: {
    policySiteId?: string;
    alertSiteId?: string;
    delayMs?: number;
  }): void {
    if (opts?.policySiteId) pendingPolicySiteIds.add(opts.policySiteId);
    if (opts?.alertSiteId) pendingAlertSiteIds.add(opts.alertSiteId);

    const dueAt = Date.now() + (opts?.delayMs ?? 400);
    if (saveTimer && saveDueAt <= dueAt) return;
    if (saveTimer) clearTimeout(saveTimer);
    saveDueAt = dueAt;
    saveTimer = setTimeout(() => {
      saveTimer = null;
      void persistNow();
    }, Math.max(0, dueAt - Date.now()));
  }

  // Fila de gravação incremental de syslogs no PostgreSQL
  const pendingInserts = new Map<string, SyslogEvent[]>();
  let pendingInsertCount = 0;
  let droppedInsertCount = 0;
  let flushChain: Promise<void> = Promise.resolve();

  function queueInserts(siteId: string, events: SyslogEvent[]): void {
    if (!usePg) return;
    if (pendingInsertCount + events.length > MAX_PENDING_INSERTS) {
      droppedInsertCount += events.length;
      if (droppedInsertCount % 10_000 < events.length) {
        console.error(
          `[${vendor}] Banco não acompanha a ingestão: ${droppedInsertCount} evento(s) descartado(s) da fila de gravação.`
        );
      }
      return;
    }
    let list = pendingInserts.get(siteId);
    if (!list) {
      list = [];
      pendingInserts.set(siteId, list);
    }
    for (const ev of events) list.push(ev);
    pendingInsertCount += events.length;
  }

  function flushPendingInserts(): Promise<void> {
    if (!usePg) return Promise.resolve();
    flushChain = flushChain.then(async () => {
      if (pendingInsertCount === 0) return;
      // O site precisa existir no banco antes dos eventos (chave estrangeira)
      if (saveTimer) await persistNow();

      const batches = [...pendingInserts.entries()];
      pendingInserts.clear();
      pendingInsertCount = 0;

      for (const [siteId, events] of batches) {
        if (!store.sites[siteId]) continue;
        try {
          await pgStore.insertSyslogs(siteId, vendor, events, resolveEventTimeMs);
        } catch (err) {
          console.error(
            `[${vendor}] Falha ao gravar ${events.length} syslog(s); nova tentativa em instantes:`,
            err instanceof Error ? err.message : err
          );
          if (store.sites[siteId]) queueInserts(siteId, events);
        }
      }
    });
    return flushChain;
  }

  async function refreshStoreSize(): Promise<void> {
    if (usePg) {
      cachedStoreSizeBytes = await pgStore.getDatabaseSizeBytes();
      return;
    }
    try {
      const stat = await fs.stat(storeFile);
      cachedStoreSizeBytes = stat.size;
    } catch {
      cachedStoreSizeBytes = 0;
    }
  }

  // ---------------------------------------------------------------------------
  // Ingestão e retenção de syslogs
  // ---------------------------------------------------------------------------

  /** `newEvents` em ordem cronológica (mais antigo primeiro). */
  function appendSyslogsToSite(site: FirewallSiteRecord, newEvents: SyslogEvent[]): number {
    if (newEvents.length === 0) return 0;

    const newestFirst = [...newEvents].reverse();
    site.syslogs = newestFirst.concat(site.syslogs);
    const truncated = site.syslogs.length > MEMORY_WINDOW;
    if (truncated) site.syslogs.length = MEMORY_WINDOW;

    if (!usePg && truncated) {
      // Sem banco, a janela em memória é todo o armazenamento: os totais refletem só ela
      const rt = emptyRuntime();
      rt.syncing = runtimes.get(site.id)?.syncing ?? false;
      addEventsToRuntime(rt, site.syslogs);
      runtimes.set(site.id, rt);
    } else {
      addEventsToRuntime(getRuntime(site), newEvents);
    }

    if (!site.hitsObservedSince) site.hitsObservedSince = new Date().toISOString();
    if (site.rules.length > 0 || site.nats.length > 0) {
      accumulateSyslogHits(site.rules, site.nats, newEvents);
      classifyDirty.add(site.id);
    }

    site.updatedAt = new Date().toISOString();
    queueInserts(site.id, newEvents);
    // Contadores de uso mudam a cada lote: grava as políticas de forma espaçada
    schedulePersist({ policySiteId: site.id, delayMs: usePg ? 30_000 : 5_000 });
    return newEvents.length;
  }

  async function clearSyslogs(site: FirewallSiteRecord): Promise<void> {
    site.syslogs = [];
    const queued = pendingInserts.get(site.id);
    if (queued) {
      pendingInsertCount -= queued.length;
      pendingInserts.delete(site.id);
    }
    if (usePg) {
      await flushChain.catch(() => undefined);
      await pgStore.deleteSyslogs(site.id);
    }
    const rt = emptyRuntime();
    rt.syncing = runtimes.get(site.id)?.syncing ?? false;
    runtimes.set(site.id, rt);
    resetSyslogHits(site);
    site.updatedAt = new Date().toISOString();
  }

  async function purgeExpiredSyslogsForSite(
    site: FirewallSiteRecord,
    forceTimestampUpdate = false
  ): Promise<number> {
    const days = Math.max(1, site.retentionDays || DEFAULT_RETENTION_DAYS);
    const cutoffMs = Date.now() - days * 24 * HOUR_MS;
    const cutoffIso = new Date(cutoffMs).toISOString();

    const before = site.syslogs.length;
    site.syslogs = site.syslogs.filter((ev) => {
      const ms = Date.parse(ev.ingestedAt || '');
      return !Number.isFinite(ms) || ms >= cutoffMs;
    });
    let purged = before - site.syslogs.length;

    if (usePg) {
      await flushPendingInserts();
      purged = await pgStore.purgeSyslogs(site.id, cutoffIso, MAX_ROWS_PER_SITE);
    }

    if (purged > 0) await rebuildRuntime(site);
    if (purged > 0 || forceTimestampUpdate) {
      site.lastPurgeAt = new Date().toISOString();
      site.lastPurgedCount = purged;
      schedulePersist();
    }
    return purged;
  }

  async function purgeExpiredAcrossAllSites(): Promise<void> {
    for (const site of Object.values(store.sites)) {
      try {
        await purgeExpiredSyslogsForSite(site, false);
      } catch (err) {
        console.error(`[${vendor}] Erro na limpeza de retenção de ${site.name}:`, err);
      }
    }
    if (usePg) {
      await pgStore
        .purgeMetrics(new Date(Date.now() - 30 * 24 * HOUR_MS).toISOString())
        .catch(() => undefined);
      await refreshStoreSize();
    }
  }

  // ---------------------------------------------------------------------------
  // Carga inicial
  // ---------------------------------------------------------------------------

  function normalizeLoadedSite(
    raw: Partial<FirewallSiteRecord>,
    fallbackId: string
  ): FirewallSiteRecord {
    const base = createEmptySite(
      raw.id || fallbackId,
      raw.name || defaultSiteName,
      raw.location || ''
    );
    const normalizedLogs = Array.isArray(raw.syslogs)
      ? raw.syslogs.map((ev) => ({
          ...ev,
          ingestedAt: ev.ingestedAt || new Date().toISOString(),
        }))
      : [];
    const site: FirewallSiteRecord = {
      ...base,
      id: raw.id || fallbackId,
      vendor,
      name: raw.name || base.name,
      location: typeof raw.location === 'string' ? raw.location : '',
      notes: typeof raw.notes === 'string' ? raw.notes : '',
      connection: raw.connection
        ? {
            host: String(raw.connection.host || ''),
            port: Number(raw.connection.port || 443),
            protocol: raw.connection.protocol === 'http' ? 'http' : 'https',
            username: String(raw.connection.username || (vendor === 'fortigate' ? 'api-readonly' : 'admin')),
            passwordEncrypted: raw.connection.passwordEncrypted,
            authMode: raw.connection.authMode || (vendor === 'fortigate' ? 'token' : 'basic'),
            vdom: raw.connection.vdom || (vendor === 'fortigate' ? 'root' : undefined),
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
      alertRecords: Array.isArray(raw.alertRecords) ? raw.alertRecords : [],
      autoSyncMinutes:
        typeof raw.autoSyncMinutes === 'number' && raw.autoSyncMinutes >= 0
          ? Math.min(1440, Math.round(raw.autoSyncMinutes))
          : DEFAULT_AUTO_SYNC_MINUTES,
      lastSyncAttemptAt: raw.lastSyncAttemptAt ?? null,
      lastSyncError: raw.lastSyncError ?? null,
      consecutiveSyncFailures:
        typeof raw.consecutiveSyncFailures === 'number' ? raw.consecutiveSyncFailures : 0,
      configChanges: Array.isArray(raw.configChanges) ? raw.configChanges : [],
      hitsObservedSince: raw.hitsObservedSince ?? null,
      metrics: Array.isArray(raw.metrics) ? raw.metrics : [],
      createdAt: raw.createdAt || base.createdAt,
      updatedAt: raw.updatedAt || base.updatedAt,
    };
    classifyDirty.add(site.id);
    return site;
  }

  function hydrateParsedStore(parsed: Record<string, unknown>): void {
    const aiSettings: AiProviderSettings =
      parsed.aiSettings && typeof parsed.aiSettings === 'object'
        ? { ...DEFAULT_AI_SETTINGS, ...(parsed.aiSettings as Partial<AiProviderSettings>) }
        : { ...DEFAULT_AI_SETTINGS };
    const notificationSettings = normalizeNotificationSettings(
      parsed.notificationSettings as Partial<NotificationSettings> | undefined
    );
    const rawUdp = parsed.udpListener as Partial<UdpListenerConfig> | undefined;
    const udpListener: UdpListenerConfig =
      rawUdp && typeof rawUdp === 'object'
        ? {
            enabled: rawUdp.enabled !== false,
            port:
              Number.isInteger(rawUdp.port) && Number(rawUdp.port) > 0 && Number(rawUdp.port) < 65536
                ? Number(rawUdp.port)
                : defaultPort,
            bindAddress: typeof rawUdp.bindAddress === 'string' ? rawUdp.bindAddress : '0.0.0.0',
          }
        : defaultUdpConfig();

    if (parsed && parsed.sites && typeof parsed.sites === 'object' && !Array.isArray(parsed.sites)) {
      const sitesMap: Record<string, FirewallSiteRecord> = {};
      for (const [siteId, rawSite] of Object.entries(
        parsed.sites as Record<string, Partial<FirewallSiteRecord>>
      )) {
        if (rawSite && typeof rawSite === 'object') {
          const normalized = normalizeLoadedSite(rawSite, siteId);
          sitesMap[normalized.id] = normalized;
        }
      }
      if (Object.keys(sitesMap).length === 0) {
        sitesMap[defaultSiteId] = createEmptySite(defaultSiteId);
      }
      const activeId =
        typeof parsed.activeSiteId === 'string' && sitesMap[parsed.activeSiteId]
          ? parsed.activeSiteId
          : Object.keys(sitesMap)[0];

      store = { vendor, activeSiteId: activeId, sites: sitesMap, aiSettings, notificationSettings, udpListener };
    } else if (
      vendor === 'sonicwall' &&
      parsed &&
      Array.isArray(parsed.syslogs) &&
      Array.isArray(parsed.rules) &&
      Array.isArray(parsed.nats)
    ) {
      const migrated = normalizeLoadedSite(
        {
          id: defaultSiteId,
          name: defaultSiteName,
          location: 'Matriz',
          appliance: parsed.appliance as ApplianceMetadata | undefined,
          retentionDays: parsed.retentionDays as number | undefined,
          lastPurgeAt: (parsed.lastPurgeAt as string | null) ?? null,
          lastPurgedCount: (parsed.lastPurgedCount as number | undefined) ?? 0,
          syslogs: parsed.syslogs as SyslogEvent[],
          rules: parsed.rules as FirewallRule[],
          nats: parsed.nats as NatPolicy[],
          telemetry: parsed.telemetry as TelemetrySnapshot | undefined,
          alertSettings: parsed.alertSettings as FirewallSiteRecord['alertSettings'] | undefined,
        },
        defaultSiteId
      );
      store = {
        vendor,
        activeSiteId: defaultSiteId,
        sites: { [defaultSiteId]: migrated },
        aiSettings,
        notificationSettings,
        udpListener,
      };
    }
  }

  async function loadStoreFromStorage(): Promise<void> {
    if (usePg) {
      const hasSites = await pgStore.hasAnySites(vendor);
      if (hasSites) {
        const pgLoaded = await pgStore.loadStore(vendor, MEMORY_WINDOW);
        hydrateParsedStore({
          activeSiteId: pgLoaded.activeSiteId ?? undefined,
          aiSettings: pgLoaded.aiSettings ?? undefined,
          notificationSettings: pgLoaded.notificationSettings ?? undefined,
          udpListener: pgLoaded.udpListener ?? undefined,
          sites: pgLoaded.sites,
        });
      } else {
        // Primeira subida com banco vazio: migra o arquivo JSON legado, se existir
        let legacy: Record<string, unknown> | null = null;
        if (vendor === 'sonicwall') {
          legacy =
            (await pgStore.maybeReadLegacyJsonFile<Record<string, unknown>>(storeFile)) ||
            (await pgStore.maybeReadLegacyJsonFile<Record<string, unknown>>(legacyStoreFile));
        } else {
          legacy = await pgStore.maybeReadLegacyJsonFile<Record<string, unknown>>(storeFile);
        }
        if (legacy) hydrateParsedStore(legacy);

        const sharedAi = await pgStore.loadSharedAiSettings();
        if (sharedAi) store.aiSettings = { ...DEFAULT_AI_SETTINGS, ...sharedAi };
        const sharedNotif = await pgStore.loadSharedSetting<Partial<NotificationSettings>>(
          'notification_settings'
        );
        if (sharedNotif) store.notificationSettings = normalizeNotificationSettings(sharedNotif);

        for (const site of Object.values(store.sites)) ensureClassified(site);
        await pgStore.saveFullStore(vendor, store);
        for (const site of Object.values(store.sites)) {
          if (site.syslogs.length > 0) {
            await pgStore.insertSyslogs(site.id, vendor, site.syslogs, resolveEventTimeMs);
            if (site.syslogs.length > MEMORY_WINDOW) site.syslogs.length = MEMORY_WINDOW;
          }
        }
      }
      for (const site of Object.values(store.sites)) {
        const rt = emptyRuntime();
        applyDbStats(rt, await pgStore.loadSyslogStats(site.id));
        runtimes.set(site.id, rt);
      }
      await refreshStoreSize();
      return;
    }

    try {
      const content = await fs.readFile(storeFile, 'utf8');
      hydrateParsedStore(JSON.parse(content) as Record<string, unknown>);
    } catch {
      if (vendor === 'sonicwall') {
        try {
          const legacyContent = await fs.readFile(legacyStoreFile, 'utf8');
          hydrateParsedStore(JSON.parse(legacyContent) as Record<string, unknown>);
        } catch {
          // Sem arquivo legado
        }
      }
    }
    for (const site of Object.values(store.sites)) {
      if (site.syslogs.length > MEMORY_WINDOW) site.syslogs.length = MEMORY_WINDOW;
    }
    await refreshStoreSize();
  }

  // ---------------------------------------------------------------------------
  // Receptor UDP
  // ---------------------------------------------------------------------------

  const unmatchedSources = new Map<string, UdpUnmatchedSource>();
  let unmatchedEvents = 0;

  function findMatchingSiteForUdpEvent(
    ev: SyslogEvent,
    remoteAddress: string
  ): FirewallSiteRecord | null {
    const sn = (ev.serialNumber || '').trim().toLowerCase();
    const fw = (ev.firewallHost || '').trim().toLowerCase();
    const remote = remoteAddress.trim().toLowerCase();
    const sites = Object.values(store.sites);

    if (sn && sn !== '-') {
      const bySerial = sites.find((s) => s.appliance.serialNumber.trim().toLowerCase() === sn);
      if (bySerial) return bySerial;
    }

    const hostMatches = (s: FirewallSiteRecord, candidate: string) =>
      s.connection.host.trim().toLowerCase() === candidate ||
      s.appliance.host.split(':')[0].trim().toLowerCase() === candidate;

    if (fw && fw !== '-' && fw !== 'sonicwall' && fw !== 'fortigate') {
      const byHost = sites.find((s) => hostMatches(s, fw) || s.name.trim().toLowerCase() === fw);
      if (byHost) return byHost;
    }

    if (remote) {
      const byRemote = sites.find((s) => hostMatches(s, remote));
      if (byRemote) return byRemote;
    }

    // Com um único firewall cadastrado não há ambiguidade
    if (sites.length === 1) return sites[0];
    return null;
  }

  // Eventos UDP são agrupados e aplicados em lotes curtos para suportar taxas altas
  const udpBuffer = new Map<string, SyslogEvent[]>();

  const udpReceiver = new SyslogUdpReceiver((events, remoteAddress) => {
    for (const ev of events) {
      const target = findMatchingSiteForUdpEvent(ev, remoteAddress);
      if (!target) {
        // Não mistura logs de um firewall desconhecido nos dados de outro
        unmatchedEvents += 1;
        const key = `${remoteAddress}|${ev.serialNumber}`;
        const entry = unmatchedSources.get(key) || {
          address: remoteAddress,
          serialNumber: ev.serialNumber || '-',
          count: 0,
          lastSeenAt: ev.ingestedAt,
        };
        entry.count += 1;
        entry.lastSeenAt = ev.ingestedAt;
        unmatchedSources.set(key, entry);
        if (unmatchedSources.size > 50) {
          const oldest = [...unmatchedSources.entries()].sort((a, b) =>
            a[1].lastSeenAt.localeCompare(b[1].lastSeenAt)
          )[0];
          if (oldest) unmatchedSources.delete(oldest[0]);
        }
        continue;
      }
      let list = udpBuffer.get(target.id);
      if (!list) {
        list = [];
        udpBuffer.set(target.id, list);
      }
      list.push(ev);
    }
  }, vendor);

  function flushUdpBuffer(): void {
    if (udpBuffer.size === 0) return;
    const batches = [...udpBuffer.entries()];
    udpBuffer.clear();
    for (const [siteId, events] of batches) {
      const site = store.sites[siteId];
      if (site) appendSyslogsToSite(site, events);
    }
  }

  function getUdpStatus(): UdpListenerStatus {
    return {
      ...udpReceiver.getStatus(),
      unmatchedEvents,
      unmatchedSources: [...unmatchedSources.values()]
        .sort((a, b) => b.count - a.count)
        .slice(0, 10),
    };
  }

  // ---------------------------------------------------------------------------
  // Alertas persistentes e notificações
  // ---------------------------------------------------------------------------

  function getNotificationSettings(): NotificationSettings {
    return normalizeNotificationSettings(store.notificationSettings);
  }

  function notificationChannels(settings: NotificationSettings) {
    return {
      webhookUrl: authManager.decryptSecret(settings.webhookUrlEncrypted),
      telegramBotToken: authManager.decryptSecret(settings.telegramBotTokenEncrypted),
      telegramChatId: settings.telegramChatId,
    };
  }

  function dispatchNotification(
    site: FirewallSiteRecord,
    kind: 'opened' | 'resolved',
    records: AlertRecord[]
  ): void {
    const settings = getNotificationSettings();
    if (!settings.enabled || records.length === 0) return;
    const channels = notificationChannels(settings);
    if (!channels.webhookUrl && !(channels.telegramBotToken && channels.telegramChatId)) return;

    void sendNotification(channels, { kind, vendor, siteName: site.name, alerts: records })
      .then((errors) => {
        if (errors.length > 0) {
          console.error(`[${vendor}] Falha ao notificar (${site.name}): ${errors.join(' | ')}`);
        }
      })
      .catch((err) => console.error(`[${vendor}] Erro ao notificar:`, err));
  }

  function evaluateSiteAlerts(site: FirewallSiteRecord): void {
    const rt = getRuntime(site);
    const settings = normalizeAlertSettings(site.alertSettings);
    const nowMs = Date.now();
    const nowIso = new Date(nowMs).toISOString();

    const detected = evaluateOverviewAlerts(
      site.telemetry || EMPTY_TELEMETRY,
      site.syslogs,
      settings,
      vendor,
      {
        nowMs,
        appliance: site.appliance,
        hourly: [...rt.hourly.entries()].map(([startMs, b]) => ({
          startMs,
          total: b.total,
          blocked: b.blocked,
        })),
        lastEventAtMs: rt.lastEventAtMs,
        udpRunning: udpReceiver.getStatus().running,
        consecutiveSyncFailures: site.consecutiveSyncFailures,
        lastSyncError: site.lastSyncError,
        configChanges: site.configChanges,
      }
    );

    const activeById = new Map<string, AlertRecord>();
    for (const rec of site.alertRecords) {
      if (rec.status !== 'resolved') activeById.set(rec.id, rec);
    }

    let changed = false;
    const opened: AlertRecord[] = [];
    const resolved: AlertRecord[] = [];
    const detectedIds = new Set<string>();

    for (const alert of detected) {
      detectedIds.add(alert.id);
      const existing = activeById.get(alert.id);
      if (existing) {
        if (
          existing.metricValue !== alert.metricValue ||
          existing.severity !== alert.severity ||
          existing.description !== alert.description
        ) {
          changed = true;
        }
        Object.assign(existing, alert, { lastDetectedAt: nowIso });
      } else {
        const rec: AlertRecord = {
          ...alert,
          key: `${alert.id}#${nowMs.toString(36)}`,
          status: 'open',
          firstSeenAt: nowIso,
          lastDetectedAt: nowIso,
          resolvedAt: null,
          acknowledgedBy: null,
          acknowledgedAt: null,
          notifiedAt: null,
        };
        site.alertRecords.unshift(rec);
        opened.push(rec);
        changed = true;
      }
    }

    for (const rec of activeById.values()) {
      if (!detectedIds.has(rec.id)) {
        rec.status = 'resolved';
        rec.resolvedAt = nowIso;
        resolved.push(rec);
        changed = true;
      }
    }

    if (changed) {
      // Mantém todos os ativos e um histórico limitado de resolvidos (30 dias)
      const historyCutoff = nowMs - 30 * 24 * HOUR_MS;
      let resolvedKept = 0;
      site.alertRecords = site.alertRecords.filter((rec) => {
        if (rec.status !== 'resolved') return true;
        const resolvedMs = Date.parse(rec.resolvedAt || '');
        if (Number.isFinite(resolvedMs) && resolvedMs < historyCutoff) return false;
        resolvedKept += 1;
        return resolvedKept <= MAX_RESOLVED_ALERTS;
      });

      const notifSettings = getNotificationSettings();
      const toNotify = opened.filter((r) => severityPasses(r.severity, notifSettings.minSeverity));
      if (notifSettings.enabled && toNotify.length > 0) {
        for (const r of toNotify) r.notifiedAt = nowIso;
        dispatchNotification(site, 'opened', toNotify);
      }
      if (notifSettings.enabled && notifSettings.notifyOnResolve) {
        dispatchNotification(
          site,
          'resolved',
          resolved.filter((r) => r.notifiedAt)
        );
      }
      schedulePersist({ alertSiteId: site.id, delayMs: 2000 });
    }
  }

  function getActiveAlerts(site: FirewallSiteRecord): OverviewAlert[] {
    return site.alertRecords
      .filter((r) => r.status !== 'resolved')
      .sort((a, b) => {
        if (a.status !== b.status) return a.status === 'open' ? -1 : 1;
        if (a.severity !== b.severity) return a.severity === 'critical' ? -1 : 1;
        return b.firstSeenAt.localeCompare(a.firstSeenAt);
      });
  }

  async function evaluateAllSites(): Promise<void> {
    if (usePg) {
      // Configuração de notificação é compartilhada entre os backends
      const shared = await pgStore
        .loadSharedSetting<Partial<NotificationSettings>>('notification_settings')
        .catch(() => null);
      if (shared) store.notificationSettings = normalizeNotificationSettings(shared);
    }
    for (const site of Object.values(store.sites)) {
      try {
        evaluateSiteAlerts(site);
      } catch (err) {
        console.error(`[${vendor}] Erro ao avaliar alertas de ${site.name}:`, err);
      }
    }
  }

  // ---------------------------------------------------------------------------
  // Visão geral
  // ---------------------------------------------------------------------------

  function toPublicConnection(site: FirewallSiteRecord): FirewallConnectionPublic {
    return {
      host: site.connection.host,
      port: site.connection.port,
      protocol: site.connection.protocol,
      username: site.connection.username,
      hasSavedPassword: Boolean(site.connection.passwordEncrypted),
      authMode: site.connection.authMode || (vendor === 'fortigate' ? 'token' : 'basic'),
      vdom: site.connection.vdom || (vendor === 'fortigate' ? 'root' : undefined),
      ignoreTlsErrors: site.connection.ignoreTlsErrors,
    };
  }

  function toSyncStatus(site: FirewallSiteRecord): SyncStatus {
    return {
      autoSyncMinutes: site.autoSyncMinutes,
      lastAttemptAt: site.lastSyncAttemptAt,
      lastError: site.lastSyncError,
      consecutiveFailures: site.consecutiveSyncFailures,
    };
  }

  function toSiteSummary(site: FirewallSiteRecord): FirewallSiteSummary {
    const active = site.alertRecords.filter((r) => r.status !== 'resolved');
    return {
      id: site.id,
      vendor,
      name: site.name,
      location: site.location,
      notes: site.notes,
      appliance: site.appliance,
      connection: toPublicConnection(site),
      totalSyslogs: getRuntime(site).total,
      rulesCount: site.rules.length,
      natsCount: site.nats.length,
      alertsCount: active.length,
      criticalAlertsCount: active.filter((a) => a.severity === 'critical').length,
      sync: toSyncStatus(site),
      createdAt: site.createdAt,
      updatedAt: site.updatedAt,
    };
  }

  function listAllSiteSummaries(): FirewallSiteSummary[] {
    return Object.values(store.sites)
      .map(toSiteSummary)
      .sort((a, b) => a.createdAt.localeCompare(b.createdAt));
  }

  function buildOverview(site: FirewallSiteRecord): AuditOverview {
    ensureClassified(site);
    const rt = getRuntime(site);

    // Totais valem para todo o histórico armazenado
    const allow = rt.byAction.allow || 0;
    const blocked = (rt.byAction.drop || 0) + (rt.byAction.deny || 0) + (rt.byAction.reset || 0);
    const system = Math.max(0, rt.total - allow - blocked);
    const criticalAndError =
      (rt.bySeverity.emergency || 0) +
      (rt.bySeverity.alert || 0) +
      (rt.bySeverity.critical || 0) +
      (rt.bySeverity.error || 0);
    const warning = rt.bySeverity.warning || 0;
    const infoAndNotice = Math.max(0, rt.total - criticalAndError - warning);

    const currentHourStart = Math.floor(Date.now() / HOUR_MS) * HOUR_MS;
    const hourlyLogVolume = [];
    for (let offset = 23; offset >= 0; offset -= 1) {
      const startMs = currentHourStart - offset * HOUR_MS;
      const bucket = rt.hourly.get(startMs);
      hourlyLogVolume.push({
        hourLabel: `${String(new Date(startMs).getHours()).padStart(2, '0')}:00`,
        total: bucket?.total ?? 0,
        allow: bucket?.allow ?? 0,
        blocked: bucket?.blocked ?? 0,
      });
    }

    // Rankings usam a janela recente em memória
    const blockedSrcCounts = new Map<string, { count: number; zone: string }>();
    const portCounts = new Map<
      string,
      { port: string; protocol: string; count: number; blocked: number }
    >();
    const zoneCounts = new Map<string, { allow: number; blocked: number }>();

    for (const ev of site.syslogs) {
      const isBlocked = isBlockedAction(ev.action);
      if (isBlocked && ev.srcIp !== '-') {
        const prev = blockedSrcCounts.get(ev.srcIp) || { count: 0, zone: ev.srcZone };
        blockedSrcCounts.set(ev.srcIp, { count: prev.count + 1, zone: ev.srcZone });
      }
      if (ev.dstPort !== null) {
        const key = `${ev.protocol.split('/')[0]}-${ev.dstPort}`;
        const prev = portCounts.get(key) || {
          port: String(ev.dstPort),
          protocol: ev.protocol,
          count: 0,
          blocked: 0,
        };
        prev.count += 1;
        if (isBlocked) prev.blocked += 1;
        portCounts.set(key, prev);
      }
      const pair = `${ev.srcZone} -> ${ev.dstZone}`;
      const zPrev = zoneCounts.get(pair) || { allow: 0, blocked: 0 };
      if (isBlocked) zPrev.blocked += 1;
      else if (ev.action === 'allow') zPrev.allow += 1;
      zoneCounts.set(pair, zPrev);
    }

    return {
      vendor,
      activeSite: {
        id: site.id,
        vendor,
        name: site.name,
        location: site.location,
        notes: site.notes,
        connection: toPublicConnection(site),
      },
      sites: listAllSiteSummaries(),
      appliance: site.appliance,
      totalSyslogs: rt.total,
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
      topBlockedSources: Array.from(blockedSrcCounts.entries())
        .map(([ip, v]) => ({ ip, count: v.count, zone: v.zone }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 8),
      topTargetedPorts: Array.from(portCounts.values())
        .sort((a, b) => b.count - a.count)
        .slice(0, 8),
      zoneTraffic: Array.from(zoneCounts.entries())
        .map(([pair, v]) => ({ pair, allow: v.allow, blocked: v.blocked }))
        .sort((a, b) => b.allow + b.blocked - (a.allow + a.blocked))
        .slice(0, 8),
      hourlyLogVolume,
      telemetry: site.telemetry || EMPTY_TELEMETRY,
      alertSettings: normalizeAlertSettings(site.alertSettings),
      alerts: getActiveAlerts(site),
      udpStatus: getUdpStatus(),
      retention: {
        retentionDays: site.retentionDays,
        autoPurgeEnabled: true,
        lastPurgeAt: site.lastPurgeAt,
        lastPurgedCount: site.lastPurgedCount,
        oldestEventAt: rt.oldestAt,
        newestEventAt: rt.newestAt,
        storeSizeBytes: cachedStoreSizeBytes,
      },
      analysisWindowSize: site.syslogs.length,
      sync: toSyncStatus(site),
      configChanges: site.configChanges.slice(0, 10),
      hitsObservedSince: site.hitsObservedSince,
    };
  }

  // ---------------------------------------------------------------------------
  // Sincronização com a API do firewall
  // ---------------------------------------------------------------------------

  function policySignature(p: FirewallRule | NatPolicy): string {
    if ('fromZone' in p) {
      return [p.name, p.fromZone, p.toZone, p.source, p.destination, p.service, p.action, p.enabled].join('|');
    }
    return [
      p.name,
      p.inboundInterface,
      p.outboundInterface,
      p.origSource,
      p.transSource,
      p.origDestination,
      p.transDestination,
      p.origService,
      p.transService,
      p.enabled,
    ].join('|');
  }

  function diffPolicies<T extends FirewallRule | NatPolicy>(
    label: string,
    previous: T[],
    next: T[],
    details: string[]
  ): { added: number; removed: number; modified: number } {
    const keyOf = (p: T) => p.uuid || p.id;
    const prevMap = new Map(previous.map((p) => [keyOf(p), p]));
    const nextMap = new Map(next.map((p) => [keyOf(p), p]));
    let added = 0;
    let removed = 0;
    let modified = 0;

    for (const [key, p] of nextMap) {
      const old = prevMap.get(key);
      if (!old) {
        added += 1;
        details.push(`+ ${label} "${p.name}"`);
      } else if (policySignature(old) !== policySignature(p)) {
        modified += 1;
        details.push(
          old.enabled !== p.enabled
            ? `~ ${label} "${p.name}" ${p.enabled ? 'habilitada' : 'desabilitada'}`
            : `~ ${label} "${p.name}" alterada`
        );
      }
    }
    for (const [key, p] of prevMap) {
      if (!nextMap.has(key)) {
        removed += 1;
        details.push(`- ${label} "${p.name}"`);
      }
    }
    return { added, removed, modified };
  }

  async function recordMetricSample(site: FirewallSiteRecord): Promise<void> {
    const wan = (site.telemetry?.interfaces || []).filter((i) => i.role !== 'internal');
    const sample: MetricSample = {
      ts: new Date().toISOString(),
      cpuPercent: site.appliance.cpuPercent ?? null,
      memoryPercent: site.appliance.memoryPercent ?? null,
      activeConnections: site.appliance.activeConnections ?? null,
      wanRxMbps: Number(wan.reduce((sum, i) => sum + i.rxMbps, 0).toFixed(2)),
      wanTxMbps: Number(wan.reduce((sum, i) => sum + i.txMbps, 0).toFixed(2)),
    };
    if (usePg) {
      await pgStore.insertMetric(site.id, sample).catch((err) => {
        console.error(`[${vendor}] Falha ao gravar métrica:`, err instanceof Error ? err.message : err);
      });
    } else {
      site.metrics = [...(site.metrics || []), sample].slice(-MAX_LOCAL_METRICS);
    }
  }

  async function syncSiteWithApi(
    site: FirewallSiteRecord,
    overrides?: {
      host?: string;
      port?: number;
      protocol?: 'https' | 'http';
      username?: string;
      password?: string;
      vdom?: string;
      ignoreTlsErrors?: boolean;
      savePassword?: boolean;
    }
  ): Promise<{ rulesCount: number; natsCount: number }> {
    const rt = getRuntime(site);
    if (rt.syncing) {
      throw new Error('Já existe uma sincronização em andamento para este firewall.');
    }
    rt.syncing = true;
    site.lastSyncAttemptAt = new Date().toISOString();

    try {
      const host = (overrides?.host ?? site.connection.host).trim();
      const port = Number(overrides?.port ?? site.connection.port ?? 443);
      const protocol =
        (overrides?.protocol ?? site.connection.protocol) === 'http' ? 'http' : 'https';
      const username = (overrides?.username ?? site.connection.username).trim();
      const vdom = (overrides?.vdom ?? site.connection.vdom ?? 'root').trim() || 'root';
      const ignoreTlsErrors = overrides?.ignoreTlsErrors ?? site.connection.ignoreTlsErrors ?? true;
      const rawSecret = overrides?.password ? String(overrides.password) : '';
      const effectiveSecret =
        rawSecret || authManager.decryptSecret(site.connection.passwordEncrypted);

      const nextPasswordEncrypted =
        overrides?.savePassword && rawSecret
          ? authManager.encryptSecret(rawSecret)
          : rawSecret && overrides?.savePassword === false
            ? undefined
            : site.connection.passwordEncrypted ||
              (overrides?.savePassword ? authManager.encryptSecret(effectiveSecret) : undefined);

      const previousRules = site.rules;
      const previousNats = site.nats;
      const hadApiBaseline =
        site.appliance.dataSource === 'api' && (previousRules.length > 0 || previousNats.length > 0);

      let nextRules: FirewallRule[];
      let nextNats: NatPolicy[];

      if (vendor === 'fortigate') {
        if (!host || !effectiveSecret) {
          throw new Error(
            'Informe o host/IP e o Token Bearer da API REST do FortiGate (ou salve o token nesta localidade).'
          );
        }

        const audit = await fetchFortiOsAudit({
          host,
          port,
          protocol,
          token: effectiveSecret,
          vdom,
          ignoreTlsErrors,
        });

        site.connection = {
          host,
          port,
          protocol,
          username: username || 'api-readonly',
          authMode: 'token',
          vdom,
          ignoreTlsErrors,
          passwordEncrypted: nextPasswordEncrypted,
        };

        nextRules = audit.rules;
        nextNats = audit.nats;
        site.telemetry = audit.telemetry;
        site.appliance = {
          model: audit.model,
          serialNumber: audit.serialNumber,
          firmware: audit.firmware,
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
      } else {
        if (!host || !username || !effectiveSecret) {
          throw new Error(
            'Informe host/IP, usuário e senha do SonicWall (ou salve a senha nesta localidade).'
          );
        }

        const audit = await fetchSonicOsAudit({
          host,
          port,
          protocol,
          username,
          password: effectiveSecret,
          ignoreTlsErrors,
        });

        site.connection = {
          host,
          port,
          protocol,
          username,
          authMode: 'basic',
          ignoreTlsErrors,
          passwordEncrypted: nextPasswordEncrypted,
        };

        nextRules = audit.rules;
        nextNats = audit.nats;
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
      }

      // Detecção de mudança de configuração entre duas coletas via API
      if (hadApiBaseline) {
        const details: string[] = [];
        const r = diffPolicies('regra', previousRules, nextRules, details);
        const n = diffPolicies('NAT', previousNats, nextNats, details);
        if (r.added + r.removed + r.modified + n.added + n.removed + n.modified > 0) {
          const entry: ConfigChangeEntry = {
            at: new Date().toISOString(),
            rulesAdded: r.added,
            rulesRemoved: r.removed,
            rulesModified: r.modified,
            natsAdded: n.added,
            natsRemoved: n.removed,
            natsModified: n.modified,
            details: details.slice(0, 20),
          };
          site.configChanges = [entry, ...site.configChanges].slice(0, MAX_CONFIG_CHANGES);
        }
      }

      // Preserva o uso já observado nos syslogs para as políticas que continuam existindo
      carryOverSyslogHits(previousRules, nextRules);
      carryOverSyslogHits(previousNats, nextNats);
      site.rules = nextRules;
      site.nats = nextNats;
      classifyDirty.add(site.id);

      site.lastSyncError = null;
      site.consecutiveSyncFailures = 0;
      site.updatedAt = new Date().toISOString();
      await recordMetricSample(site);
      evaluateSiteAlerts(site);
      schedulePersist({ policySiteId: site.id });

      return { rulesCount: site.rules.length, natsCount: site.nats.length };
    } catch (err) {
      site.lastSyncError = err instanceof Error ? err.message : 'Erro desconhecido';
      site.consecutiveSyncFailures += 1;
      schedulePersist();
      throw err;
    } finally {
      rt.syncing = false;
    }
  }

  async function runScheduledSyncs(): Promise<void> {
    const now = Date.now();
    for (const site of Object.values(store.sites)) {
      if (site.autoSyncMinutes <= 0) continue;
      if (!site.connection.host || !site.connection.passwordEncrypted) continue;
      if (getRuntime(site).syncing) continue;
      const lastMs = Date.parse(site.lastSyncAttemptAt || '');
      if (Number.isFinite(lastMs) && now - lastMs < site.autoSyncMinutes * 60 * 1000) continue;
      try {
        await syncSiteWithApi(site);
      } catch (err) {
        console.warn(
          `[${vendor}] Sincronização automática de ${site.name} falhou (${site.consecutiveSyncFailures}x): ${err instanceof Error ? err.message : err}`
        );
        evaluateSiteAlerts(site);
      }
    }
  }

  // ---------------------------------------------------------------------------
  // IA: a chave fica cifrada em repouso
  // ---------------------------------------------------------------------------

  function decryptAiKey(stored: string): string {
    if (!stored) return '';
    return stored.startsWith(ENC_PREFIX) ? authManager.decryptSecret(stored.slice(ENC_PREFIX.length)) : stored;
  }

  function getAiSettingsPlain(): AiProviderSettings {
    const current = store.aiSettings || DEFAULT_AI_SETTINGS;
    return { ...current, apiKey: decryptAiKey(current.apiKey) };
  }

  async function reloadSharedAiSettings(): Promise<void> {
    if (!usePg) return;
    const shared = await pgStore.loadSharedAiSettings();
    if (shared) store.aiSettings = { ...DEFAULT_AI_SETTINGS, ...shared };
  }

  // ---------------------------------------------------------------------------
  // Rotas
  // ---------------------------------------------------------------------------

  const router = express.Router();

  const asyncRoute =
    (handler: (req: express.Request, res: express.Response) => Promise<void>) =>
    (req: express.Request, res: express.Response) => {
      handler(req, res).catch((err) => {
        console.error(`[${vendor}] Erro em ${req.method} ${req.path}:`, err);
        if (!res.headersSent) {
          res.status(500).json({ error: 'Erro interno ao processar a requisição.' });
        }
      });
    };

  router.get('/sites', (_req, res) => {
    res.json({
      vendor,
      activeSiteId: getActiveSite().id,
      sites: listAllSiteSummaries(),
    });
  });

  router.post('/sites', (req, res) => {
    const name = String(req.body?.name || '').trim();
    const location = String(req.body?.location || '').trim();
    const notes = String(req.body?.notes || '').trim();

    if (!name) {
      res.status(400).json({ error: 'Informe o nome da localidade ou firewall.' });
      return;
    }

    const prefix = vendor === 'fortigate' ? 'fgt' : 'site';
    const id = `${prefix}-${crypto.randomUUID().slice(0, 8)}`;
    const site = createEmptySite(id, name, location);
    site.notes = notes;
    const autoSync = Number(req.body?.autoSyncMinutes);
    if (Number.isInteger(autoSync) && autoSync >= 0 && autoSync <= 1440) {
      site.autoSyncMinutes = autoSync;
    }

    const conn = req.body?.connection;
    if (conn && typeof conn === 'object') {
      const rawHost = String(conn.host || '').trim();
      const rawPassword = typeof conn.password === 'string' ? conn.password : '';
      const savePassword = Boolean(conn.savePassword);
      site.connection = {
        host: rawHost,
        port: Number(conn.port || 443),
        protocol: conn.protocol === 'http' ? 'http' : 'https',
        username:
          String(conn.username || (vendor === 'fortigate' ? 'api-readonly' : 'admin')).trim() ||
          'admin',
        passwordEncrypted:
          savePassword && rawPassword ? authManager.encryptSecret(rawPassword) : undefined,
        authMode: vendor === 'fortigate' ? 'token' : 'basic',
        vdom:
          vendor === 'fortigate'
            ? String(conn.vdom || 'root').trim() || 'root'
            : undefined,
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
    schedulePersist({ policySiteId: site.id, alertSiteId: site.id });

    res.json({
      ok: true,
      site: toSiteSummary(site),
      overview: buildOverview(req.body?.select !== false ? site : siteFor(req)),
    });
  });

  router.put('/sites/:id', (req, res) => {
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

    if (req.body?.autoSyncMinutes !== undefined) {
      const minutes = Number(req.body.autoSyncMinutes);
      if (!Number.isInteger(minutes) || minutes < 0 || minutes > 1440) {
        res.status(400).json({ error: 'Intervalo de sincronização deve ficar entre 0 e 1440 minutos.' });
        return;
      }
      site.autoSyncMinutes = minutes;
    }

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
        username:
          typeof conn.username === 'string' ? conn.username.trim() : site.connection.username,
        passwordEncrypted: nextEncrypted,
        authMode: vendor === 'fortigate' ? 'token' : 'basic',
        vdom:
          vendor === 'fortigate'
            ? typeof conn.vdom === 'string'
              ? conn.vdom.trim() || 'root'
              : site.connection.vdom || 'root'
            : undefined,
        ignoreTlsErrors: conn.ignoreTlsErrors !== false,
      };
    }

    site.updatedAt = new Date().toISOString();
    schedulePersist();
    res.json({
      ok: true,
      site: toSiteSummary(site),
      overview: buildOverview(siteFor(req)),
    });
  });

  router.post('/sites/:id/select', (req, res) => {
    const site = store.sites[req.params.id];
    if (!site) {
      res.status(404).json({ error: 'Localidade não encontrada.' });
      return;
    }
    store.activeSiteId = site.id;
    schedulePersist();
    res.json({ ok: true, overview: buildOverview(site) });
  });

  router.post(
    '/sites/:id/sync',
    asyncRoute(async (req, res) => {
      const site = store.sites[req.params.id];
      if (!site) {
        res.status(404).json({ error: 'Localidade não encontrada.' });
        return;
      }
      try {
        const result = await syncSiteWithApi(site, {
          host: typeof req.body?.host === 'string' ? req.body.host : undefined,
          port: req.body?.port !== undefined ? Number(req.body.port) : undefined,
          protocol:
            req.body?.protocol === 'http'
              ? 'http'
              : req.body?.protocol === 'https'
                ? 'https'
                : undefined,
          username: typeof req.body?.username === 'string' ? req.body.username : undefined,
          password: typeof req.body?.password === 'string' ? req.body.password : undefined,
          vdom: typeof req.body?.vdom === 'string' ? req.body.vdom : undefined,
          ignoreTlsErrors:
            typeof req.body?.ignoreTlsErrors === 'boolean' ? req.body.ignoreTlsErrors : undefined,
          savePassword:
            typeof req.body?.savePassword === 'boolean' ? req.body.savePassword : undefined,
        });
        res.json({ ok: true, ...result, overview: buildOverview(siteFor(req)) });
      } catch (err) {
        const message =
          err instanceof Error ? err.message : 'Erro ao sincronizar localidade com a API.';
        res.status(502).json({ error: message });
      }
    })
  );

  router.delete('/sites/:id', (req, res) => {
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
    runtimes.delete(req.params.id);
    udpBuffer.delete(req.params.id);
    const queued = pendingInserts.get(req.params.id);
    if (queued) {
      pendingInsertCount -= queued.length;
      pendingInserts.delete(req.params.id);
    }
    if (store.activeSiteId === req.params.id) {
      store.activeSiteId = Object.keys(store.sites)[0];
    }
    schedulePersist();
    res.json({ ok: true, overview: buildOverview(siteFor(req)) });
  });

  router.get('/overview', (req, res) => {
    res.json(buildOverview(siteFor(req)));
  });

  // --- Alertas ---------------------------------------------------------------

  router.get('/alerts', (req, res) => {
    const site = siteFor(req);
    const limit = Math.min(500, Math.max(10, Number(req.query.limit || 100)));
    res.json({
      active: getActiveAlerts(site),
      history: site.alertRecords
        .filter((r) => r.status === 'resolved')
        .sort((a, b) => (b.resolvedAt || '').localeCompare(a.resolvedAt || ''))
        .slice(0, limit),
    });
  });

  const handleAck = (acknowledge: boolean) => (req: express.Request, res: express.Response) => {
    const site = siteFor(req);
    const key = String(req.body?.key || '');
    const rec = site.alertRecords.find((r) => r.key === key && r.status !== 'resolved');
    if (!rec) {
      res.status(404).json({ error: 'Alerta não encontrado ou já resolvido.' });
      return;
    }
    rec.status = acknowledge ? 'acknowledged' : 'open';
    rec.acknowledgedBy = acknowledge ? String(res.locals.username || 'admin') : null;
    rec.acknowledgedAt = acknowledge ? new Date().toISOString() : null;
    schedulePersist({ alertSiteId: site.id });
    res.json({ ok: true, overview: buildOverview(site) });
  };

  router.post('/alerts/ack', handleAck(true));
  router.post('/alerts/unack', handleAck(false));

  router.post('/alerts/ack-all', (req, res) => {
    const site = siteFor(req);
    const now = new Date().toISOString();
    for (const rec of site.alertRecords) {
      if (rec.status === 'open') {
        rec.status = 'acknowledged';
        rec.acknowledgedBy = String(res.locals.username || 'admin');
        rec.acknowledgedAt = now;
      }
    }
    schedulePersist({ alertSiteId: site.id });
    res.json({ ok: true, overview: buildOverview(site) });
  });

  router.get('/alerts/config', (req, res) => {
    res.json(normalizeAlertSettings(siteFor(req).alertSettings));
  });

  router.post('/alerts/config', (req, res) => {
    const site = siteFor(req);
    const nextSettings = normalizeAlertSettings({
      ...normalizeAlertSettings(site.alertSettings),
      ...(req.body && typeof req.body === 'object' ? req.body : {}),
    });
    site.alertSettings = nextSettings;
    site.updatedAt = new Date().toISOString();
    evaluateSiteAlerts(site);
    schedulePersist();
    res.json({
      ok: true,
      alertSettings: nextSettings,
      overview: buildOverview(site),
    });
  });

  // --- Notificações ----------------------------------------------------------

  router.get(
    '/notifications/config',
    asyncRoute(async (_req, res) => {
      if (usePg) {
        const shared = await pgStore.loadSharedSetting<Partial<NotificationSettings>>(
          'notification_settings'
        );
        if (shared) store.notificationSettings = normalizeNotificationSettings(shared);
      }
      res.json(toPublicNotificationConfig(getNotificationSettings()));
    })
  );

  router.post(
    '/notifications/config',
    asyncRoute(async (req, res) => {
      const prev = getNotificationSettings();
      const body = req.body && typeof req.body === 'object' ? req.body : {};
      const next: NotificationSettings = { ...prev };

      if (typeof body.enabled === 'boolean') next.enabled = body.enabled;
      if (body.minSeverity === 'warning' || body.minSeverity === 'critical') {
        next.minSeverity = body.minSeverity;
      }
      if (typeof body.notifyOnResolve === 'boolean') next.notifyOnResolve = body.notifyOnResolve;

      if (body.clearWebhook) {
        next.webhookUrlEncrypted = '';
      } else if (typeof body.webhookUrl === 'string' && body.webhookUrl.trim()) {
        let parsedUrl: URL;
        try {
          parsedUrl = new URL(body.webhookUrl.trim());
        } catch {
          res.status(400).json({ error: 'URL de webhook inválida.' });
          return;
        }
        if (parsedUrl.protocol !== 'https:' && parsedUrl.protocol !== 'http:') {
          res.status(400).json({ error: 'O webhook deve usar http:// ou https://.' });
          return;
        }
        next.webhookUrlEncrypted = authManager.encryptSecret(parsedUrl.toString());
      }

      if (body.clearTelegram) {
        next.telegramBotTokenEncrypted = '';
        next.telegramChatId = '';
      } else {
        if (typeof body.telegramBotToken === 'string' && body.telegramBotToken.trim()) {
          next.telegramBotTokenEncrypted = authManager.encryptSecret(body.telegramBotToken.trim());
        }
        if (typeof body.telegramChatId === 'string') {
          next.telegramChatId = body.telegramChatId.trim();
        }
      }

      store.notificationSettings = next;
      if (usePg) {
        await pgStore.saveSharedSetting('notification_settings', next);
      } else {
        schedulePersist();
      }
      res.json(toPublicNotificationConfig(next));
    })
  );

  router.post(
    '/notifications/test',
    asyncRoute(async (req, res) => {
      const site = siteFor(req);
      const channels = notificationChannels(getNotificationSettings());
      if (!channels.webhookUrl && !(channels.telegramBotToken && channels.telegramChatId)) {
        res.status(400).json({ error: 'Configure um webhook ou o Telegram antes de testar.' });
        return;
      }
      const errors = await sendNotification(channels, {
        kind: 'test',
        vendor,
        siteName: site.name,
        alerts: [],
      });
      if (errors.length > 0) {
        res.status(502).json({ error: errors.join(' | ') });
        return;
      }
      res.json({ ok: true });
    })
  );

  // --- Métricas --------------------------------------------------------------

  router.get(
    '/metrics',
    asyncRoute(async (req, res) => {
      const site = siteFor(req);
      const hours = Math.min(720, Math.max(1, Number(req.query.hours || 24)));
      const sinceIso = new Date(Date.now() - hours * HOUR_MS).toISOString();
      const samples = usePg
        ? await pgStore.loadMetrics(site.id, sinceIso)
        : (site.metrics || []).filter((m) => m.ts >= sinceIso);
      res.json({ hours, samples, sync: toSyncStatus(site) });
    })
  );

  // --- Retenção --------------------------------------------------------------

  router.get('/retention', (req, res) => {
    res.json(buildOverview(siteFor(req)).retention);
  });

  router.post(
    '/retention',
    asyncRoute(async (req, res) => {
      const site = siteFor(req);
      const days = Number(req.body?.retentionDays);
      if (!Number.isInteger(days) || days < 1 || days > 365) {
        res.status(400).json({ error: 'Informe um período de retenção entre 1 e 365 dias.' });
        return;
      }
      site.retentionDays = days;
      site.updatedAt = new Date().toISOString();
      const purged = await purgeExpiredSyslogsForSite(site, true);
      schedulePersist();
      const overview = buildOverview(site);
      res.json({ ok: true, purged, retention: overview.retention, overview });
    })
  );

  router.post(
    '/retention/purge',
    asyncRoute(async (req, res) => {
      const site = siteFor(req);
      const purged = await purgeExpiredSyslogsForSite(site, true);
      const overview = buildOverview(site);
      res.json({ ok: true, purged, retention: overview.retention, overview });
    })
  );

  // --- Relatórios ------------------------------------------------------------

  router.get('/report', (req, res) => {
    const site = siteFor(req);
    const overview = buildOverview(site);
    res.json(buildAuditReport(overview, site.syslogs, site.rules, site.nats));
  });

  router.get('/report/download', (req, res) => {
    const site = siteFor(req);
    const format = String(req.query.format || 'html').toLowerCase();
    const overview = buildOverview(site);
    const report = buildAuditReport(overview, site.syslogs, site.rules, site.nats);
    const stamp = new Date().toISOString().slice(0, 10);
    const slug = vendor === 'fortigate' ? 'fortigate' : 'sonicwall';

    if (format === 'md' || format === 'markdown') {
      res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
      res.setHeader('Content-Disposition', `attachment; filename="fwaudit-${slug}-${stamp}.md"`);
      res.send(renderReportMarkdown(report));
      return;
    }

    if (format === 'json') {
      res.setHeader('Content-Type', 'application/json; charset=utf-8');
      res.setHeader('Content-Disposition', `attachment; filename="fwaudit-${slug}-${stamp}.json"`);
      res.send(JSON.stringify(report, null, 2));
      return;
    }

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="fwaudit-${slug}-${stamp}.html"`);
    res.send(renderReportHtml(report));
  });

  // --- Syslogs ---------------------------------------------------------------

  router.get(
    '/syslogs',
    asyncRoute(async (req, res) => {
      const site = siteFor(req);
      const search = String(req.query.q || '').trim().toLowerCase();
      const action = String(req.query.action || 'all').toLowerCase();
      const severity = String(req.query.severity || 'all').toLowerCase();
      const limit = Math.min(1000, Math.max(10, Number(req.query.limit || 250)));
      const offset = Math.max(0, Math.floor(Number(req.query.offset || 0)) || 0);
      const total = getRuntime(site).total;

      if (usePg) {
        // Busca em todo o histórico retido, direto no banco
        await flushPendingInserts();
        const result = await pgStore.querySyslogs(site.id, { search, action, severity, limit, offset });
        res.json({ total, matched: result.matched, events: result.events, offset, limit });
        return;
      }

      const filtered = site.syslogs.filter((ev) => {
        if (action !== 'all') {
          if (action === 'blocked') {
            if (!isBlockedAction(ev.action)) return false;
          } else if (ev.action !== action) {
            return false;
          }
        }
        if (severity !== 'all' && ev.severity !== severity) return false;
        if (search && !buildSyslogSearchText(ev).includes(search)) return false;
        return true;
      });

      res.json({
        total,
        matched: filtered.length,
        events: filtered.slice(offset, offset + limit),
        offset,
        limit,
      });
    })
  );

  router.post(
    '/syslogs/ingest',
    asyncRoute(async (req, res) => {
      const site = siteFor(req);
      const rawText = typeof req.body === 'string' ? req.body : String(req.body?.content || '');
      const source = (
        typeof req.body === 'object' && req.body?.source === 'paste' ? 'paste' : 'upload'
      ) as SyslogEvent['source'];
      const replace = Boolean(typeof req.body === 'object' && req.body?.replace);

      if (!rawText.trim()) {
        res.status(400).json({ error: 'Conteúdo de syslog vazio.' });
        return;
      }

      const parsed =
        vendor === 'fortigate'
          ? parseFortiGateSyslog(rawText, source)
          : parseSonicWallSyslog(rawText, source);

      if (parsed.length === 0) {
        res.status(422).json({
          error:
            vendor === 'fortigate'
              ? 'Nenhuma linha válida de syslog FortiOS (key=value) foi reconhecida.'
              : 'Nenhuma linha válida de syslog SonicWall foi reconhecida.',
        });
        return;
      }

      if (replace) await clearSyslogs(site);

      const added = appendSyslogsToSite(site, parsed);
      evaluateSiteAlerts(site);
      res.json({ added, total: getRuntime(site).total, overview: buildOverview(site) });
    })
  );

  router.delete(
    '/syslogs',
    asyncRoute(async (req, res) => {
      const site = siteFor(req);
      await clearSyslogs(site);
      evaluateSiteAlerts(site);
      schedulePersist({ policySiteId: site.id });
      res.json({ ok: true, overview: buildOverview(site) });
    })
  );

  // --- Políticas -------------------------------------------------------------

  router.get('/rules', (req, res) => {
    const site = siteFor(req);
    ensureClassified(site);
    res.json({ rules: site.rules, appliance: site.appliance, hitsObservedSince: site.hitsObservedSince });
  });

  router.get('/nats', (req, res) => {
    const site = siteFor(req);
    ensureClassified(site);
    res.json({ nats: site.nats, appliance: site.appliance, hitsObservedSince: site.hitsObservedSince });
  });

  router.post('/config/import', (req, res) => {
    const site = siteFor(req);
    const content = String(req.body?.content || '');
    const filename = String(req.body?.filename || 'config');
    if (!content.trim()) {
      res.status(400).json({ error: 'Arquivo de configuração vazio.' });
      return;
    }

    if (vendor === 'fortigate') {
      res.status(422).json({
        error:
          'No módulo FortiGate, conecte diretamente via API REST do FortiOS (/api/v2) na aba Localidades & Conexão ou envie logs via Syslog UDP (5515).',
      });
      return;
    }

    let nextRules: FirewallRule[];
    let nextNats: NatPolicy[];

    const trimmed = content.trim();
    if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
      try {
        const result = parseSonicOsJson(JSON.parse(trimmed), 'json');
        nextRules = result.rules;
        nextNats = result.nats;
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
      nextRules = expResult.rules;
      nextNats = expResult.nats;
      site.appliance = {
        model: expResult.model || 'Arquivo .exp SonicWall',
        serialNumber: expResult.serialNumber || '-',
        firmware: expResult.firmware || 'Config Export (.exp)',
        host: filename,
        lastSyncAt: new Date().toISOString(),
        dataSource: 'exp',
      };
    }

    // Conta o uso das novas políticas sobre os eventos recentes já em memória
    accumulateSyslogHits(nextRules, nextNats, site.syslogs);
    site.rules = nextRules;
    site.nats = nextNats;
    if (site.syslogs.length > 0 && !site.hitsObservedSince) {
      site.hitsObservedSince = new Date().toISOString();
    }
    classifyDirty.add(site.id);

    site.telemetry = { ...EMPTY_TELEMETRY };
    site.updatedAt = new Date().toISOString();
    evaluateSiteAlerts(site);
    schedulePersist({ policySiteId: site.id });
    res.json({
      rulesCount: nextRules.length,
      natsCount: nextNats.length,
      overview: buildOverview(site),
    });
  });

  const handleAuditConnect = asyncRoute(async (req, res) => {
    const targetSiteId = typeof req.body?.siteId === 'string' ? req.body.siteId : '';
    const site = store.sites[targetSiteId] || siteFor(req);
    const host = String(req.body?.host ?? site.connection.host ?? '').trim();
    const port = Number(req.body?.port ?? site.connection.port ?? 443);
    const protocol = (req.body?.protocol ?? site.connection.protocol) === 'http' ? 'http' : 'https';
    const username = String(req.body?.username ?? site.connection.username ?? '').trim();
    const password = String(req.body?.password || '');
    const vdom = typeof req.body?.vdom === 'string' ? req.body.vdom : site.connection.vdom;
    const ignoreTlsErrors = req.body?.ignoreTlsErrors !== false;
    const savePassword = Boolean(req.body?.savePassword);

    try {
      const result = await syncSiteWithApi(site, {
        host,
        port,
        protocol,
        username,
        password,
        vdom,
        ignoreTlsErrors,
        savePassword,
      });
      res.json({ ok: true, ...result, overview: buildOverview(site) });
    } catch (err) {
      const message =
        err instanceof Error ? err.message : 'Erro ao consultar a API REST do firewall.';
      res.status(502).json({ error: message });
    }
  });

  router.post('/firewall/audit', handleAuditConnect);
  router.post('/sonicwall/audit', handleAuditConnect);

  // --- Receptor UDP ----------------------------------------------------------

  router.get('/syslog-server/status', (_req, res) => {
    res.json(getUdpStatus());
  });

  router.post(
    '/syslog-server/start',
    asyncRoute(async (req, res) => {
      const port = Number(req.body?.port || defaultPort);
      const bindAddress = String(req.body?.bindAddress || '0.0.0.0');
      if (!Number.isInteger(port) || port < 1 || port > 65535) {
        res.status(400).json({ error: 'Porta UDP inválida.' });
        return;
      }
      try {
        await udpReceiver.start(port, bindAddress);
        // Lembra a escolha: o receptor volta sozinho após reiniciar o serviço
        store.udpListener = { enabled: true, port, bindAddress };
        schedulePersist();
        res.json(getUdpStatus());
      } catch (err) {
        const message =
          err instanceof Error
            ? `Não foi possível abrir a porta UDP ${port}: ${err.message}. No Linux, portas < 1024 exigem privilégio root/cap_net_bind_service (tente ${defaultPort}).`
            : 'Falha ao iniciar receptor UDP.';
        res.status(500).json({ error: message });
      }
    })
  );

  router.post(
    '/syslog-server/stop',
    asyncRoute(async (_req, res) => {
      await udpReceiver.stop();
      flushUdpBuffer();
      store.udpListener = { ...(store.udpListener || defaultUdpConfig()), enabled: false };
      schedulePersist();
      res.json(getUdpStatus());
    })
  );

  router.post(
    '/syslog-server/test-packet',
    asyncRoute(async (req, res) => {
      try {
        await udpReceiver.sendTestPacket();
        await new Promise((r) => setTimeout(r, 120));
        flushUdpBuffer();
        res.json({ ok: true, status: getUdpStatus(), overview: buildOverview(siteFor(req)) });
      } catch (err) {
        const message = err instanceof Error ? err.message : 'Erro ao enviar pacote UDP de teste.';
        res.status(400).json({ error: message });
      }
    })
  );

  // --- Dados de exemplo / limpeza -------------------------------------------

  router.post(
    '/sample/load',
    asyncRoute(async (req, res) => {
      const site = siteFor(req);
      const sample =
        vendor === 'fortigate' ? createFortiGateSampleDataset() : createSampleDataset();
      await clearSyslogs(site);
      site.appliance = sample.appliance;
      site.rules = sample.rules.map((r) => ({ ...r, syslogHits: 0, lastHitAt: null }));
      site.nats = sample.nats.map((n) => ({ ...n, syslogHits: 0, lastHitAt: null }));
      site.telemetry = sample.telemetry;
      site.alertRecords = [];
      site.configChanges = [];
      classifyDirty.add(site.id);
      // O dataset vem com o mais recente primeiro; a ingestão espera ordem cronológica
      appendSyslogsToSite(site, [...sample.syslogs].reverse());
      evaluateSiteAlerts(site);
      schedulePersist({ policySiteId: site.id, alertSiteId: site.id });
      res.json({ ok: true, overview: buildOverview(site) });
    })
  );

  router.post(
    '/data/clear',
    asyncRoute(async (req, res) => {
      const site = siteFor(req);
      await clearSyslogs(site);
      site.appliance = {
        model: 'Nenhum appliance sincronizado',
        serialNumber: '-',
        firmware: '-',
        host: site.connection.host ? `${site.connection.host}:${site.connection.port}` : '-',
        lastSyncAt: null,
        dataSource: 'none',
      };
      site.lastPurgedCount = 0;
      site.rules = [];
      site.nats = [];
      site.telemetry = { ...EMPTY_TELEMETRY };
      site.alertRecords = [];
      site.configChanges = [];
      site.metrics = [];
      site.lastSyncError = null;
      site.consecutiveSyncFailures = 0;
      site.updatedAt = new Date().toISOString();
      schedulePersist({ policySiteId: site.id, alertSiteId: site.id });
      res.json({ ok: true, overview: buildOverview(site) });
    })
  );

  router.post('/export/cli', (req, res) => {
    const site = siteFor(req);
    ensureClassified(site);
    const ruleIds = Array.isArray(req.body?.ruleIds) ? (req.body.ruleIds as string[]) : [];
    const natIds = Array.isArray(req.body?.natIds) ? (req.body.natIds as string[]) : [];
    const mode = req.body?.mode === 'delete' ? 'delete' : 'disable';

    const selectedRules = site.rules.filter((r) => ruleIds.includes(r.id));
    const selectedNats = site.nats.filter((n) => natIds.includes(n.id));
    const script =
      vendor === 'fortigate'
        ? generateFortiOsCli(selectedRules, selectedNats, mode)
        : generateSonicOsCli(selectedRules, selectedNats, mode);

    res.json({ script });
  });

  // --- IA --------------------------------------------------------------------

  router.get(
    '/ai/config',
    asyncRoute(async (_req, res) => {
      await reloadSharedAiSettings();
      res.json(toPublicAiConfig(getAiSettingsPlain()));
    })
  );

  router.post(
    '/ai/config',
    asyncRoute(async (req, res) => {
      const allowedProviders = new Set<AiProviderType>(['gemini', 'openrouter', 'openai', 'local']);
      const providerRaw = String(req.body?.provider || 'gemini') as AiProviderType;
      const provider: AiProviderType = allowedProviders.has(providerRaw) ? providerRaw : 'gemini';
      const model = String(req.body?.model || '').trim();
      const baseUrl = String(req.body?.baseUrl || '').trim();
      const incomingKey = typeof req.body?.apiKey === 'string' ? req.body.apiKey.trim() : undefined;
      const clearKey = Boolean(req.body?.clearKey);

      await reloadSharedAiSettings();

      let plainKey = getAiSettingsPlain().apiKey;
      if (clearKey) {
        plainKey = '';
      } else if (incomingKey !== undefined && incomingKey.length > 0) {
        plainKey = incomingKey;
      }

      const updated: AiProviderSettings = {
        provider,
        model: model || (provider === 'gemini' ? DEFAULT_AI_SETTINGS.model : ''),
        baseUrl,
        // Chave cifrada em repouso (AES-256-GCM)
        apiKey: plainKey ? `${ENC_PREFIX}${authManager.encryptSecret(plainKey)}` : '',
      };

      store.aiSettings = updated;
      if (usePg) {
        await pgStore.saveSharedAiSettings(updated);
      } else {
        schedulePersist();
      }
      res.json(toPublicAiConfig(getAiSettingsPlain()));
    })
  );

  router.post(
    '/ai/chat',
    asyncRoute(async (req, res) => {
      const site = siteFor(req);
      const message = String(req.body?.message || '').trim();
      const history = Array.isArray(req.body?.history) ? (req.body.history as AiChatMessage[]) : [];
      const overrideModel = typeof req.body?.model === 'string' ? req.body.model.trim() : '';

      if (!message) {
        res.status(400).json({ error: 'Digite uma pergunta ou cole um trecho de log para análise.' });
        return;
      }

      await reloadSharedAiSettings();
      const baseSettings = getAiSettingsPlain();
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
    })
  );

  // ---------------------------------------------------------------------------
  // Ciclo de vida
  // ---------------------------------------------------------------------------

  const timers: NodeJS.Timeout[] = [];
  let scheduledSyncRunning = false;

  async function init(): Promise<void> {
    await loadStoreFromStorage();
    await purgeExpiredAcrossAllSites();
    await evaluateAllSites();

    timers.push(setInterval(flushUdpBuffer, 250));
    timers.push(setInterval(() => void flushPendingInserts(), 1000));
    timers.push(setInterval(() => void evaluateAllSites(), 15_000));
    timers.push(
      setInterval(() => {
        if (scheduledSyncRunning) return;
        scheduledSyncRunning = true;
        void runScheduledSyncs().finally(() => {
          scheduledSyncRunning = false;
        });
      }, 30_000)
    );

    const udp = store.udpListener || defaultUdpConfig();
    if (udp.enabled) {
      try {
        await udpReceiver.start(udp.port, udp.bindAddress);
        console.log(`[${vendor}] Receptor de syslog UDP ativo em ${udp.bindAddress}:${udp.port}`);
      } catch (err) {
        console.error(
          `[${vendor}] Não foi possível iniciar o receptor UDP na porta ${udp.port}:`,
          err instanceof Error ? err.message : err
        );
      }
    }
    console.log(
      `[${vendor}] ${vendorLabel}: ${Object.keys(store.sites).length} firewall(s), janela em memória de ${MEMORY_WINDOW.toLocaleString('pt-BR')} eventos por firewall.`
    );
  }

  async function shutdown(): Promise<void> {
    for (const t of timers) clearInterval(t);
    await udpReceiver.stop().catch(() => undefined);
    flushUdpBuffer();
    for (const site of Object.values(store.sites)) {
      pendingPolicySiteIds.add(site.id);
      pendingAlertSiteIds.add(site.id);
    }
    await persistNow();
    await flushPendingInserts();
  }

  return {
    vendor,
    router,
    init,
    purgeExpired: purgeExpiredAcrossAllSites,
    shutdown,
  };
}
