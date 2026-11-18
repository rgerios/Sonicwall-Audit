import fs from 'node:fs/promises';
import path from 'node:path';
import { Pool, type PoolClient } from 'pg';
import type {
  AiProviderSettings,
  AlertRecord,
  ApplianceMetadata,
  DataStore,
  MetricSample,
  NotificationSettings,
  UdpListenerConfig,
  FirewallRule,
  FirewallSiteRecord,
  FirewallVendor,
  NatPolicy,
  SyslogEvent,
  TelemetrySnapshot,
} from './types.ts';

export interface StoredUserRecord {
  username: string;
  passwordHash: string;
  role: 'admin';
  createdAt: string;
}

export interface AuthSecretsRecord {
  sessionSecret: string;
  encryptionKey: string;
}

export interface SyslogStats {
  total: number;
  oldestAt: string | null;
  newestAt: string | null;
  byAction: Record<string, number>;
  bySeverity: Record<string, number>;
  hourly: Array<{ startMs: number; total: number; allow: number; blocked: number }>;
}

export interface SyslogQuery {
  search?: string;
  srcIp?: string;
  dstIp?: string;
  action?: string;
  severity?: string;
  device?: string;
  sinceIso?: string;
  limit: number;
  offset: number;
}

/** Instante usado para agrupar o evento por hora (ver resolveEventTimeMs no engine). */
export type EventTimeResolver = (ev: SyslogEvent) => number;

export function buildSyslogSearchText(ev: SyslogEvent): string {
  return `${ev.firewallHost} ${ev.serialNumber} ${ev.srcIp} ${ev.dstIp} ${ev.dstPort ?? ''} ${ev.protocol} ${ev.ruleRef ?? ''} ${ev.natRuleRef ?? ''} ${ev.message} ${ev.srcZone} ${ev.dstZone}`.toLowerCase();
}

export class PostgresStore {
  private pool: Pool | null = null;
  private enabled = false;

  constructor(connectionString?: string) {
    const conn = (connectionString || process.env.DATABASE_URL || '').trim();
    if (conn) {
      this.pool = new Pool({
        connectionString: conn,
        max: 10,
        idleTimeoutMillis: 30000,
        connectionTimeoutMillis: 5000,
      });
      this.enabled = true;
    }
  }

  isEnabled(): boolean {
    return this.enabled && this.pool !== null;
  }

  private getPool(): Pool {
    if (!this.pool) {
      throw new Error('PostgreSQL pool is not initialized.');
    }
    return this.pool;
  }

  async init(): Promise<void> {
    if (!this.isEnabled()) return;

    const pool = this.getPool();
    const maxAttempts = 20;
    let lastError: unknown = null;

    for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
      try {
        await pool.query('SELECT 1');
        lastError = null;
        break;
      } catch (err) {
        lastError = err;
        console.warn(
          `[PostgreSQL] Aguardando banco de dados (${attempt}/${maxAttempts})...`
        );
        await new Promise((resolve) => setTimeout(resolve, 1500));
      }
    }

    if (lastError) {
      throw lastError;
    }

    // Os dois backends sobem juntos e compartilham o banco: um advisory lock serializa a
    // criação do schema (CREATE ... IF NOT EXISTS concorrente pode falhar no PostgreSQL).
    const schemaClient = await pool.connect();
    try {
      await schemaClient.query('SELECT pg_advisory_lock(727001)');
      await this.ensureSchema(schemaClient);
    } finally {
      await schemaClient.query('SELECT pg_advisory_unlock(727001)').catch(() => undefined);
      schemaClient.release();
    }

    console.log('[PostgreSQL] Conectado e schema multi-vendor verificado com sucesso.');
  }

  private async ensureSchema(pool: PoolClient): Promise<void> {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS app_secrets (
        id TEXT PRIMARY KEY,
        session_secret TEXT NOT NULL,
        encryption_key TEXT NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'admin',
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS app_settings (
        key TEXT PRIMARY KEY,
        value_json JSONB NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS sites (
        id TEXT PRIMARY KEY,
        vendor TEXT NOT NULL DEFAULT 'sonicwall',
        name TEXT NOT NULL,
        location TEXT NOT NULL DEFAULT '',
        notes TEXT NOT NULL DEFAULT '',
        connection_json JSONB NOT NULL,
        appliance_json JSONB NOT NULL,
        retention_days INTEGER NOT NULL DEFAULT 10,
        last_purge_at TIMESTAMPTZ,
        last_purged_count INTEGER NOT NULL DEFAULT 0,
        telemetry_json JSONB NOT NULL,
        alert_settings_json JSONB NOT NULL,
        created_at TIMESTAMPTZ NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL
      );

      ALTER TABLE sites ADD COLUMN IF NOT EXISTS vendor TEXT NOT NULL DEFAULT 'sonicwall';

      CREATE TABLE IF NOT EXISTS firewall_rules (
        site_id TEXT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
        vendor TEXT NOT NULL DEFAULT 'sonicwall',
        id TEXT NOT NULL,
        sort_order INTEGER NOT NULL DEFAULT 0,
        payload_json JSONB NOT NULL,
        PRIMARY KEY (site_id, id)
      );

      ALTER TABLE firewall_rules ADD COLUMN IF NOT EXISTS vendor TEXT NOT NULL DEFAULT 'sonicwall';

      CREATE TABLE IF NOT EXISTS nat_policies (
        site_id TEXT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
        vendor TEXT NOT NULL DEFAULT 'sonicwall',
        id TEXT NOT NULL,
        sort_order INTEGER NOT NULL DEFAULT 0,
        payload_json JSONB NOT NULL,
        PRIMARY KEY (site_id, id)
      );

      ALTER TABLE nat_policies ADD COLUMN IF NOT EXISTS vendor TEXT NOT NULL DEFAULT 'sonicwall';

      CREATE TABLE IF NOT EXISTS syslogs (
        site_id TEXT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
        vendor TEXT NOT NULL DEFAULT 'sonicwall',
        id TEXT NOT NULL,
        ingested_at TIMESTAMPTZ NOT NULL,
        event_timestamp TEXT NOT NULL,
        priority INTEGER NOT NULL,
        action TEXT NOT NULL,
        severity TEXT NOT NULL,
        payload_json JSONB NOT NULL,
        PRIMARY KEY (site_id, id)
      );

      ALTER TABLE syslogs ADD COLUMN IF NOT EXISTS vendor TEXT NOT NULL DEFAULT 'sonicwall';

      ALTER TABLE syslogs ADD COLUMN IF NOT EXISTS event_at TIMESTAMPTZ;
      ALTER TABLE syslogs ADD COLUMN IF NOT EXISTS search_text TEXT NOT NULL DEFAULT '';
      DO $$
      BEGIN
        IF EXISTS (SELECT 1 FROM syslogs WHERE event_at IS NULL LIMIT 1) THEN
          UPDATE syslogs SET event_at = ingested_at WHERE event_at IS NULL;
        END IF;
      END $$;

      ALTER TABLE sites ADD COLUMN IF NOT EXISTS settings_json JSONB NOT NULL DEFAULT '{}'::jsonb;

      CREATE TABLE IF NOT EXISTS alert_records (
        site_id TEXT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
        vendor TEXT NOT NULL,
        key TEXT NOT NULL,
        status TEXT NOT NULL,
        first_seen_at TIMESTAMPTZ NOT NULL,
        payload_json JSONB NOT NULL,
        PRIMARY KEY (site_id, key)
      );

      CREATE TABLE IF NOT EXISTS metrics (
        site_id TEXT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
        ts TIMESTAMPTZ NOT NULL,
        payload_json JSONB NOT NULL,
        PRIMARY KEY (site_id, ts)
      );

      CREATE INDEX IF NOT EXISTS idx_sites_vendor ON sites (vendor, created_at ASC);
      CREATE INDEX IF NOT EXISTS idx_syslogs_site_event ON syslogs (site_id, event_at DESC);
      CREATE INDEX IF NOT EXISTS idx_syslogs_site_ingested ON syslogs (site_id, ingested_at DESC);
      CREATE INDEX IF NOT EXISTS idx_syslogs_vendor_site_ingested ON syslogs (vendor, site_id, ingested_at DESC);
    `);

    // Índice trigram acelera a busca textual em milhões de linhas. Requer a extensão
    // pg_trgm (inclusa na imagem oficial); sem permissão, a busca segue funcionando sem índice.
    try {
      await pool.query('CREATE EXTENSION IF NOT EXISTS pg_trgm');
      await pool.query(
        'CREATE INDEX IF NOT EXISTS idx_syslogs_search_trgm ON syslogs USING gin (search_text gin_trgm_ops)'
      );
    } catch (err) {
      console.warn(
        '[PostgreSQL] pg_trgm indisponível; busca textual em syslogs sem índice:',
        err instanceof Error ? err.message : err
      );
    }
  }

  async loadAuthState(): Promise<{ secrets: AuthSecretsRecord | null; users: StoredUserRecord[] }> {
    const pool = this.getPool();
    const secretsRes = await pool.query<{ session_secret: string; encryption_key: string }>(
      'SELECT session_secret, encryption_key FROM app_secrets WHERE id = $1 LIMIT 1',
      ['primary']
    );
    const usersRes = await pool.query<{
      username: string;
      password_hash: string;
      role: string;
      created_at: Date;
    }>('SELECT username, password_hash, role, created_at FROM users ORDER BY created_at ASC');

    return {
      secrets: secretsRes.rows[0]
        ? {
            sessionSecret: secretsRes.rows[0].session_secret,
            encryptionKey: secretsRes.rows[0].encryption_key,
          }
        : null,
      users: usersRes.rows.map((r) => ({
        username: r.username,
        passwordHash: r.password_hash,
        role: 'admin',
        createdAt: r.created_at instanceof Date ? r.created_at.toISOString() : String(r.created_at),
      })),
    };
  }

  async saveAuthSecrets(secrets: AuthSecretsRecord): Promise<void> {
    const pool = this.getPool();
    await pool.query(
      `
      INSERT INTO app_secrets (id, session_secret, encryption_key, updated_at)
      VALUES ($1, $2, $3, NOW())
      ON CONFLICT (id) DO NOTHING
      `,
      ['primary', secrets.sessionSecret, secrets.encryptionKey]
    );
  }

  async insertUser(user: StoredUserRecord): Promise<void> {
    const pool = this.getPool();
    await pool.query(
      `
      INSERT INTO users (username, password_hash, role, created_at)
      VALUES ($1, $2, $3, $4)
      ON CONFLICT (username) DO NOTHING
      `,
      [user.username, user.passwordHash, user.role, user.createdAt]
    );
  }

  async updateUserPassword(username: string, passwordHash: string): Promise<void> {
    const pool = this.getPool();
    await pool.query(
      'UPDATE users SET password_hash = $1 WHERE LOWER(username) = LOWER($2)',
      [passwordHash, username]
    );
  }

  async hasAnySites(vendor: FirewallVendor): Promise<boolean> {
    const pool = this.getPool();
    const res = await pool.query<{ count: string }>(
      'SELECT COUNT(*)::text AS count FROM sites WHERE vendor = $1',
      [vendor]
    );
    return Number(res.rows[0]?.count || '0') > 0;
  }

  async loadStore(
    vendor: FirewallVendor,
    syslogWindow: number
  ): Promise<{
    activeSiteId: string | null;
    aiSettings: Partial<AiProviderSettings> | null;
    notificationSettings: Partial<NotificationSettings> | null;
    udpListener: Partial<UdpListenerConfig> | null;
    sites: Record<string, Partial<FirewallSiteRecord>>;
  }> {
    const pool = this.getPool();

    const settingsRes = await pool.query<{ key: string; value_json: unknown }>(
      'SELECT key, value_json FROM app_settings WHERE key IN ($1, $2, $3, $4, $5)',
      [
        `active_site_id:${vendor}`,
        'active_site_id',
        'ai_settings',
        'notification_settings',
        `udp_listener:${vendor}`,
      ]
    );
    let notificationSettings: Partial<NotificationSettings> | null = null;
    let udpListener: Partial<UdpListenerConfig> | null = null;
    let activeSiteId: string | null = null;
    let legacyActiveSiteId: string | null = null;
    let aiSettings: Partial<AiProviderSettings> | null = null;
    for (const row of settingsRes.rows) {
      if (row.key === `active_site_id:${vendor}` && typeof row.value_json === 'string') {
        activeSiteId = row.value_json;
      } else if (row.key === 'active_site_id' && typeof row.value_json === 'string') {
        legacyActiveSiteId = row.value_json;
      } else if (row.key === 'ai_settings' && row.value_json && typeof row.value_json === 'object') {
        aiSettings = row.value_json as Partial<AiProviderSettings>;
      } else if (row.key === 'notification_settings' && row.value_json && typeof row.value_json === 'object') {
        notificationSettings = row.value_json as Partial<NotificationSettings>;
      } else if (row.key === `udp_listener:${vendor}` && row.value_json && typeof row.value_json === 'object') {
        udpListener = row.value_json as Partial<UdpListenerConfig>;
      }
    }
    if (!activeSiteId && vendor === 'sonicwall') {
      activeSiteId = legacyActiveSiteId;
    }

    const sitesRes = await pool.query<{
      id: string;
      vendor: FirewallVendor;
      name: string;
      location: string;
      notes: string;
      connection_json: FirewallSiteRecord['connection'];
      appliance_json: ApplianceMetadata;
      retention_days: number;
      last_purge_at: Date | null;
      last_purged_count: number;
      telemetry_json: TelemetrySnapshot;
      alert_settings_json: FirewallSiteRecord['alertSettings'];
      settings_json: Partial<FirewallSiteRecord> | null;
      created_at: Date;
      updated_at: Date;
    }>('SELECT * FROM sites WHERE vendor = $1 ORDER BY created_at ASC', [vendor]);

    const rulesRes = await pool.query<{ site_id: string; payload_json: FirewallRule }>(
      'SELECT site_id, payload_json FROM firewall_rules WHERE vendor = $1 ORDER BY sort_order ASC',
      [vendor]
    );
    const natsRes = await pool.query<{ site_id: string; payload_json: NatPolicy }>(
      'SELECT site_id, payload_json FROM nat_policies WHERE vendor = $1 ORDER BY sort_order ASC',
      [vendor]
    );
    const alertsRes = await pool.query<{ site_id: string; payload_json: AlertRecord }>(
      'SELECT site_id, payload_json FROM alert_records WHERE vendor = $1 ORDER BY first_seen_at DESC',
      [vendor]
    );

    // Apenas a janela recente de cada firewall vai para a memória; o histórico completo
    // permanece no banco e é consultado sob demanda.
    const syslogsBySite = new Map<string, SyslogEvent[]>();
    await Promise.all(
      sitesRes.rows.map(async (row) => {
        const res = await pool.query<{ payload_json: SyslogEvent }>(
          'SELECT payload_json FROM syslogs WHERE site_id = $1 ORDER BY ingested_at DESC LIMIT $2',
          [row.id, syslogWindow]
        );
        syslogsBySite.set(
          row.id,
          res.rows.map((r) => r.payload_json)
        );
      })
    );

    const alertsBySite = new Map<string, AlertRecord[]>();
    for (const a of alertsRes.rows) {
      const list = alertsBySite.get(a.site_id) || [];
      list.push(a.payload_json);
      alertsBySite.set(a.site_id, list);
    }

    const rulesBySite = new Map<string, FirewallRule[]>();
    for (const r of rulesRes.rows) {
      const list = rulesBySite.get(r.site_id) || [];
      list.push(r.payload_json);
      rulesBySite.set(r.site_id, list);
    }

    const natsBySite = new Map<string, NatPolicy[]>();
    for (const n of natsRes.rows) {
      const list = natsBySite.get(n.site_id) || [];
      list.push(n.payload_json);
      natsBySite.set(n.site_id, list);
    }

    const sites: Record<string, Partial<FirewallSiteRecord>> = {};
    for (const row of sitesRes.rows) {
      sites[row.id] = {
        ...(row.settings_json && typeof row.settings_json === 'object' ? row.settings_json : {}),
        alertRecords: alertsBySite.get(row.id) || [],
        id: row.id,
        vendor: row.vendor || vendor,
        name: row.name,
        location: row.location,
        notes: row.notes,
        connection: row.connection_json,
        appliance: row.appliance_json,
        retentionDays: row.retention_days,
        lastPurgeAt:
          row.last_purge_at instanceof Date
            ? row.last_purge_at.toISOString()
            : row.last_purge_at,
        lastPurgedCount: row.last_purged_count,
        telemetry: row.telemetry_json,
        alertSettings: row.alert_settings_json,
        rules: rulesBySite.get(row.id) || [],
        nats: natsBySite.get(row.id) || [],
        syslogs: syslogsBySite.get(row.id) || [],
        createdAt:
          row.created_at instanceof Date ? row.created_at.toISOString() : String(row.created_at),
        updatedAt:
          row.updated_at instanceof Date ? row.updated_at.toISOString() : String(row.updated_at),
      };
    }

    return { activeSiteId, aiSettings, notificationSettings, udpListener, sites };
  }

  async loadSharedAiSettings(): Promise<Partial<AiProviderSettings> | null> {
    if (!this.isEnabled()) return null;
    const res = await this.getPool().query<{ value_json: unknown }>(
      'SELECT value_json FROM app_settings WHERE key = $1 LIMIT 1',
      ['ai_settings']
    );
    const val = res.rows[0]?.value_json;
    return val && typeof val === 'object' ? (val as Partial<AiProviderSettings>) : null;
  }

  async saveSharedAiSettings(aiSettings: AiProviderSettings): Promise<void> {
    if (!this.isEnabled()) return;
    await this.getPool().query(
      `
      INSERT INTO app_settings (key, value_json, updated_at)
      VALUES ($1, $2::jsonb, NOW())
      ON CONFLICT (key) DO UPDATE SET
        value_json = EXCLUDED.value_json,
        updated_at = NOW()
      `,
      ['ai_settings', JSON.stringify(aiSettings)]
    );
  }

  async loadSharedSetting<T>(key: string): Promise<T | null> {
    if (!this.isEnabled()) return null;
    const res = await this.getPool().query<{ value_json: unknown }>(
      'SELECT value_json FROM app_settings WHERE key = $1 LIMIT 1',
      [key]
    );
    const val = res.rows[0]?.value_json;
    return val && typeof val === 'object' ? (val as T) : null;
  }

  async saveSharedSetting(key: string, value: unknown): Promise<void> {
    if (!this.isEnabled()) return;
    await this.getPool().query(
      `
      INSERT INTO app_settings (key, value_json, updated_at)
      VALUES ($1, $2::jsonb, NOW())
      ON CONFLICT (key) DO UPDATE SET
        value_json = EXCLUDED.value_json,
        updated_at = NOW()
      `,
      [key, JSON.stringify(value)]
    );
  }

  /**
   * Persiste configuração, sites e (quando marcados) políticas e alertas.
   * Syslogs NÃO passam por aqui: são gravados de forma incremental por insertSyslogs.
   */
  async saveFullStore(
    vendor: FirewallVendor,
    store: DataStore,
    dirtyPolicySiteIds?: Set<string>,
    dirtyAlertSiteIds?: Set<string>
  ): Promise<void> {
    if (!this.isEnabled()) return;
    const pool = this.getPool();
    const client = await pool.connect();

    const upsertSetting = (key: string, value: unknown) =>
      client.query(
        `
        INSERT INTO app_settings (key, value_json, updated_at)
        VALUES ($1, $2::jsonb, NOW())
        ON CONFLICT (key) DO UPDATE SET
          value_json = EXCLUDED.value_json,
          updated_at = NOW()
        `,
        [key, JSON.stringify(value)]
      );

    try {
      await client.query('BEGIN');

      await upsertSetting(`active_site_id:${vendor}`, store.activeSiteId);
      if (store.udpListener) {
        await upsertSetting(`udp_listener:${vendor}`, store.udpListener);
      }

      const siteIds = Object.keys(store.sites);
      if (siteIds.length > 0) {
        await client.query('DELETE FROM sites WHERE vendor = $1 AND NOT (id = ANY($2::text[]))', [
          vendor,
          siteIds,
        ]);
      } else {
        await client.query('DELETE FROM sites WHERE vendor = $1', [vendor]);
      }

      for (const site of Object.values(store.sites)) {
        const settingsJson = {
          autoSyncMinutes: site.autoSyncMinutes,
          lastSyncAttemptAt: site.lastSyncAttemptAt,
          lastSyncError: site.lastSyncError,
          consecutiveSyncFailures: site.consecutiveSyncFailures,
          configChanges: site.configChanges,
          hitsObservedSince: site.hitsObservedSince,
        };
        await client.query(
          `
          INSERT INTO sites (
            id, vendor, name, location, notes, connection_json, appliance_json,
            retention_days, last_purge_at, last_purged_count,
            telemetry_json, alert_settings_json, settings_json, created_at, updated_at
          )
          VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7::jsonb, $8, $9, $10, $11::jsonb, $12::jsonb, $13::jsonb, $14, $15)
          ON CONFLICT (id) DO UPDATE SET
            vendor = EXCLUDED.vendor,
            name = EXCLUDED.name,
            location = EXCLUDED.location,
            notes = EXCLUDED.notes,
            connection_json = EXCLUDED.connection_json,
            appliance_json = EXCLUDED.appliance_json,
            retention_days = EXCLUDED.retention_days,
            last_purge_at = EXCLUDED.last_purge_at,
            last_purged_count = EXCLUDED.last_purged_count,
            telemetry_json = EXCLUDED.telemetry_json,
            alert_settings_json = EXCLUDED.alert_settings_json,
            settings_json = EXCLUDED.settings_json,
            updated_at = EXCLUDED.updated_at
          `,
          [
            site.id,
            vendor,
            site.name,
            site.location,
            site.notes,
            JSON.stringify(site.connection),
            JSON.stringify(site.appliance),
            site.retentionDays,
            site.lastPurgeAt,
            site.lastPurgedCount,
            JSON.stringify(site.telemetry),
            JSON.stringify(site.alertSettings),
            JSON.stringify(settingsJson),
            site.createdAt,
            site.updatedAt,
          ]
        );

        const syncPolicies = !dirtyPolicySiteIds || dirtyPolicySiteIds.has(site.id);
        if (syncPolicies) {
          await client.query('DELETE FROM firewall_rules WHERE site_id = $1 AND vendor = $2', [
            site.id,
            vendor,
          ]);
          const chunkSize = 500;
          for (let i = 0; i < site.rules.length; i += chunkSize) {
            const chunk = site.rules.slice(i, i + chunkSize);
            const values: unknown[] = [];
            const placeholders: string[] = [];
            chunk.forEach((rule, idx) => {
              const offset = idx * 5;
              placeholders.push(
                `($${offset + 1}, $${offset + 2}, $${offset + 3}, $${offset + 4}, $${offset + 5}::jsonb)`
              );
              values.push(site.id, vendor, rule.id, i + idx, JSON.stringify(rule));
            });
            await client.query(
              `INSERT INTO firewall_rules (site_id, vendor, id, sort_order, payload_json) VALUES ${placeholders.join(', ')} ON CONFLICT (site_id, id) DO UPDATE SET sort_order = EXCLUDED.sort_order, payload_json = EXCLUDED.payload_json`,
              values
            );
          }

          await client.query('DELETE FROM nat_policies WHERE site_id = $1 AND vendor = $2', [
            site.id,
            vendor,
          ]);
          for (let i = 0; i < site.nats.length; i += chunkSize) {
            const chunk = site.nats.slice(i, i + chunkSize);
            const values: unknown[] = [];
            const placeholders: string[] = [];
            chunk.forEach((nat, idx) => {
              const offset = idx * 5;
              placeholders.push(
                `($${offset + 1}, $${offset + 2}, $${offset + 3}, $${offset + 4}, $${offset + 5}::jsonb)`
              );
              values.push(site.id, vendor, nat.id, i + idx, JSON.stringify(nat));
            });
            await client.query(
              `INSERT INTO nat_policies (site_id, vendor, id, sort_order, payload_json) VALUES ${placeholders.join(', ')} ON CONFLICT (site_id, id) DO UPDATE SET sort_order = EXCLUDED.sort_order, payload_json = EXCLUDED.payload_json`,
              values
            );
          }
        }

        const syncAlerts = !dirtyAlertSiteIds || dirtyAlertSiteIds.has(site.id);
        if (syncAlerts) {
          await client.query('DELETE FROM alert_records WHERE site_id = $1', [site.id]);
          const chunkSize = 200;
          for (let i = 0; i < site.alertRecords.length; i += chunkSize) {
            const chunk = site.alertRecords.slice(i, i + chunkSize);
            const values: unknown[] = [];
            const placeholders: string[] = [];
            chunk.forEach((rec, idx) => {
              const offset = idx * 6;
              placeholders.push(
                `($${offset + 1}, $${offset + 2}, $${offset + 3}, $${offset + 4}, $${offset + 5}, $${offset + 6}::jsonb)`
              );
              values.push(site.id, vendor, rec.key, rec.status, rec.firstSeenAt, JSON.stringify(rec));
            });
            await client.query(
              `INSERT INTO alert_records (site_id, vendor, key, status, first_seen_at, payload_json) VALUES ${placeholders.join(', ')} ON CONFLICT (site_id, key) DO UPDATE SET status = EXCLUDED.status, payload_json = EXCLUDED.payload_json`,
              values
            );
          }
        }
      }

      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  }

  /** Gravação incremental (append-only) de novos eventos. */
  async insertSyslogs(
    siteId: string,
    vendor: FirewallVendor,
    events: SyslogEvent[],
    resolveEventTimeMs: EventTimeResolver
  ): Promise<void> {
    if (!this.isEnabled() || events.length === 0) return;
    const pool = this.getPool();
    const chunkSize = 500;
    for (let i = 0; i < events.length; i += chunkSize) {
      const chunk = events.slice(i, i + chunkSize);
      const values: unknown[] = [];
      const placeholders: string[] = [];
      chunk.forEach((ev, idx) => {
        const o = idx * 11;
        placeholders.push(
          `($${o + 1}, $${o + 2}, $${o + 3}, $${o + 4}, $${o + 5}, $${o + 6}, $${o + 7}, $${o + 8}, $${o + 9}, $${o + 10}, $${o + 11}::jsonb)`
        );
        values.push(
          siteId,
          vendor,
          ev.id,
          ev.ingestedAt || new Date().toISOString(),
          new Date(resolveEventTimeMs(ev)).toISOString(),
          ev.timestamp,
          ev.priority,
          ev.action,
          ev.severity,
          buildSyslogSearchText(ev),
          JSON.stringify(ev)
        );
      });
      await pool.query(
        `INSERT INTO syslogs (site_id, vendor, id, ingested_at, event_at, event_timestamp, priority, action, severity, search_text, payload_json) VALUES ${placeholders.join(', ')} ON CONFLICT (site_id, id) DO NOTHING`,
        values
      );
    }
  }

  async deleteSyslogs(siteId: string): Promise<void> {
    if (!this.isEnabled()) return;
    await this.getPool().query('DELETE FROM syslogs WHERE site_id = $1', [siteId]);
  }

  /** Remove eventos mais antigos que o corte e, se configurado, o excedente do teto de linhas. */
  async purgeSyslogs(siteId: string, cutoffIso: string, maxRows = 0): Promise<number> {
    if (!this.isEnabled()) return 0;
    const pool = this.getPool();
    const res = await pool.query('DELETE FROM syslogs WHERE site_id = $1 AND ingested_at < $2', [
      siteId,
      cutoffIso,
    ]);
    let purged = res.rowCount || 0;
    if (maxRows > 0) {
      const over = await pool.query(
        `DELETE FROM syslogs WHERE site_id = $1 AND ingested_at < (
           SELECT ingested_at FROM syslogs WHERE site_id = $1
           ORDER BY ingested_at DESC OFFSET $2 LIMIT 1
         )`,
        [siteId, maxRows]
      );
      purged += over.rowCount || 0;
    }
    return purged;
  }

  async querySyslogs(
    siteId: string,
    q: SyslogQuery
  ): Promise<{ matched: number; events: SyslogEvent[] }> {
    const pool = this.getPool();
    const where: string[] = ['site_id = $1'];
    const params: unknown[] = [siteId];

    if (q.sinceIso) {
      params.push(q.sinceIso);
      where.push(`ingested_at >= $${params.length}`);
    }

    if (q.action && q.action !== 'all') {
      if (q.action === 'blocked') {
        where.push(`action IN ('drop', 'deny', 'reset')`);
      } else {
        params.push(q.action);
        where.push(`action = $${params.length}`);
      }
    }
    if (q.severity && q.severity !== 'all') {
      params.push(q.severity);
      where.push(`severity = $${params.length}`);
    }
    if (q.device && q.device !== 'all') {
      params.push(q.device);
      where.push(
        `(payload_json->>'firewallHost' = $${params.length} OR payload_json->>'serialNumber' = $${params.length})`
      );
    }
    if (q.search) {
      const escaped = q.search.toLowerCase().replace(/[\\%_]/g, (c) => `\\${c}`);
      params.push(`%${escaped}%`);
      where.push(`search_text LIKE $${params.length}`);
    }
    if (q.srcIp) {
      const escaped = q.srcIp.toLowerCase().replace(/[\\%_]/g, (c) => `\\${c}`);
      params.push(`%${escaped}%`);
      where.push(`LOWER(COALESCE(payload_json->>'srcIp', '')) LIKE $${params.length}`);
    }
    if (q.dstIp) {
      const escaped = q.dstIp.toLowerCase().replace(/[\\%_]/g, (c) => `\\${c}`);
      params.push(`%${escaped}%`);
      where.push(`LOWER(COALESCE(payload_json->>'dstIp', '')) LIKE $${params.length}`);
    }

    const whereSql = where.join(' AND ');
    const countRes = await pool.query<{ count: string }>(
      `SELECT COUNT(*)::text AS count FROM syslogs WHERE ${whereSql}`,
      params
    );
    const rowsRes = await pool.query<{ payload_json: SyslogEvent }>(
      `SELECT payload_json FROM syslogs WHERE ${whereSql} ORDER BY ingested_at DESC LIMIT $${params.length + 1} OFFSET $${params.length + 2}`,
      [...params, q.limit, q.offset]
    );
    return {
      matched: Number(countRes.rows[0]?.count || '0'),
      events: rowsRes.rows.map((r) => r.payload_json),
    };
  }

  async querySyslogsSince(
    siteId: string,
    sinceIso: string,
    ip?: string,
    limit = 50_000
  ): Promise<SyslogEvent[]> {
    const pool = this.getPool();
    const where: string[] = ['site_id = $1', 'event_at >= $2'];
    const params: unknown[] = [siteId, sinceIso];
    if (ip && ip.trim()) {
      const escaped = ip.trim().toLowerCase().replace(/[\\%_]/g, (c) => `\\${c}`);
      params.push(`%${escaped}%`);
      where.push(`search_text LIKE $${params.length}`);
    }
    params.push(limit);
    const res = await pool.query<{ payload_json: SyslogEvent }>(
      `SELECT payload_json FROM syslogs WHERE ${where.join(' AND ')} ORDER BY event_at DESC LIMIT $${params.length}`,
      params
    );
    return res.rows.map((r) => r.payload_json);
  }

  async loadSyslogStats(siteId: string): Promise<SyslogStats> {
    const pool = this.getPool();
    const totals = await pool.query<{
      action: string;
      severity: string;
      count: string;
      oldest: Date | null;
      newest: Date | null;
    }>(
      `SELECT action, severity, COUNT(*)::text AS count, MIN(ingested_at) AS oldest, MAX(ingested_at) AS newest
       FROM syslogs WHERE site_id = $1 GROUP BY action, severity`,
      [siteId]
    );
    const hourlyRes = await pool.query<{
      bucket: Date;
      total: string;
      allow: string;
      blocked: string;
    }>(
      `SELECT date_trunc('hour', event_at) AS bucket,
              COUNT(*)::text AS total,
              COUNT(*) FILTER (WHERE action = 'allow')::text AS allow,
              COUNT(*) FILTER (WHERE action IN ('drop', 'deny', 'reset'))::text AS blocked
       FROM syslogs
       WHERE site_id = $1 AND event_at >= NOW() - INTERVAL '49 hours'
       GROUP BY 1`,
      [siteId]
    );

    const stats: SyslogStats = {
      total: 0,
      oldestAt: null,
      newestAt: null,
      byAction: {},
      bySeverity: {},
      hourly: hourlyRes.rows.map((r) => ({
        startMs: new Date(r.bucket).getTime(),
        total: Number(r.total),
        allow: Number(r.allow),
        blocked: Number(r.blocked),
      })),
    };
    for (const row of totals.rows) {
      const n = Number(row.count);
      stats.total += n;
      stats.byAction[row.action] = (stats.byAction[row.action] || 0) + n;
      stats.bySeverity[row.severity] = (stats.bySeverity[row.severity] || 0) + n;
      const oldest = row.oldest ? new Date(row.oldest).toISOString() : null;
      const newest = row.newest ? new Date(row.newest).toISOString() : null;
      if (oldest && (!stats.oldestAt || oldest < stats.oldestAt)) stats.oldestAt = oldest;
      if (newest && (!stats.newestAt || newest > stats.newestAt)) stats.newestAt = newest;
    }
    return stats;
  }

  async insertMetric(siteId: string, sample: MetricSample): Promise<void> {
    if (!this.isEnabled()) return;
    await this.getPool().query(
      `INSERT INTO metrics (site_id, ts, payload_json) VALUES ($1, $2, $3::jsonb)
       ON CONFLICT (site_id, ts) DO NOTHING`,
      [siteId, sample.ts, JSON.stringify(sample)]
    );
  }

  async loadMetrics(siteId: string, sinceIso: string): Promise<MetricSample[]> {
    const res = await this.getPool().query<{ payload_json: MetricSample }>(
      'SELECT payload_json FROM metrics WHERE site_id = $1 AND ts >= $2 ORDER BY ts ASC LIMIT 5000',
      [siteId, sinceIso]
    );
    return res.rows.map((r) => r.payload_json);
  }

  async purgeMetrics(olderThanIso: string): Promise<void> {
    if (!this.isEnabled()) return;
    await this.getPool().query('DELETE FROM metrics WHERE ts < $1', [olderThanIso]);
  }

  async getDatabaseSizeBytes(): Promise<number> {
    if (!this.isEnabled()) return 0;
    try {
      const res = await this.getPool().query<{ size_bytes: string }>(
        'SELECT pg_database_size(current_database())::text AS size_bytes'
      );
      return Number(res.rows[0]?.size_bytes || '0');
    } catch {
      return 0;
    }
  }

  async maybeReadLegacyJsonFile<T>(filePath: string): Promise<T | null> {
    try {
      const raw = await fs.readFile(path.resolve(filePath), 'utf8');
      return JSON.parse(raw) as T;
    } catch {
      return null;
    }
  }

  async close(): Promise<void> {
    if (this.pool) {
      await this.pool.end();
      this.pool = null;
      this.enabled = false;
    }
  }
}
