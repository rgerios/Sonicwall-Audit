import fs from 'node:fs/promises';
import path from 'node:path';
import { Pool } from 'pg';
import type {
  AiProviderSettings,
  ApplianceMetadata,
  DataStore,
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

      CREATE INDEX IF NOT EXISTS idx_sites_vendor ON sites (vendor, created_at ASC);
      CREATE INDEX IF NOT EXISTS idx_syslogs_site_ingested ON syslogs (site_id, ingested_at DESC);
      CREATE INDEX IF NOT EXISTS idx_syslogs_vendor_site_ingested ON syslogs (vendor, site_id, ingested_at DESC);
    `);

    console.log('[PostgreSQL] Conectado e schema multi-vendor verificado com sucesso.');
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

  async loadStore(vendor: FirewallVendor): Promise<{
    activeSiteId: string | null;
    aiSettings: Partial<AiProviderSettings> | null;
    sites: Record<string, Partial<FirewallSiteRecord>>;
  }> {
    const pool = this.getPool();

    const settingsRes = await pool.query<{ key: string; value_json: unknown }>(
      'SELECT key, value_json FROM app_settings WHERE key IN ($1, $2, $3)',
      [`active_site_id:${vendor}`, 'active_site_id', 'ai_settings']
    );
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
    const syslogsRes = await pool.query<{ site_id: string; payload_json: SyslogEvent }>(
      'SELECT site_id, payload_json FROM syslogs WHERE vendor = $1 ORDER BY ingested_at DESC',
      [vendor]
    );

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

    const syslogsBySite = new Map<string, SyslogEvent[]>();
    for (const s of syslogsRes.rows) {
      const list = syslogsBySite.get(s.site_id) || [];
      list.push(s.payload_json);
      syslogsBySite.set(s.site_id, list);
    }

    const sites: Record<string, Partial<FirewallSiteRecord>> = {};
    for (const row of sitesRes.rows) {
      sites[row.id] = {
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

    return { activeSiteId, aiSettings, sites };
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

  async saveFullStore(
    vendor: FirewallVendor,
    store: DataStore,
    dirtySyslogSiteIds?: Set<string>,
    dirtyPolicySiteIds?: Set<string>
  ): Promise<void> {
    if (!this.isEnabled()) return;
    const pool = this.getPool();
    const client = await pool.connect();

    try {
      await client.query('BEGIN');

      await client.query(
        `
        INSERT INTO app_settings (key, value_json, updated_at)
        VALUES ($1, $2::jsonb, NOW())
        ON CONFLICT (key) DO UPDATE SET
          value_json = EXCLUDED.value_json,
          updated_at = NOW()
        `,
        [`active_site_id:${vendor}`, JSON.stringify(store.activeSiteId)]
      );

      if (store.aiSettings) {
        await client.query(
          `
          INSERT INTO app_settings (key, value_json, updated_at)
          VALUES ($1, $2::jsonb, NOW())
          ON CONFLICT (key) DO UPDATE SET
            value_json = EXCLUDED.value_json,
            updated_at = NOW()
          `,
          ['ai_settings', JSON.stringify(store.aiSettings)]
        );
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
        await client.query(
          `
          INSERT INTO sites (
            id, vendor, name, location, notes, connection_json, appliance_json,
            retention_days, last_purge_at, last_purged_count,
            telemetry_json, alert_settings_json, created_at, updated_at
          )
          VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7::jsonb, $8, $9, $10, $11::jsonb, $12::jsonb, $13, $14)
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
          if (site.rules.length > 0) {
            const values: unknown[] = [];
            const placeholders: string[] = [];
            site.rules.forEach((rule, idx) => {
              const offset = idx * 5;
              placeholders.push(
                `($${offset + 1}, $${offset + 2}, $${offset + 3}, $${offset + 4}, $${offset + 5}::jsonb)`
              );
              values.push(site.id, vendor, rule.id, idx, JSON.stringify(rule));
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
          if (site.nats.length > 0) {
            const values: unknown[] = [];
            const placeholders: string[] = [];
            site.nats.forEach((nat, idx) => {
              const offset = idx * 5;
              placeholders.push(
                `($${offset + 1}, $${offset + 2}, $${offset + 3}, $${offset + 4}, $${offset + 5}::jsonb)`
              );
              values.push(site.id, vendor, nat.id, idx, JSON.stringify(nat));
            });
            await client.query(
              `INSERT INTO nat_policies (site_id, vendor, id, sort_order, payload_json) VALUES ${placeholders.join(', ')} ON CONFLICT (site_id, id) DO UPDATE SET sort_order = EXCLUDED.sort_order, payload_json = EXCLUDED.payload_json`,
              values
            );
          }
        }

        const syncSyslogs = !dirtySyslogSiteIds || dirtySyslogSiteIds.has(site.id);
        if (syncSyslogs) {
          await client.query('DELETE FROM syslogs WHERE site_id = $1 AND vendor = $2', [
            site.id,
            vendor,
          ]);
          const chunkSize = 250;
          for (let i = 0; i < site.syslogs.length; i += chunkSize) {
            const chunk = site.syslogs.slice(i, i + chunkSize);
            const values: unknown[] = [];
            const placeholders: string[] = [];
            chunk.forEach((ev, idx) => {
              const offset = idx * 9;
              placeholders.push(
                `($${offset + 1}, $${offset + 2}, $${offset + 3}, $${offset + 4}, $${offset + 5}, $${offset + 6}, $${offset + 7}, $${offset + 8}, $${offset + 9}::jsonb)`
              );
              values.push(
                site.id,
                vendor,
                ev.id,
                ev.ingestedAt || new Date().toISOString(),
                ev.timestamp,
                ev.priority,
                ev.action,
                ev.severity,
                JSON.stringify(ev)
              );
            });
            await client.query(
              `INSERT INTO syslogs (site_id, vendor, id, ingested_at, event_timestamp, priority, action, severity, payload_json) VALUES ${placeholders.join(', ')} ON CONFLICT (site_id, id) DO NOTHING`,
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
