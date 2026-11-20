import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import pg from 'pg';
import { PostgresStore } from '../server/database.ts';
import type { SyslogEvent } from '../server/types.ts';

/**
 * Teste de integração com um PostgreSQL real. Só roda quando TEST_DATABASE_URL está definido
 * (um banco descartável: o teste cria e apaga o seu próprio firewall de teste), por exemplo:
 *   TEST_DATABASE_URL=postgres://usuario@127.0.0.1:5432/fwaudit_test npm test
 */
const URL = process.env.TEST_DATABASE_URL;
const SITE = 'it-stats-site';
const HOUR = 3600_000;

function ev(id: string, action: SyslogEvent['action'], severity: SyslogEvent['severity'], ageMs: number): SyslogEvent {
  const at = new Date(Date.now() - ageMs).toISOString();
  return {
    id, timestamp: at, firewallHost: 'fw', serialNumber: 'sn', priority: 6, severity, categoryCode: '1', categoryName: 'x',
    messageId: 'm', action, srcIp: '10.0.0.1', srcPort: 1, srcZone: 'X0', dstIp: '8.8.8.8', dstPort: 443, dstZone: 'X1',
    natSrcIp: null, natSrcPort: null, natDstIp: null, natDstPort: null, protocol: 'tcp', ruleRef: null, natRuleRef: null,
    bytesSent: 1, bytesRcvd: 1, appName: null, user: null, message: 'm', raw: 'r', source: 'udp', ingestedAt: at,
  } as SyslogEvent;
}

const resolveTime = (e: SyslogEvent) => Date.parse(e.ingestedAt);

describe('contadores de syslog no PostgreSQL', { skip: !URL }, () => {
  let store: PostgresStore;
  let pool: pg.Pool;

  const realCounts = async () => {
    const r = await pool.query<{ action: string; severity: string; n: string }>(
      'SELECT action, severity, COUNT(*)::text AS n FROM syslogs WHERE site_id = $1 GROUP BY 1, 2',
      [SITE]
    );
    return Object.fromEntries(r.rows.map((x) => [`${x.action}/${x.severity}`, Number(x.n)]));
  };
  const counterCounts = async () => {
    const stats = await store.loadSyslogStats(SITE);
    assert.ok(stats, 'contadores deveriam estar prontos');
    return stats;
  };

  before(async () => {
    store = new PostgresStore(URL);
    await store.init();
    pool = new pg.Pool({ connectionString: URL });
    await pool.query('DELETE FROM sites WHERE id = $1', [SITE]);
    await pool.query(
      `INSERT INTO sites (id, vendor, name, connection_json, appliance_json, telemetry_json, alert_settings_json, created_at, updated_at)
       VALUES ($1, 'sonicwall', 'Teste', '{}', '{}', '{}', '{}', now(), now())`,
      [SITE]
    );
  });

  after(async () => {
    await pool.query('DELETE FROM sites WHERE id = $1', [SITE]);
    await pool.end();
    await store.close();
  });

  it('não calcula nada até o backfill, e o backfill reflete a tabela', async () => {
    // linhas "antigas" inseridas direto, como se fossem de antes da funcionalidade
    await pool.query(
      `INSERT INTO syslogs (site_id, vendor, id, ingested_at, event_at, event_timestamp, priority, action, severity, search_text, payload_json)
       SELECT $1, 'sonicwall', 'legacy-' || g, now() - interval '1 hour', now() - interval '1 hour', 'x', 6,
              CASE WHEN g % 2 = 0 THEN 'allow' ELSE 'drop' END, 'info', 'x', '{}'::jsonb
       FROM generate_series(1, 10) g`,
      [SITE]
    );
    assert.equal(await store.loadSyslogStats(SITE), null);
    await store.backfillSyslogStats(SITE);
    const stats = await counterCounts();
    assert.equal(stats.total, 10);
    assert.equal(stats.byAction.allow, 5);
    assert.equal(stats.byAction.drop, 5);
    assert.ok(stats.hourly.reduce((s, h) => s + h.total, 0) === 10);
  });

  it('a ingestão soma só o que entrou (duplicados ignorados)', async () => {
    const batch = [ev('a1', 'allow', 'info', 1000), ev('a2', 'deny', 'error', 2000), ev('a3', 'allow', 'info', 3000)];
    await store.insertSyslogs(SITE, 'sonicwall', batch, resolveTime);
    await store.insertSyslogs(SITE, 'sonicwall', batch, resolveTime); // repetido
    const stats = await counterCounts();
    assert.equal(stats.total, 13);
    assert.equal(stats.byAction.deny, 1);
    assert.equal(stats.byAction.allow, 7);
  });

  it('a limpeza em lotes decrementa os contadores', async () => {
    await store.insertSyslogs(SITE, 'sonicwall', [ev('old1', 'drop', 'info', 30 * HOUR), ev('old2', 'allow', 'warning', 31 * HOUR)], resolveTime);
    const before = (await counterCounts()).total;
    const purged = await store.purgeSyslogs(SITE, new Date(Date.now() - 24 * HOUR).toISOString());
    assert.equal(purged, 2);
    const stats = await counterCounts();
    assert.equal(stats.total, before - 2);
    assert.deepEqual(
      Object.fromEntries(Object.entries(stats.byAction)),
      (await realCounts()) && {
        allow: 7,
        drop: 5,
        deny: 1,
      }
    );
  });

  it('contadores == contagem real por ação/severidade', async () => {
    const stats = await counterCounts();
    const real = await realCounts();
    const fromCounters: Record<string, number> = {};
    const rows = await pool.query<{ action: string; severity: string; total: string }>(
      'SELECT action, severity, total::text AS total FROM syslog_counters WHERE site_id = $1 AND total <> 0',
      [SITE]
    );
    for (const r of rows.rows) fromCounters[`${r.action}/${r.severity}`] = Number(r.total);
    assert.deepEqual(fromCounters, real);
    assert.equal(stats.total, Object.values(real).reduce((s, n) => s + n, 0));
  });

  it('o backfill concorrente com a ingestão não perde nem duplica eventos', async () => {
    await pool.query('DELETE FROM syslog_counters WHERE site_id = $1', [SITE]);
    await pool.query('DELETE FROM syslog_hourly WHERE site_id = $1', [SITE]);
    await pool.query('DELETE FROM syslog_stats_state WHERE site_id = $1', [SITE]);
    const ingest = (async () => {
      for (let i = 0; i < 20; i += 1) {
        await store.insertSyslogs(SITE, 'sonicwall', [ev(`c${i}-1`, 'allow', 'info', i * 10), ev(`c${i}-2`, 'drop', 'info', i * 10)], resolveTime);
      }
    })();
    await Promise.all([store.backfillSyslogStats(SITE), ingest]);
    await store.backfillSyslogStats(SITE); // repetir é inofensivo (idempotente)
    const stats = await counterCounts();
    assert.equal(stats.total, Object.values(await realCounts()).reduce((s, n) => s + n, 0));
  });

  it('apagar os syslogs zera os contadores e mantém o estado "pronto"', async () => {
    await store.deleteSyslogs(SITE);
    const stats = await counterCounts();
    assert.equal(stats.total, 0);
    assert.equal(stats.oldestAt, null);
  });
});
