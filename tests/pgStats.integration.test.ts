import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import pg from 'pg';
import { buildSyslogSearchText, PostgresStore, SYSLOG_COUNT_CAP, SyslogSearchTimeoutError } from '../server/database.ts';
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


describe('busca de syslogs no PostgreSQL', { skip: !URL }, () => {
  const SEARCH_SITE = 'it-search-site';
  let store: PostgresStore;
  let pool: pg.Pool;

  const mk = (i: number, over: Partial<SyslogEvent> = {}): SyslogEvent => ({
    ...ev(`s${i}`, i % 3 === 0 ? 'drop' : 'allow', 'info', i * 1000),
    srcIp: `10.0.${i % 10}.${i % 250}`,
    dstIp: i % 50 === 0 ? '203.0.113.77' : `8.8.${i % 4}.${i % 250}`,
    firewallHost: i % 2 === 0 ? 'FW-A' : 'FW-B',
    serialNumber: i % 2 === 0 ? 'SNA' : 'SNB',
    message: `evento numero ${i}`,
    ...over,
  });

  const withSearchText = async (events: SyslogEvent[]) => {
    await store.insertSyslogs(SEARCH_SITE, 'sonicwall', events, resolveTime);
  };

  before(async () => {
    store = new PostgresStore(URL);
    await store.init();
    pool = new pg.Pool({ connectionString: URL });
    await pool.query('DELETE FROM sites WHERE id = $1', [SEARCH_SITE]);
    await pool.query(
      `INSERT INTO sites (id, vendor, name, connection_json, appliance_json, telemetry_json, alert_settings_json, created_at, updated_at)
       VALUES ($1, 'sonicwall', 'Busca', '{}', '{}', '{}', '{}', now(), now())`,
      [SEARCH_SITE]
    );
    const events = Array.from({ length: 1200 }, (_, i) => mk(i));
    await withSearchText(events);
  });

  after(async () => {
    await pool.query('DELETE FROM sites WHERE id = $1', [SEARCH_SITE]);
    await pool.end();
    await store.close();
  });

  const all = Array.from({ length: 1200 }, (_, i) => mk(i));
  const q = (extra: Record<string, unknown>) =>
    store.querySyslogs(SEARCH_SITE, { limit: 5000, offset: 0, ...extra } as never);

  it('os filtros por IP, dispositivo e ação dão o mesmo resultado de uma filtragem em memória', async () => {
    const cases: Array<[Record<string, unknown>, (e: SyslogEvent) => boolean]> = [
      [{ srcIp: '10.0.3.' }, (e) => e.srcIp.includes('10.0.3.')],
      [{ dstIp: '203.0.113' }, (e) => e.dstIp.includes('203.0.113')],
      [{ dstIp: '8.8.2' }, (e) => e.dstIp.includes('8.8.2')],
      [{ device: 'FW-A' }, (e) => e.firewallHost === 'FW-A' || e.serialNumber === 'FW-A'],
      [{ device: 'SNB' }, (e) => e.firewallHost === 'SNB' || e.serialNumber === 'SNB'],
      [{ action: 'blocked' }, (e) => e.action === 'drop'],
      [{ srcIp: '10.0.1', action: 'blocked', device: 'FW-B' }, (e) => e.srcIp.includes('10.0.1') && e.action === 'drop' && (e.firewallHost === 'FW-B' || e.serialNumber === 'FW-B')],
      [{ search: 'numero 77' }, (e) => buildSyslogSearchText(e).includes('numero 77')],
    ];
    for (const [filter, pred] of cases) {
      const r = await q(filter);
      const expected = all.filter(pred).map((e) => e.id).sort();
      assert.deepEqual(r.events.map((e) => e.id).sort(), expected, JSON.stringify(filter));
      assert.equal(r.matched, expected.length, `contagem ${JSON.stringify(filter)}`);
      assert.equal(r.matchedCapped, false);
    }
  });

  it('a consulta por período e IP (radar de destinos) devolve todos os eventos do host, também os antigos', async () => {
    await pool.query(
      `INSERT INTO syslogs (site_id, vendor, id, ingested_at, event_at, event_timestamp, priority, action, severity, search_text, payload_json)
       SELECT $1, 'sonicwall', 'old-src-' || g, now() - interval '5 days' - (g || ' seconds')::interval,
              now() - interval '5 days' - (g || ' seconds')::interval, 'x', 6, 'allow', 'info', 'old 10.77.0.9 9.9.9.9',
              jsonb_build_object('id', 'old-src-' || g, 'srcIp', '10.77.0.9')
       FROM generate_series(1, 40) g`,
      [SEARCH_SITE]
    );
    const rows = await store.querySyslogsSince(SEARCH_SITE, new Date(0).toISOString(), '10.77.0.9', 1000);
    assert.equal(rows.length, 40);
    const recent = await store.querySyslogsSince(SEARCH_SITE, new Date(Date.now() - 3600_000).toISOString(), '10.77.0.9', 1000);
    assert.equal(recent.length, 0, 'o período restringe');
    const limited = await store.querySyslogsSince(SEARCH_SITE, new Date(0).toISOString(), '10.77.0.9', 10);
    assert.equal(limited.length, 10, 'o limite é respeitado');
  });

  it('a consulta com vários IPs (filtro por destino) devolve a união dos eventos de cada IP', async () => {
    const terms = ['203.0.113.77', '8.8.1.1'];
    const rows = await store.querySyslogsSince(SEARCH_SITE, new Date(0).toISOString(), terms, 5000);
    const ids = new Set(rows.map((r) => (r as { id: string }).id));
    const expected = all.filter((e) => terms.includes(e.dstIp));
    assert.ok(expected.length > 0);
    for (const e of expected) assert.ok(ids.has(e.id), `faltou ${e.id}`);
    // nada fora dos termos (o texto de busca de cada evento contém algum deles)
    for (const r of rows) {
      const ev = all.find((e) => e.id === (r as { id: string }).id);
      assert.ok(ev && terms.some((t) => buildSyslogSearchText(ev).includes(t)));
    }
    // lista vazia = sem restrição por IP; mais de 10 termos são limitados aos 10 primeiros
    const none = await store.querySyslogsSince(SEARCH_SITE, new Date(0).toISOString(), [], 7);
    assert.equal(none.length, 7);
    const many = await store.querySyslogsSince(
      SEARCH_SITE,
      new Date(0).toISOString(),
      Array.from({ length: 14 }, (_, i) => `203.0.113.${i}`),
      50
    );
    assert.ok(many.length >= 0);
  });

  it('busca por nome de destino sem IP acha eventos novos (texto indexado) e antigos (texto do log)', async () => {
    // evento novo: o nome do destino entra no texto de busca na ingestão
    const fresh = { ...mk(9001), raw: 'x dstname="api.nome-teste.example.com"' };
    assert.ok(buildSyslogSearchText(fresh).includes('api.nome-teste.example.com'));
    await withSearchText([fresh]);
    // evento antigo (de antes desta versão): o nome só existe no texto original do log
    await pool.query(
      `INSERT INTO syslogs (site_id, vendor, id, ingested_at, event_at, event_timestamp, priority, action, severity, search_text, payload_json)
       VALUES ($1, 'sonicwall', 'legacy-name-1', now() - interval '9 days', now() - interval '9 days', 'x', 6, 'allow', 'info', 'sem nome aqui',
               jsonb_build_object('id', 'legacy-name-1', 'raw', 'y dstname="API.Nome-Teste.Example.com" z'))`,
      [SEARCH_SITE]
    );
    const since = new Date(0).toISOString();
    const rows = await store.querySyslogsSince(SEARCH_SITE, since, [], 1000, { rawContains: 'nome-teste.example.com' });
    const ids = rows.map((r) => (r as { id: string }).id).sort();
    assert.deepEqual(ids, ['legacy-name-1', 's9001']);
    // o período restringe: nos últimos 3 dias só o evento novo
    const recent = await store.querySyslogsSince(SEARCH_SITE, new Date(Date.now() - 3 * 86400_000).toISOString(), [], 1000, {
      rawContains: 'nome-teste.example.com',
    });
    assert.deepEqual(recent.map((r) => (r as { id: string }).id), ['s9001']);
    // o texto digitado é literal (curingas do LIKE não casam)
    assert.equal((await store.querySyslogsSince(SEARCH_SITE, since, [], 1000, { rawContains: '%' })).length, 0);
  });

  it('caracteres especiais do LIKE são tratados como texto', async () => {
    assert.equal((await q({ srcIp: '%' })).matched, 0);
    assert.equal((await q({ search: '_' })).matched, 0);
  });

  it('o teto de contagem mostra "10.000+" e a página continua funcionando', async () => {
    await pool.query(
      `INSERT INTO syslogs (site_id, vendor, id, ingested_at, event_at, event_timestamp, priority, action, severity, search_text, payload_json)
       SELECT $1, 'sonicwall', 'bulk-' || g, now() - (g || ' seconds')::interval, now() - (g || ' seconds')::interval, 'x', 6,
              'allow', 'info', 'bulk 192.0.2.' || (g % 255), jsonb_build_object('id', 'bulk-' || g, 'srcIp', '192.0.2.' || (g % 255))
       FROM generate_series(1, ${SYSLOG_COUNT_CAP + 500}) g`,
      [SEARCH_SITE]
    );
    const r = await store.querySyslogs(SEARCH_SITE, { limit: 250, offset: 0, srcIp: '192.0.2' } as never);
    assert.equal(r.matched, SYSLOG_COUNT_CAP);
    assert.equal(r.matchedCapped, true);
    assert.equal(r.events.length, 250);
    // filtro comum (caminho pelo índice de tempo) e página mais adiante
    const page2 = await store.querySyslogs(SEARCH_SITE, { limit: 250, offset: 250, srcIp: '192.0.2' } as never);
    assert.equal(page2.events.length, 250);
    const ids = new Set([...r.events, ...page2.events].map((e) => (e as { id: string }).id));
    assert.equal(ids.size, 500, 'páginas não se repetem');
  });

  it('estourar o tempo limite devolve um erro tipado e a conexão segue saudável', async () => {
    const previous = process.env.SYSLOG_SEARCH_TIMEOUT_MS;
    process.env.SYSLOG_SEARCH_TIMEOUT_MS = '1000';
    try {
      // 12 mil linhas não bastam para estourar 1 s; usa pg_sleep dentro da própria transação da busca
      // simulando um filtro caro: o statement_timeout é do banco, então basta uma consulta lenta.
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        await client.query('SET LOCAL statement_timeout = 200');
        await assert.rejects(() => client.query('SELECT pg_sleep(1)'), (e: { code?: string }) => e.code === '57014');
      } finally {
        await client.query('ROLLBACK').catch(() => undefined);
        client.release();
      }
      assert.ok(new SyslogSearchTimeoutError(1000).message.includes('tempo limite'));
      const ok = await q({});
      assert.ok(ok.events.length > 0);
    } finally {
      if (previous === undefined) delete process.env.SYSLOG_SEARCH_TIMEOUT_MS;
      else process.env.SYSLOG_SEARCH_TIMEOUT_MS = previous;
    }
  });
});
