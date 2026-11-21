import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import pg from 'pg';
import { PostgresStore } from '../server/database.ts';
import type { SyslogEvent } from '../server/types.ts';

/** Integração: agregação do relatório de acessos no PostgreSQL (só roda com TEST_DATABASE_URL). */
const URL = process.env.TEST_DATABASE_URL;
const SITE = 'it-access-site';

function ev(id: string, over: Partial<SyslogEvent>): SyslogEvent {
  const at = new Date(Date.now() - 600_000).toISOString();
  return {
    id, timestamp: at, firewallHost: 'fw', serialNumber: 'sn', priority: 6, severity: 'info', categoryCode: '1', categoryName: 'x',
    messageId: 'm', action: 'allow', srcIp: '10.0.0.1', srcPort: 1, srcZone: 'X0', dstIp: '8.8.8.8', dstPort: 443, dstZone: 'X1',
    natSrcIp: null, natSrcPort: null, natDstIp: null, natDstPort: null, protocol: 'tcp', ruleRef: null, natRuleRef: null,
    bytesSent: 100, bytesRcvd: 900, appName: null, user: null, message: 'm', raw: 'r', source: 'udp', ingestedAt: at,
    ...over,
  } as SyslogEvent;
}

describe('agregação do relatório de acessos (PostgreSQL)', { skip: !URL }, () => {
  let store: PostgresStore;
  let pool: pg.Pool;

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

  it('agrupa por origem/destino/serviço, soma bytes e ignora eventos de sistema', async () => {
    await store.insertSyslogs(
      SITE,
      'sonicwall',
      [
        ev('a1', {}),
        ev('a2', {}),
        ev('a3', { action: 'drop', bytesSent: 0, bytesRcvd: 0, dstIp: '1.1.1.1', srcIp: '10.0.0.2' }),
        ev('a4', { action: 'system', srcIp: '-', dstIp: '-' }),
      ],
      (e) => Date.parse(e.ingestedAt)
    );
    const r = await store.aggregateAccess(SITE, new Date(Date.now() - 3600_000).toISOString());
    assert.equal(r.timedOut, false);
    assert.equal(r.totalEvents, 3);
    const g = r.groups.find((x) => x.src === '10.0.0.1' && x.dst === '8.8.8.8');
    assert.ok(g);
    assert.equal(g.c, 2);
    assert.equal(g.up, 200);
    assert.equal(g.down, 1800);
    assert.equal(r.groups.find((x) => x.dst === '1.1.1.1')?.blocked, true);
    assert.ok(r.hours.length >= 1);
  });
});
