import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { aggregateEventsInMemory, buildAccessReport } from '../server/accessReport.ts';
import type { Intel } from '../server/intel.ts';
import type { SyslogEvent } from '../server/types.ts';

const intel: Intel = {
  lookup: (ip: string) =>
    ip.startsWith('8.8.')
      ? { country: 'US', asn: 15169, asnOrg: 'Google LLC', threats: [] }
      : ip.startsWith('185.')
        ? { country: 'RU', asn: 1, asnOrg: 'Bad Net', threats: [{ list: 'FireHOL Level 1', category: 'blacklist' as const }] }
        : { country: null, asn: null, asnOrg: null, threats: [] },
  status: () => ({ updating: false, lastCheckAt: null, autoUpdate: false, ready: true, sources: [] }),
  update: async () => intel.status(),
  start: async () => undefined,
  stop: () => undefined,
};

const ev = (over: Partial<SyslogEvent>): SyslogEvent =>
  ({
    action: 'allow',
    srcIp: '10.0.0.1',
    dstIp: '8.8.8.8',
    dstPort: 443,
    protocol: 'tcp',
    bytesSent: 100,
    bytesRcvd: 900,
    ingestedAt: new Date().toISOString(),
    timestamp: new Date().toISOString(),
    appName: '',
    ...over,
  }) as SyslogEvent;

describe('relatório de acessos', () => {
  const events = [
    ev({}),
    ev({}),
    ev({ srcIp: '10.0.0.2', dstIp: '185.1.1.1', action: 'drop', bytesSent: 0, bytesRcvd: 0 }),
    ev({ action: 'system' }),
  ];
  const report = buildAccessReport({ agg: aggregateEventsInMemory(events), vendor: 'sonicwall', minutes: 60, sinceIso: new Date(Date.now() - 3600_000).toISOString(), dataSource: 'memory', intel });

  it('soma conexões, bloqueios e banda (upload/download) sem contar eventos de sistema', () => {
    assert.equal(report.totals.connections, 3);
    assert.equal(report.totals.blocked, 1);
    assert.equal(report.totals.uploadBytes, 200);
    assert.equal(report.totals.downloadBytes, 1800);
    assert.equal(report.totals.totalBytes, 2000);
  });

  it('ranqueia origens por volume e países por conexões, e marca ameaças', () => {
    assert.equal(report.sources[0].ip, '10.0.0.1');
    assert.equal(report.sources[0].totalBytes, 2000);
    assert.equal(report.countries[0].code, 'US');
    assert.equal(report.totals.threatConnections, 1);
    assert.deepEqual(report.destinations.find((d) => d.ip === '185.1.1.1')?.threats, ['FireHOL Level 1']);
  });

  it('classifica categorias e cobre 100% dos eventos agrupados', () => {
    assert.ok(report.categories.length > 0);
    assert.equal(report.coveragePct, 100);
    assert.equal(report.timeline.length, 1);
  });
});
