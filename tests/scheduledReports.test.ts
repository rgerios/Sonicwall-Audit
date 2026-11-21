import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import type { AccessReportData } from '../shared/accessReport.ts';
import { renderAccessReportHtml } from '../server/accessReportHtml.ts';
import { advanceSlot, createScheduledReports, nextOccurrence } from '../server/scheduledReports.ts';

const sample = (host: string): AccessReportData => ({
  generatedAt: new Date().toISOString(),
  vendor: 'sonicwall',
  minutes: 1440,
  periodStart: new Date(Date.now() - 86400_000).toISOString(),
  periodEnd: new Date().toISOString(),
  analyzedEvents: 10,
  dataSource: 'memory',
  coveragePct: 100,
  timedOut: false,
  totals: { connections: 10, blocked: 1, uploadBytes: 100, downloadBytes: 900, totalBytes: 1000, sources: 1, destinations: 1, countries: 1, avgMbps: 0.1, peakHourMbps: 0.2, threatConnections: 0 },
  timeline: [{ t: new Date().toISOString(), connections: 10, blocked: 1, uploadBytes: 100, downloadBytes: 900 }],
  sources: [{ ip: '10.0.0.1', connections: 10, blocked: 1, uploadBytes: 100, downloadBytes: 900, totalBytes: 1000, destinations: 1, topCategory: 'Web', topCountry: 'US' }],
  destinations: [{ ip: '8.8.8.8', host, category: 'Web', country: 'US', asnOrg: 'Google', connections: 10, blocked: 1, totalBytes: 1000, threats: [] }],
  categories: [{ name: 'Web', connections: 10, totalBytes: 1000, destinations: 1 }],
  countries: [{ code: 'US', connections: 10, blocked: 1, totalBytes: 1000, ips: 1 }],
  services: [{ name: 'HTTPS', connections: 10, totalBytes: 1000 }],
  othersSources: { count: 0, totalBytes: 0 },
});

describe('relatório agendado', () => {
  it('calcula a próxima ocorrência do horário e avança a grade sem rajada', () => {
    const base = new Date(2026, 10, 21, 10, 0, 0).getTime();
    assert.equal(new Date(nextOccurrence(base, '06:00')).getDate(), 22);
    assert.equal(new Date(nextOccurrence(base, '23:30')).getDate(), 21);
    const slot = new Date(2026, 10, 21, 6, 0, 0).getTime();
    const afterDowntime = advanceSlot(slot, 24, slot + 5 * 86400_000 + 3600_000);
    assert.ok(afterDowntime > slot + 5 * 86400_000 && afterDowntime - (slot + 5 * 86400_000 + 3600_000) <= 86400_000);
  });

  it('HTML é estático (sem scripts nem recursos externos) e escapa nomes vindos do log', () => {
    const html = renderAccessReportHtml(sample('<script>alert(1)</script>.evil.com'), 'Matriz "A"', { label: 'SonicWall', accent: '#e8590c' });
    assert.ok(!/<script/i.test(html));
    assert.ok(!/(src|href)=["']https?:/i.test(html));
    assert.ok(html.includes('&lt;script&gt;alert(1)&lt;/script&gt;.evil.com'));
    assert.ok(html.includes('<svg'));
  });

  it('gera, lista, baixa, limita a retenção e apaga', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'fwrep-'));
    const reports = createScheduledReports({
      dataDir: dir,
      brand: { label: 'SonicWall', accent: '#e8590c' },
      listSites: () => [{ id: 'site-a', name: 'Matriz' }],
      generate: async () => sample('x.example.com'),
      log: () => undefined,
    });
    let st = await reports.save('site-a', { enabled: true, everyHours: 72, timeOfDay: '07:30', keep: 2 });
    assert.equal(st.config.enabled, true);
    assert.ok(st.config.nextRunAt);
    for (let i = 0; i < 3; i += 1) await reports.runNow('site-a', 'manual');
    const custom = await reports.runNow('site-a', 'manual', 10080);
    assert.equal(custom.minutes, 10080);
    assert.ok(custom.filename.endsWith('-7d.html'));
    st = await reports.state('site-a');
    assert.equal(st.files.length, 2);
    const f = await reports.filePath('site-a', st.files[0].id);
    assert.ok(f && (await fs.readFile(f.file, 'utf8')).startsWith('<!doctype html>'));
    assert.equal(await reports.filePath('site-a', '../../etc/passwd'), null);
    assert.equal(await reports.remove('site-a', st.files[0].id), true);
    assert.equal((await reports.state('site-a')).files.length, 1);
    await fs.rm(dir, { recursive: true, force: true });
  });
});
