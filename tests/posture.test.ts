import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { computePosture, postureDelta } from '../src/utils/posture.ts';
import type { AuditOverview } from '../shared/types.ts';

function makeOverview(patch: Partial<AuditOverview> = {}): AuditOverview {
  return {
    totalSyslogs: 100,
    rulesSummary: { total: 10, active: 10, unused: 0, shadowed: 0, disabled: 0, overpermissive: 0 },
    natsSummary: { total: 5, active: 5, unused: 0, disabled: 0, orphaned: 0 },
    alerts: [],
    udpStatus: { running: true, port: 5514, bindAddress: '0.0.0.0', packetsReceived: 5, lastPacketAt: 'x', lastError: null },
    ...patch,
  } as unknown as AuditOverview;
}

describe('computePosture', () => {
  it('returns unknown without data', () => {
    const r = computePosture(makeOverview({ totalSyslogs: 0, rulesSummary: { total: 0 } as never, natsSummary: { total: 0 } as never }));
    assert.equal(r.grade, 'unknown');
  });

  it('gives 100 and no findings for a clean policy', () => {
    const r = computePosture(makeOverview());
    assert.equal(r.score, 100);
    assert.equal(r.grade, 'good');
    assert.equal(r.findings.length, 0);
  });

  it('orders findings by severity and caps penalties', () => {
    const r = computePosture(
      makeOverview({
        rulesSummary: { total: 10, active: 0, unused: 5, shadowed: 2, disabled: 1, overpermissive: 9 },
        alerts: Array.from({ length: 9 }, (_, i) => ({ id: String(i), severity: 'critical' })) as never,
      })
    );
    assert.equal(r.findings[0].id, 'alerts-critical');
    assert.equal(r.findings.find((f) => f.id === 'alerts-critical')?.penalty, 40);
    assert.equal(r.findings.find((f) => f.id === 'rules-overpermissive')?.penalty, 24);
    assert.ok(r.score >= 0 && r.score <= 100);
    assert.equal(r.grade, 'critical');
  });

  it('flags missing syslog coverage', () => {
    const r = computePosture(
      makeOverview({ totalSyslogs: 0, udpStatus: { running: false, port: 5514 } as never })
    );
    assert.ok(r.findings.some((f) => f.id === 'coverage-no-syslog'));
  });
});

describe('postureDelta', () => {
  const now = Date.now();
  it('ignores snapshots newer than 1h or older than 7 days', () => {
    assert.equal(postureDelta([{ at: now - 1000, score: 50, findings: 1 }], 80, now), null);
    assert.equal(postureDelta([{ at: now - 8 * 86400_000, score: 50, findings: 1 }], 80, now), null);
  });
  it('compares against the oldest snapshot in the window', () => {
    const d = postureDelta(
      [
        { at: now - 3 * 86400_000, score: 60, findings: 4 },
        { at: now - 2 * 3600_000, score: 70, findings: 3 },
      ],
      80,
      now
    );
    assert.equal(d?.delta, 20);
  });
});
