import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import { DEFAULT_ALERT_SETTINGS, evaluateOverviewAlerts } from '../server/alertsEngine.ts';
import { AuthManager } from '../server/authManager.ts';
import type { SyslogEvent } from '../server/types.ts';

describe('AuthManager & AlertsEngine', () => {
  it('AuthManager creates user, authenticates async, rotates password, and encrypts secrets', async () => {
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'fwaudit-auth-'));
    try {
      const auth = new AuthManager(tmpDir);
      await auth.init();
      assert.equal(auth.needsSetup(), true);

      await auth.createInitialUser('admin', 'Str0ngPassw0rd!');
      assert.equal(auth.needsSetup(), false);

      assert.equal(await auth.authenticateUser('admin', 'wrongpass'), null);
      assert.equal(await auth.authenticateUser('admin', 'Str0ngPassw0rd!'), 'admin');

      await auth.changePassword('admin', 'Str0ngPassw0rd!', 'N3wStr0ngPassw0rd!');
      assert.equal(await auth.authenticateUser('admin', 'Str0ngPassw0rd!'), null);
      assert.equal(await auth.authenticateUser('admin', 'N3wStr0ngPassw0rd!'), 'admin');

      const encrypted = auth.encryptSecret('super-secret-token');
      assert.notEqual(encrypted, 'super-secret-token');
      assert.equal(auth.decryptSecret(encrypted), 'super-secret-token');
    } finally {
      await fs.rm(tmpDir, { recursive: true, force: true });
    }
  });

  it('evaluateOverviewAlerts detects port scan from a single source IP', () => {
    const now = new Date().toISOString();
    const syslogs: SyslogEvent[] = Array.from({ length: 12 }, (_, idx) => ({
      id: `ev-${idx}`,
      timestamp: now.slice(0, 19).replace('T', ' '),
      firewallHost: '192.168.1.1',
      serialNumber: 'SN1',
      priority: 4,
      severity: 'warning',
      categoryCode: '1024',
      categoryName: 'Security',
      messageId: '537',
      action: 'drop',
      srcIp: '198.51.100.77',
      srcPort: 50000 + idx,
      srcZone: 'WAN',
      dstIp: '10.0.0.5',
      dstPort: 1000 + idx,
      dstZone: 'DMZ',
      natSrcIp: null,
      natSrcPort: null,
      natDstIp: null,
      natDstPort: null,
      protocol: 'tcp',
      ruleRef: null,
      natRuleRef: null,
      bytesSent: 0,
      bytesRcvd: 0,
      appName: null,
      user: null,
      message: 'Port scan drop',
      raw: '',
      source: 'udp',
      ingestedAt: now,
    }));

    const alerts = evaluateOverviewAlerts(
      { interfaces: [], vpns: [], licenses: [] },
      syslogs,
      { ...DEFAULT_ALERT_SETTINGS, portScanUniquePortsThreshold: 10 },
      'sonicwall',
      { nowMs: Date.parse(now) }
    );

    assert.ok(alerts.some((a) => a.category === 'anomaly' && a.sourceIp === '198.51.100.77'));
  });
});
