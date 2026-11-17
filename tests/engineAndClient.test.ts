import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  addEventsToRuntime,
  buildHourlyLogVolume,
  computeIpConsumption,
  computeWindowRankings,
  deriveInterfaceThroughput,
  diffPolicies,
  emptyRuntime,
} from '../server/engineHelpers.ts';
import { normalizeRateMbps } from '../server/sonicosClient.ts';
import type { FirewallRule, SyslogEvent } from '../server/types.ts';

function makeEvent(overrides: Partial<SyslogEvent>): SyslogEvent {
  const iso = new Date().toISOString();
  return {
    id: 'ev-1',
    timestamp: iso.slice(0, 19).replace('T', ' '),
    firewallHost: '192.168.1.1',
    serialNumber: 'SN01',
    priority: 6,
    severity: 'info',
    categoryCode: '1024',
    categoryName: 'Traffic',
    messageId: '537',
    action: 'allow',
    srcIp: '10.0.0.10',
    srcPort: 50000,
    srcZone: 'LAN',
    dstIp: '1.1.1.1',
    dstPort: 443,
    dstZone: 'WAN',
    natSrcIp: null,
    natSrcPort: null,
    natDstIp: null,
    natDstPort: null,
    protocol: 'tcp/https',
    ruleRef: null,
    natRuleRef: null,
    bytesSent: 100,
    bytesRcvd: 200,
    appName: null,
    user: null,
    message: 'Allowed',
    raw: '',
    source: 'udp',
    ingestedAt: iso,
    ...overrides,
  };
}

describe('sonicosClient & engineHelpers', () => {
  it('normalizeRateMbps separates ingress_mbps (rx) and egress_mbps (tx)', () => {
    const sample = { ingress_mbps: 42.5 };
    assert.equal(normalizeRateMbps(sample, 'rx'), 42.5);
    assert.equal(normalizeRateMbps(sample, 'tx'), 0);

    const both = { ingress_mbps: 10, egress_mbps: 5.25 };
    assert.equal(normalizeRateMbps(both, 'rx'), 10);
    assert.equal(normalizeRateMbps(both, 'tx'), 5.25);
  });

  it('addEventsToRuntime, buildHourlyLogVolume and computeWindowRankings aggregate correctly', () => {
    const now = Date.now();
    const iso = new Date(now).toISOString();
    const events: SyslogEvent[] = [
      makeEvent({ id: '1', ingestedAt: iso, action: 'allow' }),
      makeEvent({
        id: '2',
        ingestedAt: iso,
        priority: 4,
        severity: 'warning',
        action: 'drop',
        srcIp: '203.0.113.5',
        srcZone: 'WAN',
        dstIp: '192.168.1.10',
        dstPort: 22,
        dstZone: 'DMZ',
        protocol: 'tcp/ssh',
      }),
    ];

    const rt = emptyRuntime();
    addEventsToRuntime(rt, events);
    assert.equal(rt.total, 2);
    assert.equal(rt.byAction.allow, 1);
    assert.equal(rt.byAction.drop, 1);

    const hourly = buildHourlyLogVolume(rt.hourly, now);
    assert.equal(hourly.length, 24);
    assert.equal(hourly[23].total, 2);
    assert.equal(hourly[23].allow, 1);
    assert.equal(hourly[23].blocked, 1);

    const rankings = computeWindowRankings(events);
    assert.equal(rankings.topBlockedSources[0].ip, '203.0.113.5');
    assert.equal(rankings.topBlockedSources[0].count, 1);
    assert.equal(rankings.topTargetedPorts.length, 2);
  });

  it('diffPolicies detects added, modified, and removed rules', () => {
    const baseRule = (id: string, name: string, enabled = true): FirewallRule => ({
      id,
      name,
      priority: 1,
      fromZone: 'LAN',
      toZone: 'WAN',
      source: 'Any',
      destination: 'Any',
      service: 'HTTPS',
      action: 'allow',
      enabled,
      applianceHits: 0,
      syslogHits: 0,
      lastHitAt: null,
      comment: '',
      status: 'active',
      findingReason: '',
      sourceOrigin: 'api',
    });

    const prev = [baseRule('1', 'Rule A', true), baseRule('2', 'Rule B', true)];
    const next = [baseRule('1', 'Rule A', false), baseRule('3', 'Rule C', true)];
    const details: string[] = [];
    const diff = diffPolicies('Regra', prev, next, details);

    assert.deepEqual(diff, { added: 1, removed: 1, modified: 1 });
    assert.equal(details.length, 3);
  });

  it('deriveInterfaceThroughput computes Rx/Tx Mbps from byte deltas when API returns 0', () => {
    const prevSyncAt = '2026-11-16T23:00:00.000Z';
    const nowIso = '2026-11-16T23:00:10.000Z'; // 10 seconds later
    const prevTelemetry = {
      interfaces: [
        {
          name: 'wan1',
          zone: 'WAN',
          ip: '200.1.1.1',
          role: 'wan-primary' as const,
          linkStatus: 'up' as const,
          linkSpeedMbps: 100,
          rxMbps: 0,
          txMbps: 0,
          rxBytes: 1_000_000,
          txBytes: 500_000,
          rxErrors: 0,
          txErrors: 0,
          utilizationPercent: 0,
        },
      ],
      vpns: [],
      licenses: [],
    };
    const nextTelemetry = {
      interfaces: [
        {
          ...prevTelemetry.interfaces[0],
          // +25,000,000 bytes in 10s = 20 Mbps; +12,500,000 bytes in 10s = 10 Mbps
          rxBytes: 26_000_000,
          txBytes: 13_000_000,
        },
      ],
      vpns: [],
      licenses: [],
    };

    const derived = deriveInterfaceThroughput(prevTelemetry, prevSyncAt, nextTelemetry, nowIso);
    assert.equal(derived.interfaces[0].rxMbps, 20);
    assert.equal(derived.interfaces[0].txMbps, 10);
    assert.equal(derived.interfaces[0].utilizationPercent, 30);
  });

  it('computeIpConsumption aggregates IP bandwidth, top consumers and destinations', () => {
    const now = Date.now();
    const recentIso = new Date(now - 60_000).toISOString();
    const oldIso = new Date(now - 2 * 60 * 60_000).toISOString();
    const events: SyslogEvent[] = [
      makeEvent({
        id: 'c1',
        ingestedAt: recentIso,
        srcIp: '10.20.4.45',
        dstIp: '172.16.50.10',
        dstPort: 443,
        bytesSent: 15_000_000,
        bytesRcvd: 60_000_000,
      }),
      makeEvent({
        id: 'c2',
        ingestedAt: recentIso,
        srcIp: '10.20.4.99',
        dstIp: '8.8.8.8',
        dstPort: 53,
        bytesSent: 1_000,
        bytesRcvd: 2_000,
      }),
      makeEvent({
        id: 'c3-old',
        ingestedAt: oldIso,
        srcIp: '10.20.4.45',
        dstIp: '172.16.50.10',
        bytesSent: 999_999_999,
        bytesRcvd: 999_999_999,
      }),
    ];

    const report = computeIpConsumption(events, '10.20.4.45', 15, now);
    assert.equal(report.eventCount, 1);
    assert.equal(report.bytesSent, 15_000_000);
    assert.equal(report.bytesRcvd, 60_000_000);
    assert.equal(report.totalBytes, 75_000_000);
    assert.equal(report.topConsumers[0].ip, '10.20.4.45');
    assert.equal(report.topDestinations[0].ip, '172.16.50.10');
    assert.equal(report.timeline.length, 12);
    assert.ok(report.avgMbps > 0);
  });
});
