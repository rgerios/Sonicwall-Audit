import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { generateFortiOsCli, parseFortiGateSyslog } from '../server/fortigateParsers.ts';
import {
  accumulateSyslogHits,
  classifyPolicies,
  generateSonicOsCli,
  parseSonicWallSyslog,
} from '../server/parsers.ts';
import type { FirewallRule } from '../server/types.ts';

describe('SonicWall & FortiGate parsers', () => {
  it('parses SonicWall syslog line with src/dst/action/rule', () => {
    const line =
      '<134>id=firewall sn=2CB8ED549A10 time="2026-11-16 14:22:10" fw=192.168.1.1 pri=6 c=1024 m=537 msg="Connection Closed" n=14820 src=10.20.4.45:51422:X0 dst=172.16.50.10:443:X1 proto=tcp/https sent=2480 rcvd=9420 fw_action="allow" rule="R-01"';
    const events = parseSonicWallSyslog(line, 'upload');
    assert.equal(events.length, 1);
    const ev = events[0];
    assert.equal(ev.srcIp, '10.20.4.45');
    assert.equal(ev.srcPort, 51422);
    assert.equal(ev.srcZone, 'X0');
    assert.equal(ev.dstIp, '172.16.50.10');
    assert.equal(ev.dstPort, 443);
    assert.equal(ev.dstZone, 'X1');
    assert.equal(ev.action, 'allow');
    assert.equal(ev.ruleRef, 'R-01');
    assert.equal(ev.bytesSent, 2480);
    assert.equal(ev.bytesRcvd, 9420);
  });

  it('parses FortiGate key=value syslog line', () => {
    const line =
      'date=2026-11-16 time=14:30:00 devname="FGT-100F" devid="FG100F123" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip=10.40.10.22 srcport=52110 srcintf="internal" dstip=172.16.80.10 dstport=443 dstintf="wan1" proto=6 action="deny" policyid=7 policyname="Block-HTTPS" service="HTTPS" sentbyte=0 rcvdbyte=0';
    const events = parseFortiGateSyslog(line, 'udp');
    assert.equal(events.length, 1);
    const ev = events[0];
    assert.equal(ev.srcIp, '10.40.10.22');
    assert.equal(ev.dstIp, '172.16.80.10');
    assert.equal(ev.dstPort, 443);
    assert.equal(ev.action, 'deny');
    assert.equal(ev.ruleRef, 'Block-HTTPS');
    assert.equal(ev.source, 'udp');
  });

  it('accumulates syslog hits and classifies unused/disabled/overpermissive rules', () => {
    const events = parseSonicWallSyslog(
      '<134>id=firewall time="2026-11-16 10:00:00" pri=6 src=10.0.0.1:1234:LAN dst=8.8.8.8:443:WAN proto=tcp/https fw_action="allow" rule="R-1"',
      'udp'
    );
    const rules: FirewallRule[] = [
      {
        id: 'R-1',
        name: 'Allow HTTPS',
        priority: 1,
        fromZone: 'LAN',
        toZone: 'WAN',
        source: 'LAN Subnet',
        destination: 'Any',
        service: 'HTTPS',
        action: 'allow',
        enabled: true,
        applianceHits: 5,
        syslogHits: 0,
        lastHitAt: null,
        comment: '',
        status: 'active',
        findingReason: '',
        sourceOrigin: 'api',
      },
      {
        id: 'R-2',
        name: 'Any Any',
        priority: 2,
        fromZone: 'WAN',
        toZone: 'DMZ',
        source: 'Any',
        destination: 'Any',
        service: 'Any',
        action: 'allow',
        enabled: true,
        applianceHits: 5,
        syslogHits: 0,
        lastHitAt: null,
        comment: '',
        status: 'active',
        findingReason: '',
        sourceOrigin: 'api',
      },
      {
        id: 'R-3',
        name: 'Old Disabled',
        priority: 3,
        fromZone: 'DMZ',
        toZone: 'WAN',
        source: 'DMZ',
        destination: 'Any',
        service: 'HTTP',
        action: 'allow',
        enabled: false,
        applianceHits: 0,
        syslogHits: 0,
        lastHitAt: null,
        comment: '',
        status: 'active',
        findingReason: '',
        sourceOrigin: 'api',
      },
    ];

    accumulateSyslogHits(rules, [], events);
    const classified = classifyPolicies(rules, []);

    assert.equal(classified.rules[0].syslogHits, 1);
    assert.equal(classified.rules[0].status, 'active');
    assert.equal(classified.rules[1].status, 'overpermissive');
    assert.equal(classified.rules[2].status, 'disabled');

    const sonicCli = generateSonicOsCli([rules[2]], [], 'disable');
    assert.match(sonicCli, /access-rule/);
    const fortiCli = generateFortiOsCli([rules[2]], [], 'disable');
    assert.match(fortiCli, /config firewall policy/);
  });
});
