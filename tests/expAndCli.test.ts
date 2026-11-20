import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { cliName, generateSonicOsCli, parseSonicWallExp } from '../server/parsers.ts';
import type { FirewallRule } from '../shared/types.ts';

const EXP_KV =
  'policyName_1=Allow+Web&policySrcZone_1=LAN&policyDstZone_1=WAN&policyDstSvc_1=HTTPS&policyAction_1=2&policyEnabled_1=1&' +
  'policyName_2=Block+Telnet&policySrcZone_2=WAN&policyDstZone_2=LAN&policyDstSvc_2=Telnet&policyAction_2=1&policyEnabled_2=1&';

describe('parseSonicWallExp', () => {
  it('lê chave de serviço real (policyDstSvc_) e códigos numéricos de ação', () => {
    const { rules } = parseSonicWallExp(EXP_KV);
    assert.equal(rules.length, 2);
    assert.equal(rules[0].service, 'HTTPS');
    assert.equal(rules[0].action, 'allow');
    assert.equal(rules[1].service, 'Telnet');
    assert.equal(rules[1].action, 'deny');
  });

  it('decodifica Base64 com padding "=" e & final', () => {
    const b64 = Buffer.from(EXP_KV, 'utf8').toString('base64');
    const padded = Buffer.from('policyName_1=A&policyAction_1=2&z=', 'utf8').toString('base64');
    assert.match(padded, /=$/);
    assert.equal(parseSonicWallExp(padded).rules.length, 1);
    assert.equal(parseSonicWallExp(b64 + '\n').rules.length, 2);
  });
});

describe('cliName / generateSonicOsCli', () => {
  it('remove aspas e quebras de linha que injetariam comandos', () => {
    assert.equal(cliName('evil"\nno access-rule'), '"evil no access-rule"');
    assert.equal(cliName('LAN'), 'LAN');
    assert.equal(cliName(''), '""');
  });

  it('gera script com nome sanitizado e blocos indentados', () => {
    const rule = {
      id: 'r1', name: 'x"\ncommit', fromZone: 'LAN', toZone: 'WAN',
    } as unknown as FirewallRule;
    const cli = generateSonicOsCli([rule], [], 'disable');
    assert.ok(!cli.includes('\ncommit\n    no enable'));
    assert.match(cli, /access-rule ipv4 from LAN to WAN name "x commit"\n {4}no enable\n {4}exit/);
  });
});
