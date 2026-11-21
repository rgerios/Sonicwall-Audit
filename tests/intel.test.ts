import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { ipv4ToInt, parseCidrList, parseDbIpCsv } from '../server/intel.ts';

describe('intel (bases offline)', () => {
  it('converte IPv4 e rejeita lixo', () => {
    assert.equal(ipv4ToInt('1.0.0.1'), 16777217);
    assert.equal(ipv4ToInt('255.255.255.255'), 4294967295);
    assert.equal(ipv4ToInt('256.1.1.1'), null);
    assert.equal(ipv4ToInt('::1'), null);
  });

  it('lê CSV de país do DB-IP (aspas, IPv6 ignorado)', () => {
    const idx = parseDbIpCsv('"1.0.0.0","1.0.0.255","AU"\n1.0.1.0,1.0.3.255,CN\n2001:db8::,2001:db8::ffff,US\n', 'geo');
    assert.equal(idx.starts.length, 2);
    assert.deepEqual(idx.values, ['AU', 'CN']);
  });

  it('lê CSV de ASN com organização entre aspas e vírgula', () => {
    const idx = parseDbIpCsv('1.0.0.0,1.0.0.255,13335,"CLOUDFLARENET, Inc."\n', 'asn') as ReturnType<typeof parseDbIpCsv> & {
      asns: Uint32Array;
      orgs: string[];
    };
    assert.equal(idx.asns[0], 13335);
    assert.equal(idx.orgs[Number(idx.values[0])], 'CLOUDFLARENET, Inc.');
  });

  it('compila lista de CIDR/IP/JSON, ignora comentários e funde sobreposições', () => {
    const idx = parseCidrList(
      ['# comentario', '10.0.0.0/24 ; SBL1', '10.0.0.128/25', '{"cidr":"192.0.2.0/30","sblid":"SBL2"}', '203.0.113.9', 'lixo'].join('\n')
    );
    assert.equal(idx.starts.length, 3);
    assert.equal(idx.starts[0], ipv4ToInt('10.0.0.0'));
    assert.equal(idx.ends[0], ipv4ToInt('10.0.0.255'));
    assert.equal(idx.ends[2], ipv4ToInt('203.0.113.9'));
  });
});
