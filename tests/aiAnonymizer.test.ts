import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createAnonymizer } from '../server/aiAnonymizer.ts';

describe('createAnonymizer', () => {
  it('mascara IPs, MAC e e-mail de forma estável e reversível', () => {
    const a = createAnonymizer();
    const original = 'Bloqueado 185.220.101.34 -> 10.20.1.45:443 de aa:bb:cc:dd:ee:ff, contato ti@empresa.com.br; repetiu 185.220.101.34';
    const masked = a.mask(original);
    assert.ok(!/185\.220|10\.20|aa:bb|empresa/.test(masked), masked);
    assert.match(masked, /IP-PUB-001 -> IP-PRIV-001:443/);
    assert.equal((masked.match(/IP-PUB-001/g) ?? []).length, 2);
    assert.equal(a.unmask(masked), original);
    assert.equal(a.size(), 4);
  });

  it('não confunde versão de firmware nem números longos com IP', () => {
    const a = createAnonymizer();
    assert.equal(a.mask('SonicOS 7.1.2-5051 build 1.2.3.4.5'), 'SonicOS 7.1.2-5051 build 1.2.3.4.5');
  });

  it('mantém tokens desconhecidos na resposta', () => {
    assert.equal(createAnonymizer().unmask('veja IP-PUB-099'), 'veja IP-PUB-099');
  });
});
