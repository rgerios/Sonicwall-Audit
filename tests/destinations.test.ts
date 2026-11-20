import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  classifyDestination,
  extractDestinationHints,
  ipScope,
  registrableDomain,
  serviceLabel,
  shortHostLabel,
  summarizeDestinations,
  type DestinationNode,
} from '../shared/destinations.ts';
import { buildDestinationNodes } from '../server/destinationsEngine.ts';
import { createReverseResolver } from '../server/rdns.ts';
import { parseFortiGateSyslog } from '../server/fortigateParsers.ts';
import { parseSonicWallSyslog } from '../server/parsers.ts';

describe('shared destinations helpers', () => {
  it('classifica o escopo dos IPs', () => {
    assert.equal(ipScope('10.1.2.3'), 'internal');
    assert.equal(ipScope('172.20.1.1'), 'internal');
    assert.equal(ipScope('172.32.1.1'), 'public');
    assert.equal(ipScope('8.8.8.8'), 'public');
    assert.equal(ipScope('224.0.0.251'), 'multicast');
    assert.equal(ipScope('ff02::fb'), 'multicast');
    assert.equal(ipScope('fe80::1'), 'internal');
  });

  it('extrai o domínio registrável', () => {
    assert.equal(registrableDomain('a.b.microsoft.com'), 'microsoft.com');
    assert.equal(registrableDomain('www.uol.com.br'), 'uol.com.br');
    assert.equal(registrableDomain('pki.goog'), 'pki.goog');
    assert.equal(shortHostLabel('edge.microsoft.com', 'microsoft.com'), 'edge');
    assert.equal(shortHostLabel('microsoft.com', 'microsoft.com'), 'microsoft.com');
  });

  it('lê pistas de FQDN e categoria da linha original', () => {
    assert.deepEqual(
      extractDestinationHints('id=x dstname=Edge.Microsoft.com dst=1.2.3.4:443 appcat="Web.Client"'),
      { host: 'edge.microsoft.com', appCategory: 'Web.Client' }
    );
    assert.equal(extractDestinationHints('url="https://login.live.com/path?q=1"').host, 'login.live.com');
    assert.equal(extractDestinationHints('hostname=10.0.0.5').host, null);
    assert.equal(extractDestinationHints('hostname=localhost').host, null);
  });

  it('rotula serviços e categorias', () => {
    assert.equal(serviceLabel('tcp/https', 443, null), 'HTTPS');
    assert.equal(serviceLabel('udp', 9999, null), 'UDP/9999');
    assert.equal(serviceLabel('tcp', 443, 'Microsoft 365'), 'Microsoft 365');
    const base = { appCategory: null, scope: 'public' as const };
    assert.equal(classifyDestination({ ...base, host: 'ocsp.digicert.com', service: 'HTTP' }), 'Segurança online');
    assert.equal(classifyDestination({ ...base, host: 'x.windowsupdate.com', service: 'HTTPS' }), 'Software e atualizações');
    assert.equal(classifyDestination({ ...base, host: null, service: 'RDP' }), 'Acesso remoto');
    assert.equal(classifyDestination({ ...base, host: null, service: 'DNS' }), 'DNS e infraestrutura');
    assert.equal(classifyDestination({ host: null, service: 'UDP/5353', appCategory: null, scope: 'multicast' }), 'Multicast e descoberta');
    assert.equal(classifyDestination({ ...base, host: null, service: 'UDP/9', appCategory: 'Cloud.IT' }), 'Nuvem e hospedagem');
  });
});

const node = (over: Partial<DestinationNode>): DestinationNode => ({
  id: 'x', label: 'x', host: null, hostSource: null, ip: '1.1.1.1', ips: [], group: null, scope: 'public',
  category: 'Web', connections: 1, blocked: 0, bytes: 0, sources: 1, services: [], lastSeen: null, ...over,
});

describe('summarizeDestinations', () => {
  it('calcula top 5, categorias e fatos', () => {
    const nodes = Array.from({ length: 12 }, (_, i) =>
      node({ id: `n${i}`, connections: 100 - i * 5, blocked: i === 0 ? 10 : 0, category: i < 6 ? 'Web' : 'Nuvem' })
    );
    const s = summarizeDestinations(nodes, 'connections');
    assert.equal(s.top.length, 5);
    assert.equal(s.top[0].node.id, 'n0');
    assert.equal(s.categories[0].category, 'Web');
    assert.ok(Math.abs(s.categories.reduce((a, c) => a + c.share, 0) - 1) < 1e-9);
    assert.match(s.facts[0], /principais destinos/);
    assert.ok(s.facts.some((f) => /bloqueadas/.test(f)));
  });
});

describe('buildDestinationNodes', () => {
  const sonic = parseSonicWallSyslog(
    [
      '<134>id=firewall sn=ABC time="2026-01-01 10:00:00" fw=1.1.1.1 pri=6 c=1024 m=537 msg="Connection Closed" src=10.0.0.5:5000:X0 dst=52.96.1.1:443:X1 proto=tcp/https sent=100 rcvd=900 fw_action="allow" dstname="outlook.office365.com"',
      '<134>id=firewall sn=ABC time="2026-01-01 10:00:01" fw=1.1.1.1 pri=6 c=1024 m=537 msg="Connection Closed" src=10.0.0.6:5001:X0 dst=52.96.1.2:443:X1 proto=tcp/https sent=50 rcvd=450 fw_action="allow" dstname="login.office365.com"',
      '<132>id=firewall sn=ABC time="2026-01-01 10:00:02" fw=1.1.1.1 pri=4 c=32 m=537 msg="Denied" src=10.0.0.5:5002:X0 dst=45.1.2.3:3389:X1 proto=tcp/3389 fw_action="deny"',
      '<134>id=firewall sn=ABC time="2026-01-01 10:00:03" fw=1.1.1.1 pri=6 c=1024 m=537 msg="Closed" src=10.0.0.5:5003:X0 dst=45.1.2.3:3389:X1 proto=tcp/3389 fw_action="deny"',
    ].join('\n'),
    'upload'
  );

  it('agrupa por FQDN do log, soma métricas e classifica', () => {
    const { nodes, analyzed } = buildDestinationNodes(sonic);
    assert.equal(analyzed, 4);
    const outlook = nodes.find((n) => n.id === 'outlook.office365.com');
    assert.ok(outlook);
    assert.equal(outlook!.group, 'office365.com');
    assert.equal(outlook!.hostSource, 'log');
    assert.equal(outlook!.bytes, 1000);
    const rdp = nodes.find((n) => n.id === '45.1.2.3');
    assert.equal(rdp?.connections, 2);
    assert.equal(rdp?.blocked, 2);
    assert.equal(rdp?.category, 'Acesso remoto');
    assert.equal(rdp?.services[0].name, 'RDP');
    assert.equal(rdp?.sources, 1);
  });

  it('usa o nome do DNS reverso em cache só para IPs públicos e respeita o limite', () => {
    const { nodes } = buildDestinationNodes(sonic, {
      lookupHost: (ip) => (ip === '45.1.2.3' ? 'host.example.net' : null),
      maxNodes: 2,
    });
    assert.equal(nodes[0].id, 'host.example.net');
    assert.equal(nodes[0].hostSource, 'rdns');
    assert.equal(nodes.length, 2);
  });

  it('ignora eventos de sistema e sem destino', () => {
    const forti = parseFortiGateSyslog(
      'date=2026-01-01 time=10:00:00 devname="FG" type="event" subtype="system" msg="x"\n' +
        'date=2026-01-01 time=10:00:01 devname="FG" type="traffic" subtype="forward" srcip=10.0.0.1 dstip=8.8.8.8 dstport=53 proto=17 service="DNS" action="accept" sentbyte=60 rcvdbyte=120',
      'upload'
    );
    const { nodes } = buildDestinationNodes(forti);
    assert.equal(nodes.length, 1);
    assert.equal(nodes[0].id, '8.8.8.8');
    assert.equal(nodes[0].category, 'DNS e infraestrutura');
  });
});

describe('createReverseResolver', () => {
  it('resolve em segundo plano, guarda cache e ignora IPs não públicos', async () => {
    const calls: string[] = [];
    const r = createReverseResolver({
      enabled: true,
      reverse: async (ip) => {
        calls.push(ip);
        if (ip === '8.8.8.8') return ['dns.google.'];
        throw new Error('ENOTFOUND');
      },
    });
    assert.equal(r.lookupCached('8.8.8.8'), undefined);
    r.schedule(['8.8.8.8', '10.0.0.1', '9.9.9.9', '8.8.8.8']);
    await new Promise((resolve) => setTimeout(resolve, 50));
    assert.equal(r.lookupCached('8.8.8.8'), 'dns.google');
    assert.equal(r.lookupCached('9.9.9.9'), null);
    assert.equal(r.lookupCached('10.0.0.1'), undefined);
    assert.deepEqual(calls.sort(), ['8.8.8.8', '9.9.9.9']);
    assert.equal(r.stats().resolved, 1);
  });

  it('não consulta nada quando desativado', async () => {
    let called = false;
    const r = createReverseResolver({ enabled: false, reverse: async () => { called = true; return []; } });
    r.schedule(['8.8.8.8']);
    await new Promise((resolve) => setTimeout(resolve, 20));
    assert.equal(called, false);
  });
});
