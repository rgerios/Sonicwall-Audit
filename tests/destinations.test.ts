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
import {
  buildDestinationNodes,
  buildSourceNodes,
  eventMatchesDestination,
  filterEventsByDestination,
  filterEventsBySource,
  normalizeDestinationFilter,
  normalizeSourceFilter,
} from '../server/destinationsEngine.ts';
import { subnetGroup, summarizeSources } from '../shared/sources.ts';
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
  category: 'Web', connections: 1, blocked: 0, bytes: 0, sources: 1, topSources: [], services: [], lastSeen: null, ...over,
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

describe('filtro por IP de origem e origens por destino', () => {
  const lines = [
    '<134>id=firewall sn=ABC time="2026-01-01 10:00:00" fw=1.1.1.1 pri=6 c=1024 m=537 msg="x" src=10.0.0.5:1:X0 dst=8.8.8.8:53:X1 proto=udp/53 sent=1 rcvd=1 fw_action="allow"',
    '<134>id=firewall sn=ABC time="2026-01-01 10:00:01" fw=1.1.1.1 pri=6 c=1024 m=537 msg="x" src=10.0.0.5:2:X0 dst=8.8.8.8:53:X1 proto=udp/53 sent=1 rcvd=1 fw_action="allow"',
    '<134>id=firewall sn=ABC time="2026-01-01 10:00:02" fw=1.1.1.1 pri=6 c=1024 m=537 msg="x" src=10.0.0.6:3:X0 dst=8.8.8.8:53:X1 proto=udp/53 sent=1 rcvd=1 fw_action="allow"',
    '<134>id=firewall sn=ABC time="2026-01-01 10:00:03" fw=1.1.1.1 pri=6 c=1024 m=537 msg="x" src=10.0.1.9:4:X0 dst=1.1.1.1:443:X1 proto=tcp/https sent=1 rcvd=1 fw_action="allow"',
  ].join('\n');
  const events = parseSonicWallSyslog(lines, 'upload');

  it('lista as origens que mais acessam cada destino', () => {
    const { nodes } = buildDestinationNodes(events);
    const dns = nodes.find((n) => n.id === '8.8.8.8')!;
    assert.equal(dns.sources, 2);
    assert.deepEqual(dns.topSources, [
      { ip: '10.0.0.5', count: 2 },
      { ip: '10.0.0.6', count: 1 },
    ]);
  });

  it('o filtro por origem aceita prefixo e restringe os destinos', () => {
    const only = filterEventsBySource(events, '10.0.0.5');
    assert.equal(only.length, 2);
    const { nodes } = buildDestinationNodes(only);
    assert.equal(nodes.length, 1);
    assert.equal(nodes[0].connections, 2);
    assert.equal(filterEventsBySource(events, '10.0.0.').length, 3);
    assert.equal(filterEventsBySource(events, '').length, events.length);
    assert.equal(filterEventsBySource(events, '192.168').length, 0);
  });

  it('valida o texto do filtro', () => {
    assert.equal(normalizeSourceFilter('  10.0.0.5 '), '10.0.0.5');
    assert.equal(normalizeSourceFilter('FE80::1'), 'fe80::1');
    assert.equal(normalizeSourceFilter(''), '');
    assert.equal(normalizeSourceFilter(undefined), '');
    assert.equal(normalizeSourceFilter("10.0.0.5' OR 1=1"), null);
    assert.equal(normalizeSourceFilter('a'.repeat(60)), null);
  });
});

describe('origens (quem consome) e filtro por destino', () => {
  const log = (t: number, src: string, dst: string, extra: string, action = 'allow') =>
    `<134>id=firewall sn=ABC time="2026-01-01 10:00:0${t}" fw=1.1.1.1 pri=6 c=1024 m=537 msg="x" src=${src}:1:X0 dst=${dst}:443:X1 proto=tcp/https sent=100 rcvd=900 fw_action="${action}"${extra}`;
  const events = parseSonicWallSyslog(
    [
      log(1, '10.0.0.5', '52.96.1.1', ' dstname="outlook.office365.com"'),
      log(2, '10.0.0.5', '52.96.1.1', ' dstname="outlook.office365.com"'),
      log(3, '10.0.0.5', '142.250.1.1', ' dstname="www.google.com"', 'drop'),
      log(4, '10.0.0.6', '142.250.1.1', ' dstname="www.google.com"'),
      log(5, '10.0.1.9', '142.250.1.1', ' dstname="mail.google.com"'), // mesmo IP, outro domínio (CDN compartilhada)
      log(6, '10.0.0.7', '203.0.113.9', ''),
    ].join('\n'),
    'upload'
  );

  it('agrega por origem: consumo, destinos distintos, categorias e bloqueios', () => {
    const { nodes, analyzed } = buildSourceNodes(events);
    assert.equal(analyzed, 6);
    assert.equal(nodes[0].ip, '10.0.0.5');
    assert.equal(nodes[0].connections, 3);
    assert.equal(nodes[0].blocked, 1);
    assert.equal(nodes[0].bytes, 3000);
    assert.equal(nodes[0].destinations, 2);
    assert.deepEqual(nodes[0].topDestinations[0], { label: 'outlook.office365.com', count: 2 });
    assert.ok(nodes[0].categories.some((c) => c.name === 'Software e atualizações'));
    assert.equal(nodes[0].group, '10.0.0.0/24');
    assert.equal(nodes.find((n) => n.ip === '10.0.1.9')?.group, '10.0.1.0/24');
    assert.equal(nodes.find((n) => n.ip === '10.0.0.7')?.topDestinations[0].label, '203.0.113.9');
  });

  it('sub-rede por IPv4 e IPv6', () => {
    assert.equal(subnetGroup('192.168.10.45'), '192.168.10.0/24');
    assert.equal(subnetGroup('2001:db8:1:2:aaaa::1'), '2001:db8:1:2::/64');
    assert.equal(subnetGroup('não é ip'), null);
  });

  it('valida o filtro de destino', () => {
    assert.deepEqual(normalizeDestinationFilter('Outlook.Office365.com', '52.96.1.1, 52.96.1.2'), {
      text: 'outlook.office365.com',
      ips: ['52.96.1.1', '52.96.1.2'],
    });
    assert.deepEqual(normalizeDestinationFilter('', ''), { text: '', ips: [] });
    assert.equal(normalizeDestinationFilter("x' OR 1=1", ''), null);
    assert.equal(normalizeDestinationFilter('', '1.2.3.4;drop'), null);
    assert.equal(normalizeDestinationFilter('', Array.from({ length: 11 }, (_, i) => `1.1.1.${i}`).join(',')), null);
  });

  it('filtro por nome casa pelo nome (e não pelo IP compartilhado), com subdomínios por "contém"', () => {
    const byHost = filterEventsByDestination(events, { text: 'www.google.com', ips: ['142.250.1.1'] });
    assert.equal(byHost.length, 2, 'mail.google.com usa o mesmo IP mas é outro nome');
    const byDomain = filterEventsByDestination(events, { text: 'google.com', ips: [] });
    assert.equal(byDomain.length, 3);
    // sem nome conhecido cai nos IPs exatos do destino clicado
    assert.equal(filterEventsByDestination(events, { text: '203.0.113.9', ips: [] }).length, 1);
    assert.equal(filterEventsByDestination(events, { text: '', ips: ['203.0.113.9'] }).length, 1);
    assert.equal(filterEventsByDestination(events, { text: '', ips: [] }).length, events.length);
  });

  it('usa o nome do DNS reverso em cache quando o log não traz o nome', () => {
    const noName = events[5];
    assert.equal(eventMatchesDestination(noName, { text: 'example.net', ips: [] }), false);
    assert.equal(eventMatchesDestination(noName, { text: 'example.net', ips: [] }, () => 'host.example.net'), true);
  });

  it('filtros combinados: origem e destino', () => {
    const only = filterEventsByDestination(filterEventsBySource(events, '10.0.0.5'), { text: 'google.com', ips: [] });
    assert.equal(only.length, 1);
    assert.equal(buildSourceNodes(only).nodes[0].blocked, 1);
  });

  it('resume as maiores origens, categorias e fatos', () => {
    const { nodes } = buildSourceNodes(events);
    const s = summarizeSources(nodes, 'connections');
    assert.equal(s.top[0].node.ip, '10.0.0.5');
    assert.ok(Math.abs(s.top[0].share - 0.5) < 1e-9);
    assert.ok(s.facts.some((f) => /maiores origens/.test(f)));
    assert.ok(s.facts.some((f) => /bloqueadas/.test(f)));
    assert.ok(s.categories.length > 0);
  });
});
