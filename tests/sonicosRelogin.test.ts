import assert from 'node:assert/strict';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { describe, it } from 'node:test';
import { fetchSonicOsAudit } from '../server/sonicosClient.ts';

function startMock(handler: (req: http.IncomingMessage, res: http.ServerResponse) => void) {
  return new Promise<{ server: http.Server; port: number }>((resolve) => {
    const server = http.createServer(handler).listen(0, '127.0.0.1', () => {
      resolve({ server, port: (server.address() as AddressInfo).port });
    });
  });
}

describe('fetchSonicOsAudit resiliência', () => {
  it('refaz o login após 401 e tenta de novo a requisição', async () => {
    let logins = 0;
    let ruleCalls = 0;
    const { server, port } = await startMock((req, res) => {
      res.setHeader('Content-Type', 'application/json');
      if (req.url === '/api/sonicos/auth' && req.method === 'POST') {
        logins += 1;
        res.setHeader('Set-Cookie', `sid=s${logins}; Path=/`);
        res.end('{}');
        return;
      }
      if (req.url === '/api/sonicos/auth') {
        res.end('{}');
        return;
      }
      if (req.url === '/api/sonicos/access-rules/ipv4') {
        ruleCalls += 1;
        if (req.headers.cookie !== 'sid=s2') {
          res.statusCode = 401;
          res.end('{}');
          return;
        }
        res.end(JSON.stringify({ access_rules: [{ ipv4: { name: 'R1', uuid: 'u1', from: 'LAN', to: 'WAN', action: 'allow', enable: true } }] }));
        return;
      }
      res.statusCode = 404;
      res.end('{}');
    });
    try {
      const result = await fetchSonicOsAudit({
        host: '127.0.0.1', port, protocol: 'http', username: 'u', password: 'p', ignoreTlsErrors: false,
      } as never);
      assert.equal(logins, 2, 'deve logar de novo uma única vez');
      assert.ok(ruleCalls >= 2);
      assert.equal(result.rules.length, 1);
    } finally {
      server.close();
    }
  });

  it('repete a requisição em 503 transitório', async () => {
    let calls = 0;
    const { server, port } = await startMock((req, res) => {
      res.setHeader('Content-Type', 'application/json');
      if (req.url?.startsWith('/api/sonicos/auth')) {
        res.end('{}');
        return;
      }
      if (req.url === '/api/sonicos/access-rules/ipv4') {
        calls += 1;
        if (calls === 1) {
          res.statusCode = 503;
          res.end('{}');
          return;
        }
        res.end(JSON.stringify({ access_rules: [{ ipv4: { name: 'R1', uuid: 'u1', from: 'LAN', to: 'WAN', action: 'allow', enable: true } }] }));
        return;
      }
      res.statusCode = 404;
      res.end('{}');
    });
    try {
      const result = await fetchSonicOsAudit({
        host: '127.0.0.1', port, protocol: 'http', username: 'u', password: 'p', ignoreTlsErrors: false,
      } as never);
      assert.equal(calls, 2);
      assert.equal(result.rules.length, 1);
    } finally {
      server.close();
    }
  });
});
