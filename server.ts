import path from 'node:path';
import express from 'express';
import dotenv from 'dotenv';
import { AuthManager } from './server/authManager.ts';
import { PostgresStore } from './server/database.ts';
import { createVendorEngine, type VendorEngineInstance } from './server/vendorEngine.ts';

dotenv.config();

const PORT = Number(process.env.PORT || 3000);
const DATA_DIR = path.resolve(process.cwd(), 'data');
const FW_VENDOR_MODE = String(process.env.FW_VENDOR || 'both').toLowerCase();

const pgStore = new PostgresStore();
const authManager = new AuthManager(DATA_DIR, pgStore);

async function startApp(): Promise<void> {
  await pgStore.init();
  await authManager.init();

  const engines: VendorEngineInstance[] = [];
  if (FW_VENDOR_MODE === 'sonicwall' || FW_VENDOR_MODE === 'both') {
    const sw = createVendorEngine({
      vendor: 'sonicwall',
      dataDir: DATA_DIR,
      pgStore,
      authManager,
    });
    await sw.init();
    engines.push(sw);
  }
  if (FW_VENDOR_MODE === 'fortigate' || FW_VENDOR_MODE === 'both') {
    const fg = createVendorEngine({
      vendor: 'fortigate',
      dataDir: DATA_DIR,
      pgStore,
      authManager,
    });
    await fg.init();
    engines.push(fg);
  }

  // Automatic hourly purge across active vendor engines
  const purgeTimer = setInterval(() => {
    for (const eng of engines) {
      void eng.purgeExpired();
    }
  }, 60 * 60 * 1000);

  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', 1);
  app.use((_req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    res.setHeader('Referrer-Policy', 'same-origin');
    next();
  });
  const largeJson = express.json({ limit: '50mb' });
  const largeText = express.text({ limit: '50mb', type: ['text/plain', 'application/octet-stream'] });
  const largePayloadPaths = new Set([
    '/api/sonicwall/syslogs/ingest',
    '/api/fortigate/syslogs/ingest',
    '/api/syslogs/ingest',
    '/api/sonicwall/config/import',
    '/api/fortigate/config/import',
    '/api/config/import',
  ]);
  const defaultJson = express.json({ limit: '2mb' });
  const defaultText = express.text({ limit: '2mb', type: ['text/plain', 'application/octet-stream'] });
  app.use((req, res, next) => {
    const parser = largePayloadPaths.has(req.path) ? largeJson : defaultJson;
    parser(req, res, next);
  });
  app.use((req, res, next) => {
    const parser = largePayloadPaths.has(req.path) ? largeText : defaultText;
    parser(req, res, next);
  });

  // Public health check
  app.get('/api/health', (_req, res) => {
    res.json({
      ok: true,
      service: 'FW Audit',
      mode: FW_VENDOR_MODE,
      vendors: engines.map((e) => e.vendor),
      storage: pgStore.isEnabled() ? 'postgresql' : 'local-json',
    });
  });

  // Shared authentication endpoints (valid across both SonicWall & FortiGate containers)
  app.get('/api/auth/status', async (req, res) => {
    if (pgStore.isEnabled() && authManager.needsSetup()) {
      await authManager.init();
    }
    res.json(authManager.getStatus(req));
  });

  app.post('/api/auth/setup', async (req, res) => {
    try {
      const username = String(req.body?.username || '').trim();
      const password = String(req.body?.password || '');
      const createdUser = await authManager.createInitialUser(username, password);
      authManager.setSessionCookie(req, res, createdUser);
      res.json({ ok: true, username: createdUser });
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Falha ao configurar acesso inicial.';
      res.status(400).json({ error: msg });
    }
  });

  app.post('/api/auth/login', async (req, res) => {
    if (pgStore.isEnabled()) {
      await authManager.init();
    }
    if (authManager.needsSetup()) {
      res.status(409).json({ error: 'Configure o usuário administrador inicial primeiro.' });
      return;
    }
    const username = String(req.body?.username || '').trim();
    const password = String(req.body?.password || '');
    // Limite de tentativas por IP e por usuário (5 falhas => bloqueio de 15 minutos)
    const lockKeys = [`ip:${req.ip}`, `user:${username.toLowerCase()}`];
    const lockedFor = Math.max(...lockKeys.map((k) => authManager.getLoginLockSeconds(k)));
    if (lockedFor > 0) {
      res.setHeader('Retry-After', String(lockedFor));
      res.status(429).json({
        error: `Muitas tentativas de login. Tente novamente em ${Math.ceil(lockedFor / 60)} minuto(s).`,
      });
      return;
    }
    await authManager.refreshUsersIfStale(true);
    const authedUser = await authManager.authenticateUser(username, password);
    if (!authedUser) {
      for (const k of lockKeys) authManager.registerLoginFailure(k);
      res.status(401).json({ error: 'Usuário ou senha inválidos.' });
      return;
    }
    for (const k of lockKeys) authManager.clearLoginFailures(k);
    authManager.setSessionCookie(req, res, authedUser);
    res.json({ ok: true, username: authedUser });
  });

  app.post('/api/auth/logout', (req, res) => {
    authManager.clearSessionCookie(req, res);
    res.json({ ok: true });
  });

  // Auth guard protecting all /api/* routes (including /api/sonicwall/* and /api/fortigate/*)
  app.use('/api', async (req, res, next) => {
    if (
      req.path === '/health' ||
      req.path === '/auth/status' ||
      req.path === '/auth/setup' ||
      req.path === '/auth/login' ||
      req.path === '/auth/logout'
    ) {
      next();
      return;
    }
    // Reload users from PostgreSQL if user was created on the companion backend container
    if (pgStore.isEnabled() && authManager.needsSetup()) {
      await authManager.init();
    }
    await authManager.refreshUsersIfStale();
    const user = authManager.getAuthenticatedUser(req);
    if (!user) {
      res.status(401).json({ error: 'Sessão não autenticada. Faça login para continuar.' });
      return;
    }
    res.locals.username = user;
    next();
  });

  app.post('/api/auth/change-password', async (req, res) => {
    const username = authManager.getAuthenticatedUser(req);
    if (!username) {
      res.status(401).json({ error: 'Não autenticado.' });
      return;
    }
    try {
      const currentPassword = String(req.body?.currentPassword || '');
      const newPassword = String(req.body?.newPassword || '');
      await authManager.changePassword(username, currentPassword, newPassword);
      // A troca invalida as sessões antigas; renova o cookie desta sessão.
      authManager.setSessionCookie(req, res, username);
      res.json({ ok: true });
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Não foi possível alterar a senha.';
      res.status(400).json({ error: msg });
    }
  });

  for (const eng of engines) {
    app.use(`/api/${eng.vendor}`, eng.router);
  }

  // Backward-compatible fallback for single-vendor calls
  const sonic = engines.find((e) => e.vendor === 'sonicwall');
  if (sonic) {
    app.use('/api', sonic.router);
  }

  if (process.env.SERVE_STATIC === 'false') {
    app.get('/', (_req, res) => {
      res.json({
        service: 'FW Audit Backend API',
        mode: FW_VENDOR_MODE,
        vendors: engines.map((e) => e.vendor),
        ok: true,
        storage: pgStore.isEnabled() ? 'postgresql' : 'local-json',
      });
    });
  } else if (process.env.NODE_ENV !== 'production') {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distDir));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distDir, 'index.html'));
    });
  }

  const httpServer = app.listen(PORT, '0.0.0.0', () => {
    console.log(
      `FW Audit (${FW_VENDOR_MODE}) ativo em http://0.0.0.0:${PORT} [storage=${pgStore.isEnabled() ? 'postgresql' : 'local-json'}]`
    );
  });

  // Encerramento limpo: grava eventos e estado pendentes antes de sair
  let shuttingDown = false;
  const shutdown = async (signal: string) => {
    if (shuttingDown) return;
    shuttingDown = true;
    console.log(`[${signal}] Encerrando: gravando dados pendentes...`);
    clearInterval(purgeTimer);
    httpServer.close();
    try {
      await Promise.all(engines.map((e) => e.shutdown()));
      await pgStore.close();
    } catch (err) {
      console.error('Erro ao encerrar:', err);
    }
    process.exit(0);
  };
  process.on('SIGTERM', () => void shutdown('SIGTERM'));
  process.on('SIGINT', () => void shutdown('SIGINT'));
}

startApp().catch((err) => {
  console.error('Erro fatal ao iniciar servidor FW Audit:', err);
  process.exit(1);
});
