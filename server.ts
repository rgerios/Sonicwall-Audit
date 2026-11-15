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
  setInterval(() => {
    for (const eng of engines) {
      eng.purgeExpired();
    }
  }, 60 * 60 * 1000);

  const app = express();
  app.set('trust proxy', 1);
  app.use(express.json({ limit: '50mb' }));
  app.use(express.text({ limit: '50mb', type: ['text/plain', 'application/octet-stream'] }));

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
    const authedUser = authManager.authenticateUser(username, password);
    if (!authedUser) {
      res.status(401).json({ error: 'Usuário ou senha inválidos.' });
      return;
    }
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
    const user = authManager.getAuthenticatedUser(req);
    if (!user) {
      res.status(401).json({ error: 'Sessão não autenticada. Faça login para continuar.' });
      return;
    }
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

  app.listen(PORT, '0.0.0.0', () => {
    console.log(
      `FW Audit (${FW_VENDOR_MODE}) ativo em http://0.0.0.0:${PORT} [storage=${pgStore.isEnabled() ? 'postgresql' : 'local-json'}]`
    );
  });
}

startApp().catch((err) => {
  console.error('Erro fatal ao iniciar servidor FW Audit:', err);
  process.exit(1);
});
