import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { promisify } from 'node:util';
import type { Request, Response } from 'express';
import type { PostgresStore } from './database.ts';
import type { AuthStatus } from './types.ts';

const scryptAsync = promisify(crypto.scrypt);

interface StoredUser {
  username: string;
  passwordHash: string;
  role: 'admin';
  createdAt: string;
}

interface AuthStoreFile {
  sessionSecret: string;
  encryptionKey: string;
  users: StoredUser[];
}

const SESSION_COOKIE_NAME = 'sonicaudit_session';
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;
export const MIN_PASSWORD_LENGTH = 10;
const MAX_LOGIN_FAILURES = 5;
const LOGIN_LOCK_MS = 15 * 60 * 1000;
const USERS_REFRESH_MS = 15 * 1000;

export class AuthManager {
  private filePath: string;
  private pgStore: PostgresStore | null;
  private data: AuthStoreFile;
  private loginFailures = new Map<string, { count: number; lockedUntil: number }>();
  private lastUsersRefreshMs = 0;

  constructor(dataDir: string, pgStore?: PostgresStore) {
    this.filePath = path.join(dataDir, 'auth.json');
    this.pgStore = pgStore && pgStore.isEnabled() ? pgStore : null;
    this.data = {
      sessionSecret: crypto.randomBytes(32).toString('hex'),
      encryptionKey: crypto.randomBytes(32).toString('hex'),
      users: [],
    };
  }

  async init(): Promise<void> {
    if (this.pgStore && this.pgStore.isEnabled()) {
      const pgAuth = await this.pgStore.loadAuthState();
      if (pgAuth.secrets) {
        this.data = {
          sessionSecret: pgAuth.secrets.sessionSecret,
          encryptionKey: pgAuth.secrets.encryptionKey,
          users: pgAuth.users,
        };
      } else {
        // Optional migration from existing local auth.json into PostgreSQL on first container start
        const legacy = await this.pgStore.maybeReadLegacyJsonFile<Partial<AuthStoreFile>>(this.filePath);
        if (legacy && typeof legacy.sessionSecret === 'string' && typeof legacy.encryptionKey === 'string') {
          this.data = {
            sessionSecret: legacy.sessionSecret,
            encryptionKey: legacy.encryptionKey,
            users: Array.isArray(legacy.users) ? legacy.users : [],
          };
        }
        await this.pgStore.saveAuthSecrets({
          sessionSecret: this.data.sessionSecret,
          encryptionKey: this.data.encryptionKey,
        });
        for (const u of this.data.users) {
          await this.pgStore.insertUser(u);
        }
        // Dois backends podem subir ao mesmo tempo e só um grava os segredos (ON CONFLICT
        // DO NOTHING). Relê o banco para que todos adotem exatamente os mesmos segredos.
        const stored = await this.pgStore.loadAuthState();
        if (stored.secrets) {
          this.data = {
            sessionSecret: stored.secrets.sessionSecret,
            encryptionKey: stored.secrets.encryptionKey,
            users: stored.users,
          };
        }
      }
      this.lastUsersRefreshMs = Date.now();
    } else {
      try {
        const raw = await fs.readFile(this.filePath, 'utf8');
        const parsed = JSON.parse(raw) as Partial<AuthStoreFile>;
        if (parsed && typeof parsed.sessionSecret === 'string' && typeof parsed.encryptionKey === 'string') {
          this.data = {
            sessionSecret: parsed.sessionSecret,
            encryptionKey: parsed.encryptionKey,
            users: Array.isArray(parsed.users) ? parsed.users : [],
          };
        }
      } catch {
        await this.persist();
      }
    }

    // Optional Linux headless bootstrap via environment variables
    const envUser = process.env.SONICAUDIT_ADMIN_USER?.trim();
    const envPass = process.env.SONICAUDIT_ADMIN_PASS?.trim();
    if (this.data.users.length === 0 && envUser && envPass) {
      if (envPass.length < MIN_PASSWORD_LENGTH) {
        console.warn(
          `[auth] SONICAUDIT_ADMIN_PASS ignorada: a senha deve ter pelo menos ${MIN_PASSWORD_LENGTH} caracteres.`
        );
      } else {
        await this.createInitialUser(envUser, envPass).catch(() => undefined);
      }
    }
  }

  /**
   * Recarrega usuários do PostgreSQL (com intervalo mínimo) para refletir senhas alteradas
   * ou usuários criados pelo outro container de backend.
   */
  async refreshUsersIfStale(force = false): Promise<void> {
    if (!this.pgStore || !this.pgStore.isEnabled()) return;
    const now = Date.now();
    if (!force && now - this.lastUsersRefreshMs < USERS_REFRESH_MS) return;
    this.lastUsersRefreshMs = now;
    try {
      const state = await this.pgStore.loadAuthState();
      this.data.users = state.users;
    } catch (err) {
      console.warn('[auth] Falha ao recarregar usuários:', err instanceof Error ? err.message : err);
    }
  }

  /** Retorna os segundos restantes de bloqueio, ou 0 se a tentativa é permitida. */
  getLoginLockSeconds(key: string): number {
    const entry = this.loginFailures.get(key);
    if (!entry) return 0;
    const remaining = entry.lockedUntil - Date.now();
    if (remaining <= 0) {
      if (entry.lockedUntil > 0) this.loginFailures.delete(key);
      return 0;
    }
    return Math.ceil(remaining / 1000);
  }

  registerLoginFailure(key: string): void {
    const entry = this.loginFailures.get(key) || { count: 0, lockedUntil: 0 };
    entry.count += 1;
    if (entry.count >= MAX_LOGIN_FAILURES) {
      entry.lockedUntil = Date.now() + LOGIN_LOCK_MS;
      entry.count = 0;
    }
    this.loginFailures.set(key, entry);
    if (this.loginFailures.size > 5000) {
      const now = Date.now();
      for (const [k, v] of this.loginFailures) {
        if (v.lockedUntil < now) this.loginFailures.delete(k);
      }
    }
  }

  clearLoginFailures(key: string): void {
    this.loginFailures.delete(key);
  }

  private async persist(): Promise<void> {
    if (this.pgStore && this.pgStore.isEnabled()) {
      await this.pgStore.saveAuthSecrets({
        sessionSecret: this.data.sessionSecret,
        encryptionKey: this.data.encryptionKey,
      });
      return;
    }
    await fs.mkdir(path.dirname(this.filePath), { recursive: true });
    await fs.writeFile(this.filePath, JSON.stringify(this.data, null, 2), {
      encoding: 'utf8',
      mode: 0o600,
    });
  }

  private async hashPassword(password: string): Promise<string> {
    const salt = crypto.randomBytes(16).toString('hex');
    const derived = (await scryptAsync(password, salt, 64)) as Buffer;
    return `${salt}:${derived.toString('hex')}`;
  }

  private async verifyPassword(password: string, storedHash: string): Promise<boolean> {
    const parts = storedHash.split(':');
    if (parts.length !== 2) return false;
    const [salt, keyHex] = parts;
    if (!salt || !keyHex) return false;
    const keyBuf = Buffer.from(keyHex, 'hex');
    const derivedBuf = (await scryptAsync(password, salt, 64)) as Buffer;
    if (keyBuf.length !== derivedBuf.length) return false;
    return crypto.timingSafeEqual(keyBuf, derivedBuf);
  }

  needsSetup(): boolean {
    return this.data.users.length === 0;
  }

  async createInitialUser(usernameRaw: string, password: string): Promise<string> {
    await this.refreshUsersIfStale(true);
    if (!this.needsSetup()) {
      throw new Error('O acesso administrativo já foi configurado.');
    }
    const username = usernameRaw.trim();
    if (username.length < 3) {
      throw new Error('O nome de usuário deve ter pelo menos 3 caracteres.');
    }
    if (password.length < MIN_PASSWORD_LENGTH) {
      throw new Error(`A senha deve ter pelo menos ${MIN_PASSWORD_LENGTH} caracteres.`);
    }
    const newUser: StoredUser = {
      username,
      passwordHash: await this.hashPassword(password),
      role: 'admin',
      createdAt: new Date().toISOString(),
    };
    this.data.users.push(newUser);
    if (this.pgStore && this.pgStore.isEnabled()) {
      await this.pgStore.insertUser(newUser);
      // Se o outro backend criou o mesmo usuário primeiro, o INSERT é ignorado: adota o
      // registro que realmente ficou no banco para que os dois validem a mesma senha.
      await this.refreshUsersIfStale(true);
    } else {
      await this.persist();
    }
    return username;
  }

  async authenticateUser(usernameRaw: string, password: string): Promise<string | null> {
    const username = usernameRaw.trim().toLowerCase();
    const found = this.data.users.find((u) => u.username.toLowerCase() === username);
    if (!found) return null;
    if (!(await this.verifyPassword(password, found.passwordHash))) return null;
    return found.username;
  }

  async changePassword(
    usernameRaw: string,
    currentPassword: string,
    newPassword: string
  ): Promise<void> {
    const username = usernameRaw.trim().toLowerCase();
    const found = this.data.users.find((u) => u.username.toLowerCase() === username);
    if (!found) {
      throw new Error('Usuário não encontrado.');
    }
    if (!(await this.verifyPassword(currentPassword, found.passwordHash))) {
      throw new Error('Senha atual incorreta.');
    }
    if (newPassword.length < MIN_PASSWORD_LENGTH) {
      throw new Error(`A nova senha deve ter pelo menos ${MIN_PASSWORD_LENGTH} caracteres.`);
    }
    const nextHash = await this.hashPassword(newPassword);
    found.passwordHash = nextHash;
    if (this.pgStore && this.pgStore.isEnabled()) {
      await this.pgStore.updateUserPassword(found.username, nextHash);
    } else {
      await this.persist();
    }
  }

  /** Impressão digital da senha atual: trocar a senha invalida as sessões existentes. */
  private passwordVersion(user: StoredUser): string {
    return crypto
      .createHmac('sha256', this.data.sessionSecret)
      .update(user.passwordHash)
      .digest('base64url')
      .slice(0, 16);
  }

  private signToken(username: string): string {
    const user = this.data.users.find((u) => u.username === username);
    const payload = Buffer.from(
      JSON.stringify({
        u: username,
        exp: Date.now() + SESSION_TTL_MS,
        v: user ? this.passwordVersion(user) : '',
      }),
      'utf8'
    ).toString('base64url');
    const sig = crypto
      .createHmac('sha256', this.data.sessionSecret)
      .update(payload)
      .digest('base64url');
    return `${payload}.${sig}`;
  }

  private verifyToken(token: string | undefined): string | null {
    if (!token) return null;
    const dotIdx = token.indexOf('.');
    if (dotIdx <= 0) return null;
    const payload = token.slice(0, dotIdx);
    const sig = token.slice(dotIdx + 1);
    if (!payload || !sig) return null;

    const expectedSig = crypto
      .createHmac('sha256', this.data.sessionSecret)
      .update(payload)
      .digest('base64url');

    const sigBuf = Buffer.from(sig, 'utf8');
    const expectedBuf = Buffer.from(expectedSig, 'utf8');
    if (sigBuf.length !== expectedBuf.length || !crypto.timingSafeEqual(sigBuf, expectedBuf)) {
      return null;
    }

    try {
      const parsed = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as {
        u?: string;
        exp?: number;
        v?: string;
      };
      if (!parsed.u || typeof parsed.exp !== 'number' || parsed.exp < Date.now()) {
        return null;
      }
      const user = this.data.users.find((u) => u.username === parsed.u);
      if (!user || parsed.v !== this.passwordVersion(user)) return null;
      return parsed.u;
    } catch {
      return null;
    }
  }

  private parseCookie(req: Request, name: string): string | undefined {
    const header = req.headers.cookie;
    if (!header) return undefined;
    for (const part of header.split(';')) {
      const eq = part.indexOf('=');
      if (eq > 0) {
        const key = part.slice(0, eq).trim();
        if (key === name) {
          return decodeURIComponent(part.slice(eq + 1).trim());
        }
      }
    }
    return undefined;
  }

  private isHttps(req: Request): boolean {
    const forwarded = String(req.headers['x-forwarded-proto'] || '').toLowerCase();
    return req.secure || forwarded.includes('https');
  }

  setSessionCookie(req: Request, res: Response, username: string): void {
    const token = this.signToken(username);
    const maxAgeSec = Math.floor(SESSION_TTL_MS / 1000);
    const attrs = [
      `${SESSION_COOKIE_NAME}=${encodeURIComponent(token)}`,
      'Path=/',
      `Max-Age=${maxAgeSec}`,
      'HttpOnly',
      this.isHttps(req) ? 'SameSite=Lax; Secure' : 'SameSite=Lax',
    ];
    res.setHeader('Set-Cookie', attrs.join('; '));
  }

  clearSessionCookie(req: Request, res: Response): void {
    const attrs = [
      `${SESSION_COOKIE_NAME}=`,
      'Path=/',
      'Max-Age=0',
      'HttpOnly',
      this.isHttps(req) ? 'SameSite=Lax; Secure' : 'SameSite=Lax',
    ];
    res.setHeader('Set-Cookie', attrs.join('; '));
  }

  getAuthenticatedUser(req: Request): string | null {
    const token = this.parseCookie(req, SESSION_COOKIE_NAME);
    return this.verifyToken(token);
  }

  getStatus(req: Request): AuthStatus {
    const username = this.getAuthenticatedUser(req);
    return {
      authenticated: Boolean(username),
      needsSetup: this.needsSetup(),
      username,
    };
  }

  encryptSecret(plaintext: string): string {
    const trimmed = plaintext.trim();
    if (!trimmed) return '';
    const key = Buffer.from(this.data.encryptionKey, 'hex');
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([cipher.update(trimmed, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    return `${iv.toString('hex')}:${tag.toString('hex')}:${encrypted.toString('hex')}`;
  }

  decryptSecret(ciphertext: string | undefined): string {
    if (!ciphertext) return '';
    const parts = ciphertext.split(':');
    if (parts.length !== 3) return '';
    try {
      const key = Buffer.from(this.data.encryptionKey, 'hex');
      const iv = Buffer.from(parts[0], 'hex');
      const tag = Buffer.from(parts[1], 'hex');
      const enc = Buffer.from(parts[2], 'hex');
      const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
      decipher.setAuthTag(tag);
      return Buffer.concat([decipher.update(enc), decipher.final()]).toString('utf8');
    } catch {
      return '';
    }
  }
}
