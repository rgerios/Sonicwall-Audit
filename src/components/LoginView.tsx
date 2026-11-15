import { useState } from 'react';
import { Eye, EyeOff, Lock, ShieldCheck, Terminal, UserPlus } from 'lucide-react';

interface LoginViewProps {
  needsSetup: boolean;
  onAuthenticated: (username: string) => void;
}

export function LoginView({ needsSetup, onAuthenticated }: LoginViewProps) {
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (needsSetup && password !== confirmPassword) {
      setError('A confirmação de senha não confere.');
      return;
    }

    setSubmitting(true);
    try {
      const endpoint = needsSetup ? '/api/auth/setup' : '/api/auth/login';
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: username.trim(), password }),
      });
      const data = (await res.json()) as { username?: string; error?: string };
      if (!res.ok) {
        setError(data.error || 'Não foi possível autenticar.');
      } else {
        onAuthenticated(data.username || username.trim());
      }
    } catch {
      setError('Erro de comunicação com o servidor FW Audit.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen bg-[var(--fw-bg)] text-[var(--fw-text)] flex items-center justify-center p-6">
      <div className="w-full max-w-md bg-white border border-[var(--fw-border)] rounded-lg overflow-hidden">
        <div className="bg-[var(--fw-surface)] border-b border-[var(--fw-border)] px-6 py-5 flex items-center gap-3">
          <div className="w-9 h-9 rounded-md bg-[var(--fw-accent)] text-white flex items-center justify-center shrink-0">
            <Terminal className="w-5 h-5" aria-hidden="true" />
          </div>
          <div>
            <h1 className="text-base font-bold tracking-tight text-[var(--fw-heading)]">FW Audit</h1>
            <p className="text-xs text-[var(--fw-text-muted)]">
              Auditoria SonicWall &amp; FortiGate · Syslog &amp; PostgreSQL
            </p>
          </div>
        </div>

        <form onSubmit={(e) => void handleSubmit(e)} className="p-6 space-y-4">
          <div className="space-y-1">
            <h2 className="text-sm font-semibold text-[var(--fw-heading)] flex items-center gap-2">
              {needsSetup ? (
                <>
                  <UserPlus className="w-4 h-4 text-[var(--fw-accent)]" />
                  Criar Acesso Administrativo Inicial
                </>
              ) : (
                <>
                  <Lock className="w-4 h-4 text-[var(--fw-accent)]" />
                  Acesso Protegido
                </>
              )}
            </h2>
            <p className="text-xs text-[var(--fw-text-muted)] leading-relaxed">
              {needsSetup
                ? 'Defina o usuário e a senha únicos que protegerão os ambientes SonicWall e FortiGate neste servidor.'
                : 'Informe suas credenciais para acessar os firewalls SonicWall, FortiGate e relatórios persistidos.'}
            </p>
          </div>

          <div>
            <label className="block text-xs font-medium text-[var(--fw-text-body)] mb-1">Usuário</label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              minLength={3}
              autoComplete="username"
              placeholder="admin"
              className="w-full px-3 py-2 text-xs font-mono border border-[var(--fw-border-strong)] rounded-md bg-[var(--fw-bg-input)] focus:outline-none focus:ring-2 focus:ring-[var(--fw-accent-mid)]"
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-[var(--fw-text-body)] mb-1">Senha</label>
            <div className="relative">
              <input
                type={showPassword ? 'text' : 'password'}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                minLength={6}
                autoComplete={needsSetup ? 'new-password' : 'current-password'}
                placeholder="••••••••"
                className="w-full px-3 py-2 pr-9 text-xs border border-[var(--fw-border-strong)] rounded-md bg-[var(--fw-bg-input)] focus:outline-none focus:ring-2 focus:ring-[var(--fw-accent-mid)]"
              />
              <button
                type="button"
                onClick={() => setShowPassword((v) => !v)}
                aria-label={showPassword ? 'Ocultar senha' : 'Mostrar senha'}
                className="absolute right-2.5 top-1/2 -translate-y-1/2 text-[var(--fw-text-subtle)] hover:text-[var(--fw-heading)]"
              >
                {showPassword ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
              </button>
            </div>
          </div>

          {needsSetup && (
            <div>
              <label className="block text-xs font-medium text-[var(--fw-text-body)] mb-1">
                Confirmar Senha
              </label>
              <input
                type={showPassword ? 'text' : 'password'}
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                required
                minLength={6}
                autoComplete="new-password"
                placeholder="••••••••"
                className="w-full px-3 py-2 text-xs border border-[var(--fw-border-strong)] rounded-md bg-[var(--fw-bg-input)] focus:outline-none focus:ring-2 focus:ring-[var(--fw-accent-mid)]"
              />
            </div>
          )}

          {error && (
            <div className="p-3 rounded-md border border-red-200 bg-red-50 text-xs text-red-800">
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={submitting}
            className="w-full inline-flex items-center justify-center gap-2 px-4 py-2.5 text-xs font-medium text-white bg-[var(--fw-accent)] rounded-md hover:bg-[var(--fw-accent-hover)] disabled:opacity-50 transition-colors"
          >
            <ShieldCheck className="w-4 h-4" />
            {submitting
              ? 'Validando...'
              : needsSetup
                ? 'Criar Acesso e Entrar'
                : 'Entrar no Painel'}
          </button>

          <p className="text-[11px] text-[var(--fw-text-subtle)] text-center pt-1">
            Sessão única via cookie HttpOnly · Credenciais criptografadas com scrypt + AES-256-GCM
          </p>
        </form>
      </div>
    </div>
  );
}
