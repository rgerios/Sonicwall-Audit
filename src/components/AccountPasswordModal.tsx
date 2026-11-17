import { useState } from 'react';
import { KeyRound, X } from 'lucide-react';

interface AccountPasswordModalProps {
  username: string;
  onClose: () => void;
}

export function AccountPasswordModal({ username, onClose }: AccountPasswordModalProps) {
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [saving, setSaving] = useState(false);
  const [feedback, setFeedback] = useState<{ type: 'ok' | 'err'; text: string } | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setFeedback(null);
    if (newPassword !== confirmPassword) {
      setFeedback({ type: 'err', text: 'A confirmação da nova senha não confere.' });
      return;
    }

    setSaving(true);
    try {
      const res = await fetch('/api/auth/change-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ currentPassword, newPassword }),
      });
      const data = (await res.json()) as { error?: string };
      if (!res.ok) {
        setFeedback({ type: 'err', text: data.error || 'Erro ao atualizar senha.' });
      } else {
        setFeedback({ type: 'ok', text: 'Senha atualizada com sucesso.' });
        setCurrentPassword('');
        setNewPassword('');
        setConfirmPassword('');
      }
    } finally {
      setSaving(false);
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 bg-slate-950/45 flex items-center justify-center p-4"
      role="dialog"
      aria-modal="true"
      aria-label="Alterar Senha de Acesso"
    >
      <div className="w-full max-w-md bg-white border border-[var(--fw-border)] rounded-lg overflow-hidden">
        <div className="px-5 py-3.5 bg-[var(--fw-surface)] border-b border-[var(--fw-border)] flex items-center justify-between">
          <div className="flex items-center gap-2">
            <KeyRound className="w-4 h-4 text-[var(--fw-accent)]" />
            <h2 className="text-sm font-semibold text-[var(--fw-heading)]">
              Alterar Senha ({username})
            </h2>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Fechar janela"
            className="p-1 text-[var(--fw-text-muted)] hover:text-[var(--fw-heading)] rounded"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <form onSubmit={(e) => void handleSubmit(e)} className="p-5 space-y-3.5">
          <div>
            <label className="block text-xs font-medium text-[var(--fw-text-body)] mb-1">Senha Atual</label>
            <input
              type="password"
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
              required
              autoComplete="current-password"
              className="w-full px-3 py-2 text-xs border border-[var(--fw-border-strong)] rounded-md bg-[var(--fw-bg-input)] focus:outline-none focus:ring-2 focus:ring-[var(--fw-accent-mid)]"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-[var(--fw-text-body)] mb-1">
              Nova Senha (mín. 10 caracteres)
            </label>
            <input
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              required
              minLength={10}
              autoComplete="new-password"
              className="w-full px-3 py-2 text-xs border border-[var(--fw-border-strong)] rounded-md bg-[var(--fw-bg-input)] focus:outline-none focus:ring-2 focus:ring-[var(--fw-accent-mid)]"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-[var(--fw-text-body)] mb-1">
              Confirmar Nova Senha
            </label>
            <input
              type="password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              required
              minLength={10}
              autoComplete="new-password"
              className="w-full px-3 py-2 text-xs border border-[var(--fw-border-strong)] rounded-md bg-[var(--fw-bg-input)] focus:outline-none focus:ring-2 focus:ring-[var(--fw-accent-mid)]"
            />
          </div>

          {feedback && (
            <div
              className={`p-3 rounded-md border text-xs ${
                feedback.type === 'ok'
                  ? 'bg-[var(--fw-surface)] border-[var(--fw-border-strong)] text-[var(--fw-heading)]'
                  : 'bg-red-50 border-red-200 text-red-800'
              }`}
            >
              {feedback.text}
            </div>
          )}

          <div className="pt-2 flex items-center justify-end gap-2">
            <button
              type="button"
              onClick={onClose}
              className="px-3.5 py-2 text-xs font-medium text-[var(--fw-text-body)] bg-white border border-[var(--fw-border-strong)] rounded-md hover:bg-[var(--fw-bg)]"
            >
              Fechar
            </button>
            <button
              type="submit"
              disabled={saving}
              className="px-4 py-2 text-xs font-medium text-white bg-[var(--fw-accent)] rounded-md hover:bg-[var(--fw-accent-hover)] disabled:opacity-50"
            >
              {saving ? 'Salvando...' : 'Salvar Nova Senha'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
