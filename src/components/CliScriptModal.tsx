import { useState } from 'react';
import { Check, Copy, Download, X } from 'lucide-react';
import type { FirewallVendor } from '../types.ts';

interface CliScriptModalProps {
  vendor: FirewallVendor;
  title: string;
  script: string;
  mode: 'disable' | 'delete';
  onModeChange: (mode: 'disable' | 'delete') => void;
  onClose: () => void;
}

export function CliScriptModal({
  vendor,
  title,
  script,
  mode,
  onModeChange,
  onClose,
}: CliScriptModalProps) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(script);
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    } catch {
      // Fallback ignored if clipboard blocked
    }
  };

  const handleDownload = () => {
    const blob = new Blob([script], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    const prefix = vendor === 'fortigate' ? 'fortios' : 'sonicos';
    anchor.download = `${prefix}-remediation-${mode}.txt`;
    anchor.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div
      className="fixed inset-0 z-50 bg-slate-950/50 flex items-center justify-center p-4"
      role="dialog"
      aria-modal="true"
      aria-labelledby="cli-modal-title"
    >
      <div className="bg-white border border-[var(--fw-border)] rounded-lg w-full max-w-3xl overflow-hidden shadow-lg">
        <div className="px-6 py-4 border-b border-[var(--fw-border)] flex items-center justify-between gap-4">
          <div>
            <h2 id="cli-modal-title" className="text-base font-semibold text-[var(--fw-heading)]">
              {title}
            </h2>
            <p className="text-xs text-[var(--fw-text-muted)] mt-0.5">
              Recomendado desabilitar primeiro e monitorar por 7 a 14 dias antes da remoção definitiva.
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="p-2 text-[var(--fw-text-muted)] hover:text-[var(--fw-heading)] rounded-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--fw-accent-mid)]"
            aria-label="Fechar modal"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="px-6 py-3 bg-[var(--fw-surface)] border-b border-[var(--fw-border)] flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-1 p-1 bg-[var(--fw-surface-chip)] rounded-md">
            <button
              type="button"
              onClick={() => onModeChange('disable')}
              className={`px-3 py-1.5 text-xs font-medium rounded transition-colors whitespace-nowrap ${
                mode === 'disable'
                  ? 'bg-white text-[var(--fw-heading)] shadow-xs'
                  : 'text-[var(--fw-text-body)] hover:text-[var(--fw-heading)]'
              }`}
            >
              Desabilitar (Seguro)
            </button>
            <button
              type="button"
              onClick={() => onModeChange('delete')}
              className={`px-3 py-1.5 text-xs font-medium rounded transition-colors whitespace-nowrap ${
                mode === 'delete'
                  ? 'bg-white text-red-700 shadow-xs'
                  : 'text-[var(--fw-text-body)] hover:text-[var(--fw-heading)]'
              }`}
            >
              Remover Definitivamente
            </button>
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={handleCopy}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-[var(--fw-text-body)] bg-white border border-[var(--fw-border-strong)] rounded-md hover:bg-[var(--fw-bg)] whitespace-nowrap"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-700" /> : <Copy className="w-3.5 h-3.5" />}
              {copied ? 'Copiado' : 'Copiar CLI'}
            </button>
            <button
              type="button"
              onClick={handleDownload}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-white bg-[var(--fw-accent)] rounded-md hover:bg-[var(--fw-accent-hover)] whitespace-nowrap"
            >
              <Download className="w-3.5 h-3.5" />
              Baixar .txt
            </button>
          </div>
        </div>

        <div className="p-6 bg-[var(--fw-terminal-bg)] text-[var(--fw-terminal-text)] max-h-[420px] overflow-auto">
          <pre className="font-mono text-xs leading-6 whitespace-pre-wrap">{script}</pre>
        </div>
      </div>
    </div>
  );
}
