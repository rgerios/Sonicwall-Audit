import { useCallback, useEffect, useState } from 'react';
import { AlertCircle, AlertTriangle, Info, RefreshCw, Search, Terminal, Trash2 } from 'lucide-react';
import type { AppLogEntry, AppLogLevel, FirewallVendor } from '../types.ts';
import { vendorApiUrl } from '../utils/vendorApi.ts';

interface AppLogsPanelProps {
  vendor: FirewallVendor;
  refreshTrigger?: number;
}

export function AppLogsPanel({ vendor, refreshTrigger = 0 }: AppLogsPanelProps) {
  const [logs, setLogs] = useState<AppLogEntry[]>([]);
  const [level, setLevel] = useState<'all' | AppLogLevel>('all');
  const [search, setSearch] = useState('');
  const [loading, setLoading] = useState(false);

  const fetchLogs = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams({ level, search, limit: '120' });
      const res = await fetch(vendorApiUrl(vendor, `/app-logs?${params.toString()}`));
      if (res.ok) {
        const data = (await res.json()) as { logs?: AppLogEntry[] };
        setLogs(data.logs || []);
      }
    } finally {
      setLoading(false);
    }
  }, [vendor, level, search]);

  useEffect(() => {
    void fetchLogs();
  }, [fetchLogs, refreshTrigger]);

  const handleClear = async () => {
    const res = await fetch(vendorApiUrl(vendor, '/app-logs'), { method: 'DELETE' });
    if (res.ok) {
      setLogs([]);
    }
  };

  const renderBadge = (lvl: AppLogLevel) => {
    if (lvl === 'error') {
      return (
        <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-red-500/20 text-red-300 font-semibold uppercase text-[10px]">
          <AlertCircle className="w-3 h-3" /> ERRO
        </span>
      );
    }
    if (lvl === 'warn') {
      return (
        <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-300 font-semibold uppercase text-[10px]">
          <AlertTriangle className="w-3 h-3" /> AVISO
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-sky-500/20 text-sky-300 font-semibold uppercase text-[10px]">
        <Info className="w-3 h-3" /> INFO
      </span>
    );
  };

  return (
    <div className="bg-white border border-[var(--fw-border)] rounded-lg p-6 space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <Terminal className="w-4 h-4 text-[var(--fw-accent)]" />
          <div>
            <h3 className="text-sm font-semibold text-[var(--fw-heading)]">
              Logs da Aplicação (Diagnóstico)
            </h3>
            <p className="text-xs text-[var(--fw-text-muted)]">
              Acompanhe em tempo real erros de conexão/autenticação com o firewall, receptor UDP, IA e API.
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-[var(--fw-text-subtle)] absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Filtrar mensagem..."
              className="pl-8 pr-3 py-1.5 text-xs border border-[var(--fw-border-strong)] rounded-md bg-[var(--fw-bg-input)] focus:outline-none focus:ring-2 focus:ring-[var(--fw-accent-mid)]"
            />
          </div>

          <div className="inline-flex rounded-md border border-[var(--fw-border-strong)] bg-[var(--fw-bg)] p-0.5 text-[11px]">
            {(
              [
                { id: 'all', label: 'Todos' },
                { id: 'error', label: 'Erros' },
                { id: 'warn', label: 'Avisos' },
                { id: 'info', label: 'Info' },
              ] as const
            ).map((opt) => (
              <button
                key={opt.id}
                type="button"
                onClick={() => setLevel(opt.id)}
                className={`px-2.5 py-1 rounded font-medium transition-colors cursor-pointer ${
                  level === opt.id
                    ? 'bg-white text-[var(--fw-heading)] shadow-xs'
                    : 'text-[var(--fw-text-body)] hover:text-[var(--fw-heading)]'
                }`}
              >
                {opt.label}
              </button>
            ))}
          </div>

          <button
            type="button"
            onClick={() => void fetchLogs()}
            disabled={loading}
            className="inline-flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-medium text-[var(--fw-text-body)] bg-white border border-[var(--fw-border-strong)] rounded-md hover:bg-[var(--fw-surface)] cursor-pointer disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Atualizar
          </button>

          {logs.length > 0 && (
            <button
              type="button"
              onClick={() => void handleClear()}
              className="inline-flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-medium text-red-700 bg-white border border-red-200 rounded-md hover:bg-red-50 cursor-pointer"
            >
              <Trash2 className="w-3.5 h-3.5" />
              Limpar
            </button>
          )}
        </div>
      </div>

      <div className="bg-[var(--fw-terminal-bg)] text-[var(--fw-terminal-text)] rounded-md p-3 font-mono text-[11px] max-h-72 overflow-y-auto space-y-1.5">
        {logs.length === 0 ? (
          <div className="py-6 text-center opacity-70">
            Nenhum registro de log encontrado para o filtro atual.
          </div>
        ) : (
          logs.map((entry) => (
            <div
              key={entry.id}
              className="border-b border-white/10 pb-1.5 last:border-b-0 last:pb-0 space-y-0.5"
            >
              <div className="flex flex-wrap items-center gap-2">
                <span className="opacity-65 tabular-nums">
                  {new Date(entry.ts).toLocaleString('pt-BR', {
                    day: '2-digit',
                    month: '2-digit',
                    hour: '2-digit',
                    minute: '2-digit',
                    second: '2-digit',
                  })}
                </span>
                {renderBadge(entry.level)}
                <span className="px-1.5 py-0.5 rounded bg-white/10 text-[10px]">
                  {entry.scope}
                </span>
                <span className="font-semibold">{entry.message}</span>
              </div>
              {entry.detail && (
                <div className="pl-2 opacity-85 break-words text-[11px] text-amber-200">
                  ↳ {entry.detail}
                </div>
              )}
            </div>
          ))
        )}
      </div>
    </div>
  );
}
