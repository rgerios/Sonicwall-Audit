import { useEffect, useMemo, useRef, useState } from 'react';
import {
  Activity,
  ArrowLeftRight,
  Bot,
  Building2,
  CornerDownLeft,
  Database,
  FileBarChart2,
  FileTerminal,
  KeyRound,
  LogOut,
  Moon,
  Radar,
  RefreshCw,
  Search,
  Server,
  ServerCog,
  ShieldAlert,
  Sun,
  Bell,
} from 'lucide-react';
import type { ActiveSection, AuditOverview, FirewallVendor } from '../types.ts';

interface CommandPaletteProps {
  open: boolean;
  onClose: () => void;
  vendor: FirewallVendor;
  overview: AuditOverview | null;
  colorMode: 'light' | 'dark';
  onNavigate: (section: ActiveSection) => void;
  onSelectVendor: (vendor: FirewallVendor) => void;
  onSelectSite: (siteId: string) => void;
  onInvestigate: (query: string) => void;
  onToggleColorMode: () => void;
  onToggleToastPopups: () => void;
  onLoadSample: () => void;
  onRefresh: () => void;
  onOpenAlertConfig: () => void;
  onOpenPasswordModal: () => void;
  onLogout: () => void;
}

interface Command {
  id: string;
  label: string;
  hint?: string;
  group: 'Ir para' | 'Ações' | 'Ambiente' | 'Localidades' | 'Buscar';
  icon: typeof Activity;
  keywords?: string;
  run: () => void;
}

const IPV4 = /^(?:\d{1,3}\.){3}\d{1,3}$/;
const IP_PARTIAL = /^\d{1,3}(?:\.\d{0,3}){1,3}$/;

function normalize(value: string): string {
  return value.normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase();
}

/** Pontuação simples: prefixo > palavra > substring > letras em ordem. 0 = sem correspondência. */
function score(query: string, text: string): number {
  if (!query) return 1;
  const q = normalize(query);
  const t = normalize(text);
  if (t.startsWith(q)) return 100;
  if (t.split(/[\s/·-]+/).some((w) => w.startsWith(q))) return 80;
  if (t.includes(q)) return 60;
  let i = 0;
  for (const ch of t) if (ch === q[i]) i += 1;
  return i === q.length ? 20 : 0;
}

export function CommandPalette(props: CommandPaletteProps) {
  const { open, onClose, vendor, overview, colorMode } = props;
  const [query, setQuery] = useState('');
  const [cursor, setCursor] = useState(0);
  const inputRef = useRef<HTMLInputElement | null>(null);
  const listRef = useRef<HTMLUListElement | null>(null);
  const previouslyFocused = useRef<HTMLElement | null>(null);

  useEffect(() => {
    if (open) {
      previouslyFocused.current = document.activeElement as HTMLElement | null;
      setQuery('');
      setCursor(0);
      requestAnimationFrame(() => inputRef.current?.focus());
    } else {
      previouslyFocused.current?.focus?.();
    }
  }, [open]);

  const commands = useMemo<Command[]>(() => {
    const go = (section: ActiveSection) => () => props.onNavigate(section);
    const list: Command[] = [
      { id: 'go-overview', label: 'Visão Geral', group: 'Ir para', icon: Activity, keywords: 'inicio home dashboard', run: go('overview') },
      { id: 'go-syslogs', label: 'Syslogs', group: 'Ir para', icon: FileTerminal, keywords: 'logs eventos', run: go('syslogs') },
      { id: 'go-destinations', label: 'Destinos (radar)', group: 'Ir para', icon: Radar, keywords: 'bolhas fqdn dominios internet trafego', run: go('destinations') },
      { id: 'go-rules', label: 'Regras Sem Uso', group: 'Ir para', icon: ShieldAlert, keywords: 'firewall politicas sombreadas', run: go('rules') },
      { id: 'go-nats', label: vendor === 'fortigate' ? 'NATs, VIPs e IP Pools Sem Uso' : 'NATs Sem Uso', group: 'Ir para', icon: ArrowLeftRight, keywords: 'nat vip', run: go('nats') },
      { id: 'go-reports', label: 'Relatórios', group: 'Ir para', icon: FileBarChart2, keywords: 'pdf exportar', run: go('reports') },
      { id: 'go-ai', label: 'Análise com IA', group: 'Ir para', icon: Bot, keywords: 'gemini chat assistente', run: go('ai') },
      { id: 'go-connect', label: 'Localidades, Conexão e Linux', group: 'Ir para', icon: ServerCog, keywords: 'conectar importar api syslog udp', run: go('connect') },
      { id: 'act-refresh', label: 'Atualizar dados agora', group: 'Ações', icon: RefreshCw, keywords: 'recarregar', run: props.onRefresh },
      { id: 'act-alerts', label: 'Limites e alertas', hint: 'configurar', group: 'Ações', icon: Bell, keywords: 'anomalias notificacoes', run: props.onOpenAlertConfig },
      { id: 'act-sample', label: 'Carregar amostra de demonstração', group: 'Ações', icon: Database, keywords: 'demo exemplo', run: props.onLoadSample },
      {
        id: 'act-theme',
        label: colorMode === 'dark' ? 'Mudar para tema claro' : 'Mudar para tema escuro',
        group: 'Ações',
        icon: colorMode === 'dark' ? Sun : Moon,
        keywords: 'dark light aparencia',
        run: props.onToggleColorMode,
      },
      { id: 'act-toasts', label: 'Alternar popups de alerta', group: 'Ações', icon: Bell, keywords: 'toast notificacoes', run: props.onToggleToastPopups },
      { id: 'act-password', label: 'Alterar minha senha', group: 'Ações', icon: KeyRound, keywords: 'conta', run: props.onOpenPasswordModal },
      { id: 'act-logout', label: 'Sair', group: 'Ações', icon: LogOut, keywords: 'logout encerrar', run: props.onLogout },
    ];
    for (const target of ['sonicwall', 'fortigate'] as const) {
      if (target !== vendor) {
        list.push({
          id: `vendor-${target}`,
          label: `Trocar para ${target === 'sonicwall' ? 'SonicWall' : 'FortiGate'}`,
          group: 'Ambiente',
          icon: Server,
          keywords: 'ambiente fabricante',
          run: () => props.onSelectVendor(target),
        });
      }
    }
    for (const site of overview?.sites ?? []) {
      if (site.id === overview?.activeSite?.id) continue;
      list.push({
        id: `site-${site.id}`,
        label: `Localidade: ${site.name}`,
        hint: site.location || undefined,
        group: 'Localidades',
        icon: Building2,
        keywords: `${site.location ?? ''} firewall site`,
        run: () => props.onSelectSite(site.id),
      });
    }
    return list;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [vendor, overview?.sites, overview?.activeSite?.id, colorMode]);

  const results = useMemo(() => {
    const trimmed = query.trim();
    const out: Command[] = [];
    if (trimmed && (IPV4.test(trimmed) || IP_PARTIAL.test(trimmed))) {
      out.push({
        id: 'search-ip',
        label: `Investigar ${trimmed} nos syslogs`,
        hint: IPV4.test(trimmed) ? 'IP' : 'prefixo de IP',
        group: 'Buscar',
        icon: Search,
        run: () => props.onInvestigate(trimmed),
      });
    }
    const ranked = commands
      .map((c) => ({ c, s: Math.max(score(trimmed, c.label), score(trimmed, c.keywords ?? '') * 0.6) }))
      .filter((x) => x.s > 0)
      .sort((a, b) => b.s - a.s);
    out.push(...ranked.map((x) => x.c));
    if (trimmed && !IPV4.test(trimmed) && ranked.length === 0) {
      out.push({
        id: 'search-text',
        label: `Buscar “${trimmed}” nos syslogs`,
        group: 'Buscar',
        icon: Search,
        run: () => props.onInvestigate(trimmed),
      });
    }
    return out;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [query, commands]);

  useEffect(() => {
    setCursor(0);
  }, [query]);

  useEffect(() => {
    const el = listRef.current?.querySelector<HTMLElement>(`[data-index="${cursor}"]`);
    el?.scrollIntoView({ block: 'nearest' });
  }, [cursor]);

  if (!open) return null;

  const execute = (cmd: Command | undefined) => {
    if (!cmd) return;
    onClose();
    // fecha primeiro para a navegação não disputar o foco com o modal
    setTimeout(() => cmd.run(), 0);
  };

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setCursor((c) => Math.min(c + 1, Math.max(results.length - 1, 0)));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setCursor((c) => Math.max(c - 1, 0));
    } else if (e.key === 'Enter') {
      e.preventDefault();
      execute(results[cursor]);
    } else if (e.key === 'Escape') {
      e.preventDefault();
      onClose();
    }
  };

  let lastGroup = '';

  return (
    <div
      className="fixed inset-0 z-[100] flex items-start justify-center pt-[12vh] px-4 bg-black/40"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label="Paleta de comandos"
        className="w-full max-w-xl bg-white border border-[var(--fw-border-strong)] rounded-xl shadow-2xl overflow-hidden"
        onKeyDown={onKeyDown}
      >
        <div className="flex items-center gap-3 px-4 border-b border-[var(--fw-border)]">
          <Search className="w-4 h-4 text-[var(--fw-text-muted)]" aria-hidden="true" />
          <input
            ref={inputRef}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Digite um comando, tela ou IP…"
            aria-label="Buscar comando"
            aria-controls="cmdk-list"
            aria-activedescendant={results[cursor] ? `cmdk-${results[cursor].id}` : undefined}
            className="flex-1 h-12 bg-transparent outline-none text-sm text-[var(--fw-text-body)] placeholder:text-[var(--fw-text-faint)]"
          />
          <kbd className="text-[10px] font-mono text-[var(--fw-text-subtle)] border border-[var(--fw-border)] rounded px-1.5 py-0.5">
            Esc
          </kbd>
        </div>

        <ul id="cmdk-list" ref={listRef} role="listbox" className="max-h-[50vh] overflow-y-auto py-1">
          {results.length === 0 && (
            <li className="px-4 py-6 text-center text-sm text-[var(--fw-text-muted)]">Nada encontrado.</li>
          )}
          {results.map((cmd, index) => {
            const showGroup = cmd.group !== lastGroup;
            lastGroup = cmd.group;
            const Icon = cmd.icon;
            const active = index === cursor;
            return (
              <li key={cmd.id} role="presentation">
                {showGroup && (
                  <p className="px-4 pt-2 pb-1 text-[10px] uppercase tracking-wider text-[var(--fw-text-faint)]">
                    {cmd.group}
                  </p>
                )}
                <button
                  type="button"
                  id={`cmdk-${cmd.id}`}
                  role="option"
                  aria-selected={active}
                  data-index={index}
                  onMouseMove={() => setCursor(index)}
                  onClick={() => execute(cmd)}
                  className={`w-full flex items-center gap-3 px-4 py-2 text-left text-sm ${
                    active
                      ? 'bg-[var(--fw-surface-alt)] text-[var(--fw-heading)]'
                      : 'text-[var(--fw-text-body)]'
                  }`}
                >
                  <Icon className="w-4 h-4 shrink-0 text-[var(--fw-text-muted)]" aria-hidden="true" />
                  <span className="flex-1 truncate">{cmd.label}</span>
                  {cmd.hint && (
                    <span className="text-xs text-[var(--fw-text-subtle)] truncate max-w-[10rem]">{cmd.hint}</span>
                  )}
                  {active && <CornerDownLeft className="w-3.5 h-3.5 text-[var(--fw-text-subtle)]" aria-hidden="true" />}
                </button>
              </li>
            );
          })}
        </ul>

        <div className="flex items-center gap-4 px-4 py-2 border-t border-[var(--fw-border)] bg-[var(--fw-surface-soft)] text-[11px] text-[var(--fw-text-subtle)]">
          <span>↑↓ navegar</span>
          <span>↵ executar</span>
          <span className="ml-auto">Dica: digite um IP para investigar nos syslogs</span>
        </div>
      </div>
    </div>
  );
}
