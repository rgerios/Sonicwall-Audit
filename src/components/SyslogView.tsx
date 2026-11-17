import { Fragment, useEffect, useState } from 'react';
import {
  Ban,
  Bot,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  FileUp,
  Info,
  RefreshCw,
  Search,
  Trash2,
} from 'lucide-react';
import type { FirewallVendor, SyslogEvent } from '../types.ts';
import { vendorApiUrl } from '../utils/vendorApi.ts';
import { VENDOR_THEMES } from '../utils/vendorTheme.ts';

interface SyslogViewProps {
  vendor: FirewallVendor;
  refreshToken: number;
  onDataChanged: () => void;
  onAnalyzeEvent: (rawEventText: string) => void;
  pendingQuery?: string | null;
  onConsumePendingQuery?: () => void;
}

export function SyslogView({
  vendor,
  refreshToken,
  onDataChanged,
  onAnalyzeEvent,
  pendingQuery,
  onConsumePendingQuery,
}: SyslogViewProps) {
  const theme = VENDOR_THEMES[vendor];
  const [events, setEvents] = useState<SyslogEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [matched, setMatched] = useState(0);
  const [loading, setLoading] = useState(true);

  const [query, setQuery] = useState('');
  const [actionFilter, setActionFilter] = useState('all');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const [showPasteBox, setShowPasteBox] = useState(false);
  const [pasteText, setPasteText] = useState('');
  const [ingesting, setIngesting] = useState(false);
  const [feedback, setFeedback] = useState<{ type: 'ok' | 'err'; text: string } | null>(null);

  useEffect(() => {
    setExpandedId(null);
    setFeedback(null);
  }, [vendor]);

  useEffect(() => {
    if (pendingQuery) {
      setQuery(pendingQuery);
      setActionFilter('all');
      setSeverityFilter('all');
      onConsumePendingQuery?.();
    }
  }, [pendingQuery, onConsumePendingQuery]);

  const PAGE_SIZE = 250;
  const [loadingMore, setLoadingMore] = useState(false);

  const fetchLogs = async (offset = 0) => {
    if (offset === 0) setLoading(true);
    else setLoadingMore(true);
    try {
      const params = new URLSearchParams({
        q: query,
        action: actionFilter,
        severity: severityFilter,
        limit: String(PAGE_SIZE),
        offset: String(offset),
      });
      const res = await fetch(vendorApiUrl(vendor, `/syslogs?${params.toString()}`));
      if (res.ok) {
        const data = await res.json();
        const page: SyslogEvent[] = data.events || [];
        setEvents((prev) => {
          if (offset === 0) return page;
          const known = new Set(prev.map((e) => e.id));
          return [...prev, ...page.filter((e) => !known.has(e.id))];
        });
        setTotal(data.total || 0);
        setMatched(data.matched || 0);
      }
    } finally {
      setLoading(false);
      setLoadingMore(false);
    }
  };

  useEffect(() => {
    void fetchLogs();
  }, [vendor, query, actionFilter, severityFilter, refreshToken]);

  const handleFileUpload = async (file: File | undefined) => {
    if (!file) return;
    setIngesting(true);
    setFeedback(null);
    try {
      const content = await file.text();
      const res = await fetch(vendorApiUrl(vendor, '/syslogs/ingest'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content, source: 'upload' }),
      });
      const data = await res.json();
      if (!res.ok) {
        setFeedback({ type: 'err', text: data.error || 'Falha ao importar arquivo de syslog.' });
      } else {
        setFeedback({
          type: 'ok',
          text: `${data.added.toLocaleString('pt-BR')} eventos importados de ${file.name}.`,
        });
        onDataChanged();
        await fetchLogs();
      }
    } catch {
      setFeedback({ type: 'err', text: 'Erro de rede ao enviar syslogs.' });
    } finally {
      setIngesting(false);
    }
  };

  const handlePasteSubmit = async () => {
    if (!pasteText.trim()) return;
    setIngesting(true);
    setFeedback(null);
    try {
      const res = await fetch(vendorApiUrl(vendor, '/syslogs/ingest'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content: pasteText, source: 'paste' }),
      });
      const data = await res.json();
      if (!res.ok) {
        setFeedback({ type: 'err', text: data.error || 'Falha ao processar linhas coladas.' });
      } else {
        setFeedback({
          type: 'ok',
          text: `${data.added.toLocaleString('pt-BR')} linhas de syslog analisadas.`,
        });
        setPasteText('');
        setShowPasteBox(false);
        onDataChanged();
        await fetchLogs();
      }
    } finally {
      setIngesting(false);
    }
  };

  const handleClearLogs = async () => {
    await fetch(vendorApiUrl(vendor, '/syslogs'), { method: 'DELETE' });
    onDataChanged();
    await fetchLogs();
  };

  const renderActionLabel = (action: SyslogEvent['action']) => {
    if (action === 'allow') {
      return (
        <span className="inline-flex items-center gap-1.5 text-emerald-800 font-medium">
          <CheckCircle2 className="w-3.5 h-3.5 shrink-0" /> Permitido
        </span>
      );
    }
    if (action === 'drop' || action === 'deny' || action === 'reset') {
      return (
        <span className="inline-flex items-center gap-1.5 text-red-700 font-medium">
          <Ban className="w-3.5 h-3.5 shrink-0" /> {action === 'deny' ? 'Negado' : 'Drop'}
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1.5 text-[var(--fw-text-muted)] font-medium">
        <Info className="w-3.5 h-3.5 shrink-0" /> Sistema
      </span>
    );
  };

  const pastePlaceholder =
    vendor === 'fortigate'
      ? '<189>date=2026-11-13 time=10:05:11 devname="FGT100F-MATRIZ" devid="FG100FTK21004512" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip=10.20.1.50 srcport=55120 srcintf="port1" dstip=8.8.8.8 dstport=53 dstintf="wan1" proto=17 policyid=12 policyname="LAN-to-WAN-DNS" action="accept" sentbyte=142 rcvdbyte=290 msg="Allowed"'
      : '<134>id=firewall sn=2CB8ED549A10 time="2026-11-13 10:05:11" fw=192.168.10.1 pri=6 c=1024 m=537 msg="Connection Closed" src=10.20.1.50:55120:X0 dst=8.8.8.8:53:X1 proto=udp/dns fw_action="allow"';

  return (
    <div className="space-y-4">
      <div className="bg-white border border-[var(--fw-border)] rounded-lg p-4 flex flex-wrap items-center justify-between gap-4">
        <div className="flex flex-wrap items-center gap-3 flex-1 min-w-[260px]">
          <div className="relative flex-1 min-w-[220px] max-w-md">
            <Search className="w-4 h-4 text-[var(--fw-text-subtle)] absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Filtrar IP, porta, regra, mensagem..."
              className="w-full pl-9 pr-3 py-2 text-xs border border-[var(--fw-border-strong)] rounded-md bg-[var(--fw-bg-input)] focus:outline-none focus:ring-2 focus:ring-[var(--fw-accent-mid)]"
            />
          </div>

          <div className="flex items-center gap-1 p-1 bg-[var(--fw-surface-alt)] rounded-md">
            {[
              { id: 'all', label: 'Todos' },
              { id: 'allow', label: 'Permitidos' },
              { id: 'blocked', label: 'Bloqueados' },
              { id: 'system', label: 'Sistema' },
            ].map((tab) => (
              <button
                key={tab.id}
                type="button"
                onClick={() => setActionFilter(tab.id)}
                className={`px-3 py-1.5 text-xs font-medium rounded transition-colors whitespace-nowrap ${
                  actionFilter === tab.id
                    ? 'bg-white text-[var(--fw-heading)] shadow-xs'
                    : 'text-[var(--fw-text-body)] hover:text-[var(--fw-heading)]'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>

          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            aria-label="Filtrar por severidade"
            className="px-3 py-2 text-xs border border-[var(--fw-border-strong)] rounded-md bg-white text-[var(--fw-text-body)] focus:outline-none focus:ring-2 focus:ring-[var(--fw-accent-mid)]"
          >
            <option value="all">Todas severidades</option>
            <option value="critical">Crítico</option>
            <option value="error">Erro</option>
            <option value="warning">Alerta</option>
            <option value="notice">Notice</option>
            <option value="info">Info</option>
          </select>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <label className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-[var(--fw-text-body)] bg-[var(--fw-bg)] border border-[var(--fw-border-strong)] rounded-md hover:bg-[var(--fw-surface)] cursor-pointer whitespace-nowrap">
            <FileUp className="w-3.5 h-3.5" />
            Importar .log/.txt
            <input
              type="file"
              accept=".log,.txt,.syslog"
              className="hidden"
              onChange={(e) => void handleFileUpload(e.target.files?.[0])}
            />
          </label>
          <button
            type="button"
            onClick={() => setShowPasteBox((v) => !v)}
            className="px-3 py-2 text-xs font-medium text-[var(--fw-text-body)] bg-white border border-[var(--fw-border-strong)] rounded-md hover:bg-[var(--fw-surface)] whitespace-nowrap"
          >
            Colar Logs
          </button>
          <button
            type="button"
            onClick={() => void fetchLogs()}
            className="p-2 text-[var(--fw-text-body)] bg-white border border-[var(--fw-border-strong)] rounded-md hover:bg-[var(--fw-surface)]"
            title="Atualizar"
            aria-label="Atualizar lista de syslogs"
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
          {total > 0 && (
            <button
              type="button"
              onClick={() => void handleClearLogs()}
              className="p-2 text-red-700 bg-white border border-[var(--fw-border-strong)] rounded-md hover:bg-red-50"
              title="Limpar syslogs"
              aria-label="Limpar todos os syslogs"
            >
              <Trash2 className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      </div>

      {feedback && (
        <div
          className={`px-4 py-3 rounded-md border text-xs ${
            feedback.type === 'ok'
              ? 'bg-[var(--fw-surface)] border-[var(--fw-border-strong)] text-[var(--fw-heading)]'
              : 'bg-red-50 border-red-200 text-red-800'
          }`}
        >
          {feedback.text}
        </div>
      )}

      {showPasteBox && (
        <div className="bg-white border border-[var(--fw-border)] rounded-lg p-4 space-y-3">
          <div className="flex items-center justify-between">
            <p className="text-xs font-medium text-[var(--fw-heading)]">
              Cole linhas brutas do rsyslog ou exportação {theme.label} (
              <span className="font-mono">
                {vendor === 'fortigate' ? 'date=... devname=... srcip=...' : 'id=firewall ...'}
              </span>
              )
            </p>
            <button
              type="button"
              onClick={() => setShowPasteBox(false)}
              className="text-xs text-[var(--fw-text-muted)] hover:text-[var(--fw-heading)]"
            >
              Fechar
            </button>
          </div>
          <textarea
            value={pasteText}
            onChange={(e) => setPasteText(e.target.value)}
            rows={5}
            placeholder={pastePlaceholder}
            className="w-full p-3 font-mono text-xs border border-[var(--fw-border-strong)] rounded-md bg-[var(--fw-bg-input)] focus:outline-none focus:ring-2 focus:ring-[var(--fw-accent-mid)]"
          />
          <div className="flex justify-end">
            <button
              type="button"
              disabled={ingesting || !pasteText.trim()}
              onClick={() => void handlePasteSubmit()}
              className="px-4 py-2 text-xs font-medium text-white bg-[var(--fw-accent)] rounded-md hover:bg-[var(--fw-accent-hover)] disabled:opacity-50"
            >
              {ingesting ? 'Processando...' : 'Analisar Linhas'}
            </button>
          </div>
        </div>
      )}

      <div className="bg-white border border-[var(--fw-border)] rounded-lg overflow-hidden">
        <div className="px-4 py-2.5 border-b border-[var(--fw-border)] bg-[var(--fw-surface)] flex items-center justify-between text-xs text-[var(--fw-text-body)]">
          <span className="tabular-nums">
            Exibindo {events.length.toLocaleString('pt-BR')} de{' '}
            {matched.toLocaleString('pt-BR')} correspondências ({total.toLocaleString('pt-BR')} total)
          </span>
          <span>Expurgo automático ativo · Porta UDP :{theme.defaultUdpPort} · Clique para expandir</span>
        </div>

        {loading ? (
          <div className="p-6 space-y-2 animate-pulse">
            {[1, 2, 3, 4, 5].map((n) => (
              <div key={n} className="h-9 bg-[var(--fw-surface)] rounded" />
            ))}
          </div>
        ) : events.length === 0 ? (
          <div className="p-10 text-center">
            <p className="text-sm font-medium text-[var(--fw-heading)]">
              Nenhum evento de syslog {theme.label} encontrado
            </p>
            <p className="text-xs text-[var(--fw-text-muted)] mt-1">
              Importe um arquivo de log (<span className="font-mono">/var/log/{vendor}.log</span>),
              cole linhas acima ou inicie o receptor UDP na porta{' '}
              <span className="font-mono">{theme.defaultUdpPort}</span>.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-[var(--fw-border)] text-[var(--fw-text-muted)] bg-[var(--fw-bg)]">
                  <th className="py-2.5 pl-4 pr-2 text-left font-medium w-8" />
                  <th className="py-2.5 px-3 text-left font-medium">Data / Hora</th>
                  <th className="py-2.5 px-3 text-left font-medium">Ação</th>
                  <th className="py-2.5 px-3 text-left font-medium">Origem</th>
                  <th className="py-2.5 px-3 text-left font-medium">Destino</th>
                  <th className="py-2.5 px-3 text-left font-medium">Proto / Porta</th>
                  <th className="py-2.5 px-3 text-left font-medium">Regra / NAT</th>
                  <th className="py-2.5 px-4 text-left font-medium">Mensagem</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--fw-border-soft)]">
                {events.map((ev) => {
                  const isOpen = expandedId === ev.id;
                  return (
                    <Fragment key={ev.id}>
                      <tr
                        onClick={() => setExpandedId(isOpen ? null : ev.id)}
                        className="hover:bg-[var(--fw-bg)] cursor-pointer transition-colors"
                      >
                        <td className="py-2.5 pl-4 pr-2 text-[var(--fw-text-subtle)]">
                          {isOpen ? (
                            <ChevronDown className="w-3.5 h-3.5" />
                          ) : (
                            <ChevronRight className="w-3.5 h-3.5" />
                          )}
                        </td>
                        <td className="py-2.5 px-3 font-mono text-[var(--fw-text-muted)] whitespace-nowrap tabular-nums">
                          {ev.timestamp}
                        </td>
                        <td className="py-2.5 px-3 whitespace-nowrap">{renderActionLabel(ev.action)}</td>
                        <td className="py-2.5 px-3 font-mono text-[var(--fw-heading)] whitespace-nowrap">
                          {ev.srcIp}
                          {ev.srcPort ? `:${ev.srcPort}` : ''}
                          {ev.srcZone !== '-' && (
                            <span className="text-[var(--fw-text-subtle)] ml-1">({ev.srcZone})</span>
                          )}
                        </td>
                        <td className="py-2.5 px-3 font-mono text-[var(--fw-heading)] whitespace-nowrap">
                          {ev.dstIp}
                          {ev.dstPort ? `:${ev.dstPort}` : ''}
                          {ev.dstZone !== '-' && (
                            <span className="text-[var(--fw-text-subtle)] ml-1">({ev.dstZone})</span>
                          )}
                        </td>
                        <td className="py-2.5 px-3 font-mono text-[var(--fw-text-body)] whitespace-nowrap">
                          {ev.protocol}
                          {ev.dstPort !== null ? `/${ev.dstPort}` : ''}
                        </td>
                        <td className="py-2.5 px-3 font-mono text-[var(--fw-text-muted)] whitespace-nowrap">
                          {ev.ruleRef || '-'}
                          {ev.natRuleRef ? ` · ${ev.natRuleRef}` : ''}
                        </td>
                        <td className="py-2.5 px-4 text-[var(--fw-text-body)] max-w-xs truncate">
                          {ev.message}
                        </td>
                      </tr>
                      {isOpen && (
                        <tr className="bg-[var(--fw-bg)]">
                          <td colSpan={8} className="px-6 py-4 border-t border-[var(--fw-border)]">
                            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs mb-3">
                              <div>
                                <span className="text-[var(--fw-text-muted)]">Categoria:</span>{' '}
                                <span className="text-[var(--fw-heading)] font-medium">
                                  {ev.categoryName}
                                </span>
                              </div>
                              <div>
                                <span className="text-[var(--fw-text-muted)]">Severidade:</span>{' '}
                                <span className="font-mono text-[var(--fw-heading)]">
                                  {ev.severity} (pri {ev.priority})
                                </span>
                              </div>
                              <div>
                                <span className="text-[var(--fw-text-muted)]">Bytes Env/Rec:</span>{' '}
                                <span className="font-mono tabular-nums text-[var(--fw-heading)]">
                                  {ev.bytesSent.toLocaleString('pt-BR')} /{' '}
                                  {ev.bytesRcvd.toLocaleString('pt-BR')}
                                </span>
                              </div>
                              <div>
                                <span className="text-[var(--fw-text-muted)]">NAT Traduzido:</span>{' '}
                                <span className="font-mono text-[var(--fw-heading)]">
                                  {ev.natSrcIp || ev.natDstIp || 'Nenhum'}
                                </span>
                              </div>
                            </div>
                            <pre className="p-3 bg-[var(--fw-terminal-bg)] text-[var(--fw-terminal-text)] rounded-md font-mono text-[11px] overflow-x-auto whitespace-pre-wrap">
                              {ev.raw}
                            </pre>
                            <div className="mt-3 flex justify-end">
                              <button
                                type="button"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  onAnalyzeEvent(
                                    `Explique este evento de syslog do ${theme.label} em linguagem humana, avalie se há risco e indique o que fazer:\n\n${ev.raw}`
                                  );
                                }}
                                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-white bg-[var(--fw-accent)] rounded-md hover:bg-[var(--fw-accent-hover)]"
                              >
                                <Bot className="w-3.5 h-3.5" />
                                Analisar este evento com IA
                              </button>
                            </div>
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
            {events.length < matched && (
              <div className="px-4 py-3 border-t border-[var(--fw-border)] flex justify-center">
                <button
                  type="button"
                  disabled={loadingMore}
                  onClick={() => void fetchLogs(events.length)}
                  className="px-4 py-1.5 text-xs font-medium text-[var(--fw-text-body)] bg-white border border-[var(--fw-border-strong)] rounded-md hover:bg-[var(--fw-bg)] disabled:opacity-50"
                >
                  {loadingMore
                    ? 'Carregando...'
                    : `Carregar mais ${Math.min(PAGE_SIZE, matched - events.length).toLocaleString('pt-BR')} (restam ${(matched - events.length).toLocaleString('pt-BR')})`}
                </button>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
