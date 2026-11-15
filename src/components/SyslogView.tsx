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
import type { SyslogEvent } from '../types.ts';

interface SyslogViewProps {
  refreshToken: number;
  onDataChanged: () => void;
  onAnalyzeEvent: (rawEventText: string) => void;
  pendingQuery?: string | null;
  onConsumePendingQuery?: () => void;
}

export function SyslogView({
  refreshToken,
  onDataChanged,
  onAnalyzeEvent,
  pendingQuery,
  onConsumePendingQuery,
}: SyslogViewProps) {
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
    if (pendingQuery) {
      setQuery(pendingQuery);
      setActionFilter('all');
      setSeverityFilter('all');
      onConsumePendingQuery?.();
    }
  }, [pendingQuery, onConsumePendingQuery]);

  const fetchLogs = async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams({
        q: query,
        action: actionFilter,
        severity: severityFilter,
        limit: '250',
      });
      const res = await fetch(`/api/syslogs?${params.toString()}`);
      if (res.ok) {
        const data = await res.json();
        setEvents(data.events || []);
        setTotal(data.total || 0);
        setMatched(data.matched || 0);
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void fetchLogs();
  }, [query, actionFilter, severityFilter, refreshToken]);

  const handleFileUpload = async (file: File | undefined) => {
    if (!file) return;
    setIngesting(true);
    setFeedback(null);
    try {
      const content = await file.text();
      const res = await fetch('/api/syslogs/ingest', {
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
      const res = await fetch('/api/syslogs/ingest', {
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
    await fetch('/api/syslogs', { method: 'DELETE' });
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
      <span className="inline-flex items-center gap-1.5 text-[#456354] font-medium">
        <Info className="w-3.5 h-3.5 shrink-0" /> Sistema
      </span>
    );
  };

  return (
    <div className="space-y-4">
      <div className="bg-white border border-[#D4E4D8] rounded-lg p-4 flex flex-wrap items-center justify-between gap-4">
        <div className="flex flex-wrap items-center gap-3 flex-1 min-w-[260px]">
          <div className="relative flex-1 min-w-[220px] max-w-md">
            <Search className="w-4 h-4 text-[#6D8B7B] absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Filtrar IP, porta, regra, mensagem..."
              className="w-full pl-9 pr-3 py-2 text-xs border border-[#BFD5C5] rounded-md focus:outline-none focus:ring-2 focus:ring-[#2A6B52]"
            />
          </div>

          <div className="flex items-center gap-1 p-1 bg-[#E5EFE8] rounded-md">
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
                    ? 'bg-white text-[#123325] shadow-xs'
                    : 'text-[#456354] hover:text-[#123325]'
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
            className="px-3 py-2 text-xs border border-[#BFD5C5] rounded-md bg-white text-[#1D3B2E] focus:outline-none focus:ring-2 focus:ring-[#2A6B52]"
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
          <label className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-[#1D3B2E] bg-[#F4F8F5] border border-[#BFD5C5] rounded-md hover:bg-[#E7F2EA] cursor-pointer whitespace-nowrap">
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
            className="px-3 py-2 text-xs font-medium text-[#1D3B2E] bg-white border border-[#BFD5C5] rounded-md hover:bg-[#EDF5EF] whitespace-nowrap"
          >
            Colar Logs
          </button>
          <button
            type="button"
            onClick={() => void fetchLogs()}
            className="p-2 text-[#2C4B3D] bg-white border border-[#BFD5C5] rounded-md hover:bg-[#EDF5EF]"
            title="Atualizar"
            aria-label="Atualizar lista de syslogs"
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
          {total > 0 && (
            <button
              type="button"
              onClick={() => void handleClearLogs()}
              className="p-2 text-red-700 bg-white border border-[#BFD5C5] rounded-md hover:bg-red-50"
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
              ? 'bg-[#E7F2EA] border-[#B6D4BE] text-[#143D2C]'
              : 'bg-red-50 border-red-200 text-red-800'
          }`}
        >
          {feedback.text}
        </div>
      )}

      {showPasteBox && (
        <div className="bg-white border border-[#D4E4D8] rounded-lg p-4 space-y-3">
          <div className="flex items-center justify-between">
            <p className="text-xs font-medium text-[#123325]">
              Cole linhas brutas do rsyslog ou exportação SonicWall (<span className="font-mono">id=firewall ...</span>)
            </p>
            <button
              type="button"
              onClick={() => setShowPasteBox(false)}
              className="text-xs text-[#4B6B5C] hover:text-[#123325]"
            >
              Fechar
            </button>
          </div>
          <textarea
            value={pasteText}
            onChange={(e) => setPasteText(e.target.value)}
            rows={5}
            placeholder='<134>id=firewall sn=2CB8ED549A10 time="2026-11-13 10:05:11" fw=192.168.10.1 pri=6 c=1024 m=537 msg="Connection Closed" src=10.20.1.50:55120:X0 dst=8.8.8.8:53:X1 proto=udp/dns fw_action="allow"'
            className="w-full p-3 font-mono text-xs border border-[#BFD5C5] rounded-md focus:outline-none focus:ring-2 focus:ring-[#2A6B52]"
          />
          <div className="flex justify-end">
            <button
              type="button"
              disabled={ingesting || !pasteText.trim()}
              onClick={() => void handlePasteSubmit()}
              className="px-4 py-2 text-xs font-medium text-white bg-[#1E4D3B] rounded-md hover:bg-[#163A2C] disabled:opacity-50"
            >
              {ingesting ? 'Processando...' : 'Analisar Linhas'}
            </button>
          </div>
        </div>
      )}

      <div className="bg-white border border-[#D4E4D8] rounded-lg overflow-hidden">
        <div className="px-4 py-2.5 border-b border-[#D4E4D8] bg-[#EDF5EF] flex items-center justify-between text-xs text-[#2C4B3D]">
          <span className="tabular-nums">
            Exibindo {events.length.toLocaleString('pt-BR')} de{' '}
            {matched.toLocaleString('pt-BR')} correspondências ({total.toLocaleString('pt-BR')} total)
          </span>
          <span>Expurgo automático ativo (10 dias) · Clique na linha para ver detalhes</span>
        </div>

        {loading ? (
          <div className="p-6 space-y-2 animate-pulse">
            {[1, 2, 3, 4, 5].map((n) => (
              <div key={n} className="h-9 bg-[#EDF5EF] rounded" />
            ))}
          </div>
        ) : events.length === 0 ? (
          <div className="p-10 text-center">
            <p className="text-sm font-medium text-[#123325]">Nenhum evento de syslog encontrado</p>
            <p className="text-xs text-[#4B6B5C] mt-1">
              Importe um arquivo de log do Linux (<span className="font-mono">/var/log/sonicwall.log</span>),
              cole linhas acima ou ative o receptor UDP.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-[#D4E4D8] text-[#456354] bg-[#F4F8F5]">
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
              <tbody className="divide-y divide-[#E6F0E8]">
                {events.map((ev) => {
                  const isOpen = expandedId === ev.id;
                  return (
                    <Fragment key={ev.id}>
                      <tr
                        onClick={() => setExpandedId(isOpen ? null : ev.id)}
                        className="hover:bg-[#F6FAF7] cursor-pointer transition-colors"
                      >
                        <td className="py-2.5 pl-4 pr-2 text-[#6D8B7B]">
                          {isOpen ? (
                            <ChevronDown className="w-3.5 h-3.5" />
                          ) : (
                            <ChevronRight className="w-3.5 h-3.5" />
                          )}
                        </td>
                        <td className="py-2.5 px-3 font-mono text-[#456354] whitespace-nowrap tabular-nums">
                          {ev.timestamp}
                        </td>
                        <td className="py-2.5 px-3 whitespace-nowrap">{renderActionLabel(ev.action)}</td>
                        <td className="py-2.5 px-3 font-mono text-[#123325] whitespace-nowrap">
                          {ev.srcIp}
                          {ev.srcPort ? `:${ev.srcPort}` : ''}
                          {ev.srcZone !== '-' && (
                            <span className="text-[#6D8B7B] ml-1">({ev.srcZone})</span>
                          )}
                        </td>
                        <td className="py-2.5 px-3 font-mono text-[#123325] whitespace-nowrap">
                          {ev.dstIp}
                          {ev.dstPort ? `:${ev.dstPort}` : ''}
                          {ev.dstZone !== '-' && (
                            <span className="text-[#6D8B7B] ml-1">({ev.dstZone})</span>
                          )}
                        </td>
                        <td className="py-2.5 px-3 font-mono text-[#2C4B3D] whitespace-nowrap">
                          {ev.protocol}
                          {ev.dstPort !== null ? `/${ev.dstPort}` : ''}
                        </td>
                        <td className="py-2.5 px-3 font-mono text-[#456354] whitespace-nowrap">
                          {ev.ruleRef || '-'}
                          {ev.natRuleRef ? ` · ${ev.natRuleRef}` : ''}
                        </td>
                        <td className="py-2.5 px-4 text-[#2C4B3D] max-w-xs truncate">
                          {ev.message}
                        </td>
                      </tr>
                      {isOpen && (
                        <tr className="bg-[#F4F8F5]">
                          <td colSpan={8} className="px-6 py-4 border-t border-[#D4E4D8]">
                            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs mb-3">
                              <div>
                                <span className="text-[#4B6B5C]">Categoria:</span>{' '}
                                <span className="text-[#123325] font-medium">{ev.categoryName}</span>
                              </div>
                              <div>
                                <span className="text-[#4B6B5C]">Severidade:</span>{' '}
                                <span className="font-mono text-[#123325]">
                                  {ev.severity} (pri {ev.priority})
                                </span>
                              </div>
                              <div>
                                <span className="text-[#4B6B5C]">Bytes Env/Rec:</span>{' '}
                                <span className="font-mono tabular-nums text-[#123325]">
                                  {ev.bytesSent.toLocaleString('pt-BR')} / {ev.bytesRcvd.toLocaleString('pt-BR')}
                                </span>
                              </div>
                              <div>
                                <span className="text-[#4B6B5C]">NAT Traduzido:</span>{' '}
                                <span className="font-mono text-[#123325]">
                                  {ev.natSrcIp || ev.natDstIp || 'Nenhum'}
                                </span>
                              </div>
                            </div>
                            <pre className="p-3 bg-[#0E221A] text-[#E6F2EB] rounded-md font-mono text-[11px] overflow-x-auto whitespace-pre-wrap">
                              {ev.raw}
                            </pre>
                            <div className="mt-3 flex justify-end">
                              <button
                                type="button"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  onAnalyzeEvent(
                                    `Explique este evento de syslog do SonicWall em linguagem humana, avalie se há risco e indique o que fazer:\n\n${ev.raw}`
                                  );
                                }}
                                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-white bg-[#1E4D3B] rounded-md hover:bg-[#163A2C]"
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
          </div>
        )}
      </div>
    </div>
  );
}
