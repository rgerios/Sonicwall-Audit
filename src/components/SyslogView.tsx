import { Fragment, useEffect, useState } from 'react';
import {
  Ban,
  Bot,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  FileUp,
  Filter,
  Info,
  Loader2,
  RefreshCw,
  RotateCcw,
  Search,
  X,
} from 'lucide-react';
import type { FirewallVendor, SyslogEvent } from '../types.ts';
import { vendorApiUrl } from '../utils/vendorApi.ts';
import { VENDOR_THEMES } from '../utils/vendorTheme.ts';
import { IpConsumptionPanel } from './IpConsumptionPanel.tsx';

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
  const [srcIpFilter, setSrcIpFilter] = useState('');
  const [dstIpFilter, setDstIpFilter] = useState('');
  const [actionFilter, setActionFilter] = useState('all');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [deviceFilter, setDeviceFilter] = useState('all');

  const [appliedFilters, setAppliedFilters] = useState({
    q: '',
    srcIp: '',
    dstIp: '',
    action: 'all',
    severity: 'all',
    device: 'all',
  });
  const [devices, setDevices] = useState<Array<{ id: string; label: string }>>([]);
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const [showPasteBox, setShowPasteBox] = useState(false);
  const [pasteText, setPasteText] = useState('');
  const [ingesting, setIngesting] = useState(false);
  const [clearing, setClearing] = useState(false);
  const [confirmReset, setConfirmReset] = useState(false);
  const [feedback, setFeedback] = useState<{ type: 'ok' | 'err'; text: string } | null>(null);

  useEffect(() => {
    setExpandedId(null);
    setConfirmReset(false);
    setQuery('');
    setSrcIpFilter('');
    setDstIpFilter('');
    setActionFilter('all');
    setSeverityFilter('all');
    setDeviceFilter('all');
    setAppliedFilters({ q: '', srcIp: '', dstIp: '', action: 'all', severity: 'all', device: 'all' });
    setDevices([]);
    setFeedback(null);
  }, [vendor]);

  useEffect(() => {
    if (pendingQuery) {
      setQuery(pendingQuery);
      setSrcIpFilter('');
      setDstIpFilter('');
      setActionFilter('all');
      setSeverityFilter('all');
      setDeviceFilter('all');
      setAppliedFilters({
        q: pendingQuery,
        srcIp: '',
        dstIp: '',
        action: 'all',
        severity: 'all',
        device: 'all',
      });
      onConsumePendingQuery?.();
    }
  }, [pendingQuery, onConsumePendingQuery]);

  const PAGE_SIZE = 250;
  const [loadingMore, setLoadingMore] = useState(false);

  const fetchLogs = async (offset = 0, filters = appliedFilters) => {
    if (offset === 0) setLoading(true);
    else setLoadingMore(true);
    try {
      const params = new URLSearchParams({
        q: filters.q,
        srcIp: filters.srcIp,
        dstIp: filters.dstIp,
        action: filters.action,
        severity: filters.severity,
        device: filters.device,
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
        if (Array.isArray(data.devices)) {
          setDevices(data.devices);
        }
      }
    } finally {
      setLoading(false);
      setLoadingMore(false);
    }
  };

  useEffect(() => {
    void fetchLogs(0, appliedFilters);
  }, [vendor, appliedFilters, refreshToken]);

  const handleApplyFilters = (e?: React.FormEvent) => {
    e?.preventDefault();
    setAppliedFilters({
      q: query.trim(),
      srcIp: srcIpFilter.trim(),
      dstIp: dstIpFilter.trim(),
      action: actionFilter,
      severity: severityFilter,
      device: deviceFilter,
    });
  };

  const handleClearFilters = () => {
    setQuery('');
    setSrcIpFilter('');
    setDstIpFilter('');
    setActionFilter('all');
    setSeverityFilter('all');
    setDeviceFilter('all');
    setAppliedFilters({ q: '', srcIp: '', dstIp: '', action: 'all', severity: 'all', device: 'all' });
  };

  const hasPendingFilterChanges =
    query.trim() !== appliedFilters.q ||
    srcIpFilter.trim() !== appliedFilters.srcIp ||
    dstIpFilter.trim() !== appliedFilters.dstIp ||
    actionFilter !== appliedFilters.action ||
    severityFilter !== appliedFilters.severity ||
    deviceFilter !== appliedFilters.device;

  const activeFilterChips: string[] = [];
  if (appliedFilters.q) activeFilterChips.push(`Busca: "${appliedFilters.q}"`);
  if (appliedFilters.srcIp) activeFilterChips.push(`Origem: ${appliedFilters.srcIp}`);
  if (appliedFilters.dstIp) activeFilterChips.push(`Destino: ${appliedFilters.dstIp}`);
  if (appliedFilters.action !== 'all') {
    const actionLabel =
      appliedFilters.action === 'allow'
        ? 'Permitidos'
        : appliedFilters.action === 'blocked'
          ? 'Bloqueados'
          : 'Sistema';
    activeFilterChips.push(`Ação: ${actionLabel}`);
  }
  if (appliedFilters.severity !== 'all') activeFilterChips.push(`Severidade: ${appliedFilters.severity}`);
  if (appliedFilters.device !== 'all') activeFilterChips.push(`Device: ${appliedFilters.device}`);

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
    setClearing(true);
    setFeedback(null);
    try {
      const res = await fetch(vendorApiUrl(vendor, '/syslogs'), { method: 'DELETE' });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        setFeedback({
          type: 'err',
          text: (data as { error?: string }).error || 'Falha ao resetar syslogs.',
        });
        return;
      }
      setConfirmReset(false);
      setExpandedId(null);
      setEvents([]);
      setTotal(0);
      setMatched(0);
      setFeedback({
        type: 'ok',
        text: 'Todos os syslogs recebidos foram limpos e os contadores de uso foram zerados.',
      });
      onDataChanged();
      await fetchLogs(0);
    } catch {
      setFeedback({ type: 'err', text: 'Erro de rede ao resetar syslogs.' });
    } finally {
      setClearing(false);
    }
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
      <IpConsumptionPanel
        vendor={vendor}
        refreshToken={refreshToken}
        onFilterSyslogsByIp={(ip) => {
          setQuery(ip);
          setSrcIpFilter('');
          setDstIpFilter('');
          setActionFilter('all');
          setSeverityFilter('all');
          setDeviceFilter('all');
          setAppliedFilters({
            q: ip,
            srcIp: '',
            dstIp: '',
            action: 'all',
            severity: 'all',
            device: 'all',
          });
        }}
      />

      <form
        onSubmit={handleApplyFilters}
        className="bg-white border border-[var(--fw-border)] rounded-lg p-4 space-y-3"
      >
        <div className="flex flex-wrap items-center gap-2.5">
          <div className="relative flex-1 min-w-[200px]">
            <Search className="w-4 h-4 text-[var(--fw-text-subtle)] absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Busca geral (porta, regra, mensagem...)"
              className="w-full pl-9 pr-3 py-2 text-xs border border-[var(--fw-border-strong)] rounded-md bg-[var(--fw-bg-input)] focus:outline-none focus:ring-2 focus:ring-[var(--fw-accent-mid)]"
            />
          </div>

          <input
            type="text"
            value={srcIpFilter}
            onChange={(e) => setSrcIpFilter(e.target.value)}
            placeholder="IP Origem (ex: 10.20.4.45)"
            aria-label="Filtrar por IP de origem"
            className="w-44 px-3 py-2 text-xs font-mono border border-[var(--fw-border-strong)] rounded-md bg-[var(--fw-bg-input)] focus:outline-none focus:ring-2 focus:ring-[var(--fw-accent-mid)]"
          />

          <input
            type="text"
            value={dstIpFilter}
            onChange={(e) => setDstIpFilter(e.target.value)}
            placeholder="IP Destino (ex: 8.8.8.8)"
            aria-label="Filtrar por IP de destino"
            className="w-44 px-3 py-2 text-xs font-mono border border-[var(--fw-border-strong)] rounded-md bg-[var(--fw-bg-input)] focus:outline-none focus:ring-2 focus:ring-[var(--fw-accent-mid)]"
          />

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
                className={`px-3 py-1.5 text-xs font-medium rounded transition-colors whitespace-nowrap cursor-pointer ${
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

          <select
            value={deviceFilter}
            onChange={(e) => setDeviceFilter(e.target.value)}
            aria-label="Filtrar por device"
            className="px-3 py-2 text-xs font-mono border border-[var(--fw-border-strong)] rounded-md bg-white text-[var(--fw-text-body)] focus:outline-none focus:ring-2 focus:ring-[var(--fw-accent-mid)] max-w-[210px]"
          >
            <option value="all">Todos os devices</option>
            {devices.map((dev) => (
              <option key={dev.id} value={dev.id}>
                {dev.label}
              </option>
            ))}
          </select>

          <button
            type="submit"
            disabled={loading}
            className={`inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-semibold text-white rounded-md transition-colors cursor-pointer disabled:opacity-50 whitespace-nowrap ${
              hasPendingFilterChanges
                ? 'bg-[var(--fw-accent)] hover:bg-[var(--fw-accent-hover)] ring-2 ring-[var(--fw-accent-mid)]/40'
                : 'bg-[var(--fw-accent)] hover:bg-[var(--fw-accent-hover)]'
            }`}
          >
            <Filter className="w-3.5 h-3.5" />
            Aplicar Filtro
          </button>

          {(activeFilterChips.length > 0 || hasPendingFilterChanges) && (
            <button
              type="button"
              onClick={handleClearFilters}
              className="inline-flex items-center gap-1 px-2.5 py-2 text-xs font-medium text-[var(--fw-text-body)] bg-[var(--fw-bg)] border border-[var(--fw-border-strong)] rounded-md hover:bg-[var(--fw-surface)] cursor-pointer whitespace-nowrap"
            >
              <X className="w-3.5 h-3.5" />
              Limpar
            </button>
          )}
        </div>

        <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-[var(--fw-border-soft)]">
          <div className="flex flex-wrap items-center gap-1.5 text-[11px]">
            <span className="text-[var(--fw-text-muted)] font-medium">Filtrando por:</span>
            {activeFilterChips.length === 0 ? (
              <span className="px-2 py-0.5 rounded bg-[var(--fw-surface)] text-[var(--fw-text-body)]">
                Sem filtro (exibindo logs mais recentes)
              </span>
            ) : (
              activeFilterChips.map((chip) => (
                <span
                  key={chip}
                  className="px-2 py-0.5 rounded bg-[var(--fw-surface-chip)] text-[var(--fw-heading)] font-mono font-medium"
                >
                  {chip}
                </span>
              ))
            )}
            {hasPendingFilterChanges && (
              <span className="text-amber-800 font-medium ml-1">
                (alterações pendentes — clique em Aplicar Filtro)
              </span>
            )}
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
          {!confirmReset && (
            <button
              type="button"
              onClick={() => setConfirmReset(true)}
              disabled={clearing || total === 0}
              className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-red-700 bg-white border border-red-200 rounded-md hover:bg-red-50 cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed whitespace-nowrap"
              title={
                total === 0
                  ? 'Nenhum syslog armazenado para limpar'
                  : 'Limpar todos os syslogs recebidos e começar do zero'
              }
              aria-label="Resetar todos os syslogs"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              Resetar Syslogs
            </button>
          )}
          {confirmReset && (
            <div className="inline-flex items-center gap-1.5 bg-red-50 border border-red-200 rounded-md px-2.5 py-1">
              <span className="text-[11px] font-medium text-red-800">
                Apagar {total.toLocaleString('pt-BR')} log(s)?
              </span>
              <button
                type="button"
                onClick={() => void handleClearLogs()}
                disabled={clearing}
                className="px-2.5 py-1 text-[11px] font-semibold text-white bg-red-600 rounded hover:bg-red-700 cursor-pointer disabled:opacity-50"
              >
                {clearing ? 'Resetando...' : 'Confirmar'}
              </button>
              <button
                type="button"
                onClick={() => setConfirmReset(false)}
                disabled={clearing}
                className="px-2 py-1 text-[11px] font-medium text-[var(--fw-text-body)] bg-white border border-[var(--fw-border-strong)] rounded hover:bg-[var(--fw-bg)] cursor-pointer disabled:opacity-50"
              >
                Cancelar
              </button>
            </div>
          )}
        </div>
        </div>
      </form>

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
          <div className="p-8 space-y-4">
            <div className="flex items-center justify-center gap-3 text-sm font-medium text-[var(--fw-heading)]">
              <Loader2 className="w-5 h-5 animate-spin text-[var(--fw-accent)]" />
              <span>
                Carregando syslogs {theme.label}
                {activeFilterChips.length > 0 ? ' com os filtros aplicados...' : '...'}
              </span>
            </div>
            <p className="text-center text-xs text-[var(--fw-text-muted)]">
              Consultando registros armazenados ({total.toLocaleString('pt-BR')} eventos no total). Aguarde...
            </p>
            <div className="space-y-2 animate-pulse max-w-4xl mx-auto">
              {[1, 2, 3, 4, 5].map((n) => (
                <div key={n} className="h-9 bg-[var(--fw-surface)] rounded" />
              ))}
            </div>
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
                  <th className="py-2.5 px-3 text-left font-medium">Device</th>
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
                        <td className="py-2.5 px-3 font-mono text-[var(--fw-heading)] whitespace-nowrap">
                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              const id =
                                (ev.firewallHost && ev.firewallHost !== '-' ? ev.firewallHost : '') ||
                                (ev.serialNumber && ev.serialNumber !== '-' ? ev.serialNumber : '');
                              if (id) {
                                const nextDevice = appliedFilters.device === id ? 'all' : id;
                                setDeviceFilter(nextDevice);
                                setAppliedFilters((prev) => ({ ...prev, device: nextDevice }));
                              }
                            }}
                            title="Clique para filtrar apenas este device"
                            className="text-left hover:underline cursor-pointer"
                          >
                            {ev.firewallHost && ev.firewallHost !== '-'
                              ? ev.firewallHost
                              : ev.serialNumber || '-'}
                          </button>
                          {ev.serialNumber &&
                            ev.serialNumber !== '-' &&
                            ev.firewallHost !== ev.serialNumber && (
                              <span className="block text-[10px] text-[var(--fw-text-subtle)]">
                                {ev.serialNumber}
                              </span>
                            )}
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
                          <td colSpan={9} className="px-6 py-4 border-t border-[var(--fw-border)]">
                            <div className="grid grid-cols-2 md:grid-cols-5 gap-3 text-xs mb-3">
                              <div>
                                <span className="text-[var(--fw-text-muted)]">Device:</span>{' '}
                                <span className="font-mono text-[var(--fw-heading)] font-medium">
                                  {ev.firewallHost || '-'}
                                  {ev.serialNumber && ev.serialNumber !== '-'
                                    ? ` (${ev.serialNumber})`
                                    : ''}
                                </span>
                              </div>
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
