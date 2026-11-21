import { useEffect, useMemo, useState } from 'react';
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { AlertTriangle, CalendarClock, Download, ExternalLink, FileDown, Loader2, Printer, Trash2 } from 'lucide-react';
import type { AccessReportData, FirewallVendor, ReportScheduleState } from '../types.ts';
import { formatBytes } from '../../shared/destinations.ts';
import { downloadCsv } from '../utils/csv.ts';
import { exportAccessReportPdf, periodLabel } from '../utils/exportAccessPdf.ts';
import { vendorApiUrl } from '../utils/vendorApi.ts';
import { countryName, flagEmoji } from '../utils/worldGeo.ts';

interface AccessReportViewProps {
  vendor: FirewallVendor;
  refreshToken: number;
}

const RANGES: Array<{ label: string; minutes: number }> = [
  { label: '1 h', minutes: 60 },
  { label: '6 h', minutes: 360 },
  { label: '24 h', minutes: 1440 },
  { label: '7 dias', minutes: 10080 },
  { label: '30 dias', minutes: 43200 },
];

const n = (v: number) => v.toLocaleString('pt-BR');
const pct = (part: number, whole: number) => (whole > 0 ? (part / whole) * 100 : 0);
const btn =
  'inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-[var(--fw-text-body)] bg-white border border-[var(--fw-border-strong)] rounded-md hover:bg-[var(--fw-surface)] whitespace-nowrap disabled:opacity-50';
const seg = (active: boolean) =>
  `px-3 py-1.5 text-xs font-semibold rounded-md transition-colors ${
    active ? 'bg-white text-[var(--fw-heading)] shadow-xs' : 'text-[var(--fw-text-muted)] hover:text-[var(--fw-heading)]'
  }`;

function Bar({ value, color = '#38bdf8' }: { value: number; color?: string }) {
  return (
    <div className="h-1.5 rounded-full bg-[var(--fw-surface-alt)] overflow-hidden">
      <div className="h-full rounded-full" style={{ width: `${Math.max(2, Math.min(100, value))}%`, background: color }} />
    </div>
  );
}


const FREQUENCIES = [
  { hours: 24, label: 'A cada 24 horas' },
  { hours: 72, label: 'A cada 3 dias' },
  { hours: 168, label: 'A cada 7 dias' },
];

const whenBr = (iso: string | null) => (iso ? new Date(iso).toLocaleString('pt-BR', { dateStyle: 'short', timeStyle: 'short' }) : '—');

/** Agendamento: o servidor gera o relatório em HTML estático no horário e deixa pronto para baixar. */
function SchedulePanel({ vendor }: { vendor: FirewallVendor }) {
  const [state, setState] = useState<ReportScheduleState | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = async () => {
    try {
      const res = await fetch(vendorApiUrl(vendor, '/reports/schedule'));
      if (res.ok) setState((await res.json()) as ReportScheduleState);
    } catch {
      /* mantém o estado anterior */
    }
  };
  useEffect(() => {
    void load();
    // enquanto gera, acompanha a lista
    const id = window.setInterval(() => void load(), 4000);
    return () => window.clearInterval(id);
  }, [vendor]);

  const save = async (patch: Record<string, unknown>) => {
    setMsg(null);
    try {
      const res = await fetch(vendorApiUrl(vendor, '/reports/schedule'), {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(patch),
      });
      const data = (await res.json().catch(() => ({}))) as ReportScheduleState & { error?: string };
      if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
      setState(data);
      setMsg('Agendamento salvo.');
    } catch (err) {
      setMsg(err instanceof Error ? err.message : 'Falha ao salvar.');
    }
  };

  const runNow = async () => {
    setBusy(true);
    setMsg(null);
    try {
      const res = await fetch(vendorApiUrl(vendor, '/reports/schedule/run'), { method: 'POST' });
      const data = (await res.json().catch(() => ({}))) as { error?: string };
      if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
      setMsg('Gerando o relatório… ele aparece na lista abaixo quando ficar pronto.');
      void load();
    } catch (err) {
      setMsg(err instanceof Error ? err.message : 'Falha ao iniciar.');
    } finally {
      setBusy(false);
    }
  };

  const remove = async (id: string) => {
    if (!window.confirm('Apagar este relatório? Não dá para desfazer.')) return;
    await fetch(vendorApiUrl(vendor, `/reports/files/${id}`), { method: 'DELETE' });
    void load();
  };

  const cfg = state?.config;
  return (
    <section className="no-print bg-white border border-[var(--fw-border)] rounded-lg p-4 space-y-3" aria-label="Agendamento de relatórios">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h3 className="text-sm font-semibold text-[var(--fw-heading)] inline-flex items-center gap-2">
          <CalendarClock className="w-4 h-4" aria-hidden="true" /> Relatório agendado (HTML estático, pronto para baixar)
        </h3>
        <label className="inline-flex items-center gap-2 text-xs font-medium text-[var(--fw-heading)]">
          <input type="checkbox" checked={cfg?.enabled ?? false} onChange={(e) => void save({ enabled: e.target.checked })} className="w-4 h-4 accent-[var(--fw-accent)]" />
          Gerar automaticamente
        </label>
      </div>

      <div className="flex flex-wrap items-end gap-3 text-xs">
        <label className="flex flex-col gap-1 text-[var(--fw-text-muted)]">
          Frequência (e período analisado)
          <select value={cfg?.everyHours ?? 24} onChange={(e) => void save({ everyHours: Number(e.target.value) })} className="px-2 py-1.5 border border-[var(--fw-border-strong)] rounded-md bg-[var(--fw-bg-input)] text-[var(--fw-text-body)]">
            {FREQUENCIES.map((f) => (
              <option key={f.hours} value={f.hours}>
                {f.label}
              </option>
            ))}
          </select>
        </label>
        <label className="flex flex-col gap-1 text-[var(--fw-text-muted)]">
          Horário (servidor)
          <input type="time" value={cfg?.timeOfDay ?? '06:00'} onChange={(e) => e.target.value && void save({ timeOfDay: e.target.value })} className="px-2 py-1.5 border border-[var(--fw-border-strong)] rounded-md bg-[var(--fw-bg-input)] text-[var(--fw-text-body)]" />
        </label>
        <label className="flex flex-col gap-1 text-[var(--fw-text-muted)]">
          Guardar os últimos
          <input type="number" min={1} max={200} value={cfg?.keep ?? 30} onChange={(e) => e.target.value && void save({ keep: Number(e.target.value) })} className="w-20 px-2 py-1.5 border border-[var(--fw-border-strong)] rounded-md bg-[var(--fw-bg-input)] text-[var(--fw-text-body)]" />
        </label>
        <button type="button" onClick={() => void runNow()} disabled={busy || state?.running} className={btn}>
          {state?.running ? <Loader2 className="w-3.5 h-3.5 animate-spin" aria-hidden="true" /> : <CalendarClock className="w-3.5 h-3.5" aria-hidden="true" />}
          {state?.running ? 'Gerando…' : 'Gerar agora'}
        </button>
        <p className="text-[var(--fw-text-muted)] tabular-nums pb-1.5">
          {cfg?.enabled ? `Próxima geração: ${whenBr(cfg.nextRunAt)}` : 'Agendamento desligado'}
          {cfg?.lastRunAt ? ` · última: ${whenBr(cfg.lastRunAt)}` : ''}
        </p>
      </div>
      {cfg?.lastError && (
        <p className="text-xs text-red-700" role="alert">
          Última tentativa falhou: {cfg.lastError}
        </p>
      )}
      {msg && (
        <p className="text-xs text-[var(--fw-text-muted)]" role="status">
          {msg}
        </p>
      )}

      {state && state.files.length > 0 ? (
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="text-left text-[var(--fw-text-muted)]">
                <th className="py-1.5 pr-3 font-medium">Gerado em</th>
                <th className="py-1.5 pr-3 font-medium">Período</th>
                <th className="py-1.5 pr-3 font-medium text-right">Conexões</th>
                <th className="py-1.5 pr-3 font-medium text-right">Volume</th>
                <th className="py-1.5 pr-3 font-medium">Origem</th>
                <th className="py-1.5 pr-3 font-medium text-right">Tamanho</th>
                <th className="py-1.5 font-medium text-right">Ações</th>
              </tr>
            </thead>
            <tbody>
              {state.files.map((f) => (
                <tr key={f.id} className="border-t border-[var(--fw-border)]">
                  <td className="py-1.5 pr-3 tabular-nums">{whenBr(f.createdAt)}</td>
                  <td className="py-1.5 pr-3 tabular-nums text-[var(--fw-text-muted)]">
                    {whenBr(f.periodStart)} → {whenBr(f.periodEnd)}
                  </td>
                  <td className="py-1.5 pr-3 text-right tabular-nums">{n(f.connections)}</td>
                  <td className="py-1.5 pr-3 text-right tabular-nums">{formatBytes(f.totalBytes)}</td>
                  <td className="py-1.5 pr-3 text-[var(--fw-text-muted)]">{f.trigger === 'scheduled' ? 'agendado' : 'manual'}</td>
                  <td className="py-1.5 pr-3 text-right tabular-nums">{formatBytes(f.sizeBytes)}</td>
                  <td className="py-1.5 text-right whitespace-nowrap">
                    <a href={vendorApiUrl(vendor, `/reports/files/${f.id}`)} className="inline-flex items-center gap-1 px-2 py-1 font-medium text-[var(--fw-accent)] hover:underline">
                      <Download className="w-3.5 h-3.5" aria-hidden="true" /> Baixar
                    </a>
                    <a href={vendorApiUrl(vendor, `/reports/files/${f.id}?view=1`)} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 px-2 py-1 font-medium text-[var(--fw-text-body)] hover:underline">
                      <ExternalLink className="w-3.5 h-3.5" aria-hidden="true" /> Abrir
                    </a>
                    <button type="button" onClick={() => void remove(f.id)} aria-label="Apagar relatório" className="inline-flex items-center px-2 py-1 text-[var(--fw-text-muted)] hover:text-red-700">
                      <Trash2 className="w-3.5 h-3.5" aria-hidden="true" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="text-xs text-[var(--fw-text-muted)]">Nenhum relatório gerado ainda. Ative o agendamento ou clique em “Gerar agora”.</p>
      )}
    </section>
  );
}

export function AccessReportView({ vendor, refreshToken }: AccessReportViewProps) {
  const [minutes, setMinutes] = useState(1440);
  const [report, setReport] = useState<AccessReportData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const ctrl = new AbortController();
    setLoading(true);
    setError(null);
    void (async () => {
      try {
        const res = await fetch(vendorApiUrl(vendor, `/access-report?minutes=${minutes}`), { signal: ctrl.signal });
        if (!res.ok) {
          const data = (await res.json().catch(() => ({}))) as { error?: string };
          throw new Error(data.error || `HTTP ${res.status}`);
        }
        setReport((await res.json()) as AccessReportData);
      } catch (err) {
        if ((err as Error).name !== 'AbortError') setError(err instanceof Error ? err.message : 'Falha ao gerar o relatório.');
      } finally {
        if (!ctrl.signal.aborted) setLoading(false);
      }
    })();
    return () => ctrl.abort();
  }, [vendor, minutes, refreshToken]);

  const chart = useMemo(
    () =>
      (report?.timeline ?? []).map((p) => ({
        hora: new Date(p.t).toLocaleString('pt-BR', { day: '2-digit', month: '2-digit', hour: '2-digit' }),
        Download: +((p.downloadBytes * 8) / 3600 / 1e6).toFixed(3),
        Upload: +((p.uploadBytes * 8) / 3600 / 1e6).toFixed(3),
      })),
    [report]
  );

  const t = report?.totals;
  const maxSrc = report?.sources[0]?.totalBytes ?? 0;
  const maxCat = report?.categories[0]?.connections ?? 0;
  const maxCountry = report?.countries[0]?.connections ?? 0;
  const maxSvc = report?.services[0]?.connections ?? 0;

  const exportSources = () =>
    report &&
    downloadCsv(
      `fwaudit-consumo-por-ip-${new Date().toISOString().slice(0, 10)}.csv`,
      ['IP', 'Download (bytes)', 'Upload (bytes)', 'Total (bytes)', '% do total', 'Conexoes', 'Bloqueadas', 'Destinos distintos', 'Categoria principal', 'Pais mais acessado'],
      report.sources.map((s) => [s.ip, s.downloadBytes, s.uploadBytes, s.totalBytes, pct(s.totalBytes, report.totals.totalBytes).toFixed(2), s.connections, s.blocked, s.destinations, s.topCategory ?? '', s.topCountry ? countryName(s.topCountry) : ''])
    );
  const exportDestinations = () =>
    report &&
    downloadCsv(
      `fwaudit-destinos-${new Date().toISOString().slice(0, 10)}.csv`,
      ['Destino', 'IP', 'Categoria', 'Pais', 'Organizacao (ASN)', 'Conexoes', 'Bloqueadas', 'Volume (bytes)', 'Reputacao'],
      report.destinations.map((d) => [d.host ?? '', d.ip, d.category, d.country ? countryName(d.country) : '', d.asnOrg ?? '', d.connections, d.blocked, d.totalBytes, d.threats.join(' | ')])
    );

  return (
    <div className="space-y-4">
      <SchedulePanel vendor={vendor} />
      <div className="no-print bg-white border border-[var(--fw-border)] rounded-lg p-4 flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="text-sm font-semibold text-[var(--fw-heading)]">Relatório de Acessos e Consumo</h2>
          <p className="text-xs text-[var(--fw-text-muted)] mt-0.5">
            Quem acessa o quê, para onde e quanta banda consome, a partir dos syslogs retidos no banco.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <div className="flex items-center gap-1 p-1 bg-[var(--fw-surface-alt)] rounded-md" role="group" aria-label="Período do relatório">
            {RANGES.map((r) => (
              <button key={r.minutes} type="button" onClick={() => setMinutes(r.minutes)} aria-pressed={minutes === r.minutes} className={seg(minutes === r.minutes)}>
                {r.label}
              </button>
            ))}
          </div>
          <button type="button" disabled={!report} onClick={() => report && exportAccessReportPdf(report, 'Localidade ativa')} className={btn}>
            <FileDown className="w-3.5 h-3.5" /> Exportar PDF
          </button>
          <button type="button" disabled={!report} onClick={exportSources} className={btn}>
            <Download className="w-3.5 h-3.5" /> CSV por IP
          </button>
          <button type="button" disabled={!report} onClick={exportDestinations} className={btn}>
            <Download className="w-3.5 h-3.5" /> CSV destinos
          </button>
          <button type="button" onClick={() => window.print()} className={btn}>
            <Printer className="w-3.5 h-3.5" /> Imprimir
          </button>
        </div>
      </div>

      {loading && (
        <p className="text-xs text-[var(--fw-text-muted)] inline-flex items-center gap-2" role="status">
          <Loader2 className="w-3.5 h-3.5 animate-spin" aria-hidden="true" /> Calculando no banco… períodos longos podem levar alguns segundos.
        </p>
      )}
      {error && (
        <p className="text-xs text-red-700" role="alert">
          {error}
        </p>
      )}
      {report?.timedOut && (
        <div className="flex items-start gap-2 rounded-lg border border-amber-300 bg-amber-50 p-3 text-xs text-amber-900" role="alert">
          <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0" aria-hidden="true" />
          <p>O banco não terminou o cálculo no tempo limite (muitos logs no período). Escolha um período menor.</p>
        </div>
      )}

      {report && t && !report.timedOut && (
        <div className="bg-white border border-[var(--fw-border)] rounded-lg p-6 space-y-6">
          <div className="border-b border-[var(--fw-border)] pb-4">
            <p className="text-xs font-medium text-[var(--fw-accent)]">FW Audit · Acessos e Consumo</p>
            <h3 className="text-xl font-semibold text-[var(--fw-heading)] mt-1">Últimos {periodLabel(report.minutes)}</h3>
            <p className="text-xs text-[var(--fw-text-muted)] mt-1 tabular-nums">
              {new Date(report.periodStart ?? report.generatedAt).toLocaleString('pt-BR')} até {new Date(report.periodEnd).toLocaleString('pt-BR')} · {n(report.analyzedEvents)} eventos de tráfego
              {report.coveragePct < 100 ? ` · detalhe cobre ${report.coveragePct}% (maiores fluxos)` : ''}
            </p>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {[
              { l: 'Conexões', v: n(t.connections), s: `${n(t.blocked)} bloqueadas (${pct(t.blocked, t.connections).toFixed(1)}%)` },
              { l: 'Volume total', v: formatBytes(t.totalBytes), s: `↓ ${formatBytes(t.downloadBytes)} · ↑ ${formatBytes(t.uploadBytes)}` },
              { l: 'Banda média / pico', v: `${t.avgMbps.toLocaleString('pt-BR')} Mbps`, s: `pico em 1 h: ${t.peakHourMbps.toLocaleString('pt-BR')} Mbps` },
              { l: 'Alcance', v: `${n(t.sources)} IPs`, s: `${n(t.destinations)} destinos · ${n(t.countries)} países` },
            ].map((c) => (
              <div key={c.l} className="border border-[var(--fw-border)] rounded-lg p-3">
                <p className="text-[11px] text-[var(--fw-text-muted)]">{c.l}</p>
                <p className="text-lg font-semibold text-[var(--fw-heading)] tabular-nums">{c.v}</p>
                <p className="text-[11px] text-[var(--fw-text-subtle)] tabular-nums">{c.s}</p>
              </div>
            ))}
          </div>
          {t.threatConnections > 0 && (
            <p className="text-xs rounded-md border border-red-200 bg-red-50 text-red-800 p-2" role="alert">
              Atenção: {n(t.threatConnections)} conexões foram para IPs em listas de ameaça (blacklist, botnet ou Tor). Veja a coluna Reputação em Destinos.
            </p>
          )}

          <section aria-label="Banda ao longo do tempo">
            <h4 className="text-sm font-semibold text-[var(--fw-heading)] mb-2">Banda ao longo do tempo (média por hora, Mbps)</h4>
            {chart.length === 0 ? (
              <p className="text-xs text-[var(--fw-text-muted)]">Sem dados com volume no período.</p>
            ) : (
              <div className="h-56">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={chart}>
                    <CartesianGrid strokeDasharray="3 3" stroke="var(--fw-border)" />
                    <XAxis dataKey="hora" tick={{ fontSize: 10 }} minTickGap={24} />
                    <YAxis tick={{ fontSize: 10 }} width={48} />
                    <Tooltip />
                    <Area type="monotone" dataKey="Download" stroke="#0ea5e9" fill="#0ea5e9" fillOpacity={0.25} />
                    <Area type="monotone" dataKey="Upload" stroke="#8b5cf6" fill="#8b5cf6" fillOpacity={0.25} />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            )}
          </section>

          <section aria-label="Consumo por IP">
            <h4 className="text-sm font-semibold text-[var(--fw-heading)] mb-2">Consumo de banda por IP de origem (Top {report.sources.length})</h4>
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="text-left text-[var(--fw-text-muted)]">
                    <th className="py-1.5 pr-3 font-medium">IP</th>
                    <th className="py-1.5 pr-3 font-medium w-40">Consumo</th>
                    <th className="py-1.5 pr-3 font-medium text-right">Download</th>
                    <th className="py-1.5 pr-3 font-medium text-right">Upload</th>
                    <th className="py-1.5 pr-3 font-medium text-right">Total</th>
                    <th className="py-1.5 pr-3 font-medium text-right">%</th>
                    <th className="py-1.5 pr-3 font-medium text-right">Conexões</th>
                    <th className="py-1.5 pr-3 font-medium text-right">Bloq.</th>
                    <th className="py-1.5 pr-3 font-medium">Categoria principal</th>
                    <th className="py-1.5 font-medium">País</th>
                  </tr>
                </thead>
                <tbody>
                  {report.sources.map((s) => (
                    <tr key={s.ip} className="border-t border-[var(--fw-border)]">
                      <td className="py-1.5 pr-3 font-mono">{s.ip}</td>
                      <td className="py-1.5 pr-3"><Bar value={pct(s.totalBytes, maxSrc)} color="#0ea5e9" /></td>
                      <td className="py-1.5 pr-3 text-right tabular-nums">{formatBytes(s.downloadBytes)}</td>
                      <td className="py-1.5 pr-3 text-right tabular-nums">{formatBytes(s.uploadBytes)}</td>
                      <td className="py-1.5 pr-3 text-right tabular-nums font-semibold">{formatBytes(s.totalBytes)}</td>
                      <td className="py-1.5 pr-3 text-right tabular-nums">{pct(s.totalBytes, t.totalBytes).toFixed(1)}%</td>
                      <td className="py-1.5 pr-3 text-right tabular-nums">{n(s.connections)}</td>
                      <td className="py-1.5 pr-3 text-right tabular-nums">{n(s.blocked)}</td>
                      <td className="py-1.5 pr-3 text-[var(--fw-text-muted)]">{s.topCategory ?? '—'}</td>
                      <td className="py-1.5 text-[var(--fw-text-muted)]">{s.topCountry ? `${flagEmoji(s.topCountry)} ${countryName(s.topCountry)}` : '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {report.othersSources.count > 0 && (
              <p className="mt-1 text-[11px] text-[var(--fw-text-muted)]">
                + {n(report.othersSources.count)} outros IPs somam {formatBytes(report.othersSources.totalBytes)} ({pct(report.othersSources.totalBytes, t.totalBytes).toFixed(1)}% do volume).
              </p>
            )}
          </section>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <section aria-label="Categorias">
              <h4 className="text-sm font-semibold text-[var(--fw-heading)] mb-2">Categorias mais acessadas</h4>
              <ul className="space-y-2">
                {report.categories.slice(0, 12).map((c) => (
                  <li key={c.name}>
                    <div className="flex justify-between gap-2 text-xs">
                      <span className="font-medium text-[var(--fw-heading)]">{c.name}</span>
                      <span className="tabular-nums text-[var(--fw-text-muted)]">
                        {n(c.connections)} ({pct(c.connections, t.connections).toFixed(1)}%) · {formatBytes(c.totalBytes)}
                      </span>
                    </div>
                    <Bar value={pct(c.connections, maxCat)} color="#8b5cf6" />
                  </li>
                ))}
              </ul>
              <p className="mt-1 text-[11px] text-[var(--fw-text-subtle)]">Categoria pelo nome do destino (log ou DNS reverso) e pelo serviço/porta quando o nome é desconhecido.</p>
            </section>

            <section aria-label="Países">
              <h4 className="text-sm font-semibold text-[var(--fw-heading)] mb-2">Países mais acessados</h4>
              <ul className="space-y-2">
                {report.countries.slice(0, 12).map((c) => (
                  <li key={c.code}>
                    <div className="flex justify-between gap-2 text-xs">
                      <span className="font-medium text-[var(--fw-heading)]">
                        {flagEmoji(c.code)} {countryName(c.code)}
                      </span>
                      <span className="tabular-nums text-[var(--fw-text-muted)]">
                        {n(c.connections)} ({pct(c.connections, t.connections).toFixed(1)}%) · {formatBytes(c.totalBytes)}
                      </span>
                    </div>
                    <Bar value={pct(c.connections, maxCountry)} color="#10b981" />
                  </li>
                ))}
                {report.countries.length === 0 && <li className="text-xs text-[var(--fw-text-muted)]">Sem países (baixe as bases na aba Behavior).</li>}
              </ul>
            </section>
          </div>

          <section aria-label="Destinos">
            <h4 className="text-sm font-semibold text-[var(--fw-heading)] mb-2">Destinos mais acessados (Top {report.destinations.length})</h4>
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="text-left text-[var(--fw-text-muted)]">
                    <th className="py-1.5 pr-3 font-medium">Destino</th>
                    <th className="py-1.5 pr-3 font-medium">Categoria</th>
                    <th className="py-1.5 pr-3 font-medium">País</th>
                    <th className="py-1.5 pr-3 font-medium">Organização (ASN)</th>
                    <th className="py-1.5 pr-3 font-medium text-right">Conexões</th>
                    <th className="py-1.5 pr-3 font-medium text-right">Volume</th>
                    <th className="py-1.5 font-medium">Reputação</th>
                  </tr>
                </thead>
                <tbody>
                  {report.destinations.map((d) => (
                    <tr key={d.ip} className="border-t border-[var(--fw-border)]">
                      <td className="py-1.5 pr-3">
                        <span className="font-medium text-[var(--fw-heading)]">{d.host ?? d.ip}</span>
                        {d.host && <span className="block font-mono text-[10px] text-[var(--fw-text-subtle)]">{d.ip}</span>}
                      </td>
                      <td className="py-1.5 pr-3 text-[var(--fw-text-muted)]">{d.category}</td>
                      <td className="py-1.5 pr-3 text-[var(--fw-text-muted)]">{d.country ? `${flagEmoji(d.country)} ${countryName(d.country)}` : '—'}</td>
                      <td className="py-1.5 pr-3 text-[var(--fw-text-muted)]">{d.asnOrg ?? '—'}</td>
                      <td className="py-1.5 pr-3 text-right tabular-nums">{n(d.connections)}</td>
                      <td className="py-1.5 pr-3 text-right tabular-nums">{formatBytes(d.totalBytes)}</td>
                      <td className="py-1.5">
                        {d.threats.length ? <span className="px-1.5 py-0.5 rounded border border-red-200 bg-red-100 text-red-800 text-[10px] font-semibold">{d.threats.join(', ')}</span> : <span className="text-[var(--fw-text-subtle)]">limpo</span>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>

          <section aria-label="Serviços">
            <h4 className="text-sm font-semibold text-[var(--fw-heading)] mb-2">Serviços mais usados</h4>
            <ul className="grid grid-cols-1 md:grid-cols-2 gap-x-6 gap-y-2">
              {report.services.map((s) => (
                <li key={s.name}>
                  <div className="flex justify-between gap-2 text-xs">
                    <span className="font-medium text-[var(--fw-heading)]">{s.name}</span>
                    <span className="tabular-nums text-[var(--fw-text-muted)]">
                      {n(s.connections)} · {formatBytes(s.totalBytes)}
                    </span>
                  </div>
                  <Bar value={pct(s.connections, maxSvc)} color="#f59e0b" />
                </li>
              ))}
            </ul>
          </section>

          <p className="text-[11px] text-[var(--fw-text-subtle)] border-t border-[var(--fw-border)] pt-3">
            Metodologia: conexões e bytes somados dos syslogs de tráfego (eventos de sistema excluídos). Download = bytes recebidos pelo cliente, Upload = bytes enviados. País, ASN e reputação vêm das
            bases offline (aba Behavior). Banda por hora é a média do volume dividido por 3600 s.
          </p>
        </div>
      )}
    </div>
  );
}
