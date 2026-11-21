import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { AlertTriangle, DatabaseZap, Globe2, Loader2, RefreshCw, ShieldAlert } from 'lucide-react';
import type { BehaviorIntelStatus, BehaviorIp, BehaviorReport, FirewallVendor } from '../types.ts';
import { formatBytes } from '../../shared/destinations.ts';
import { vendorApiUrl } from '../utils/vendorApi.ts';
import { allCountries, countryName, flagEmoji } from '../utils/worldGeo.ts';
import { WorldMap, type MapMode } from './WorldMap.tsx';

interface BehaviorViewProps {
  vendor: FirewallVendor;
  refreshToken: number;
  onInvestigate: (query: string) => void;
}

const RANGES: Array<{ label: string; minutes: number }> = [
  { label: '5 min', minutes: 5 },
  { label: '15 min', minutes: 15 },
  { label: '1 h', minutes: 60 },
  { label: '6 h', minutes: 360 },
  { label: '24 h', minutes: 1440 },
];

const CATEGORY_LABEL: Record<string, string> = { blacklist: 'Blacklist', botnet: 'Botnet', tor: 'Tor' };
const CATEGORY_STYLE: Record<string, string> = {
  blacklist: 'bg-red-100 text-red-800 border-red-200',
  botnet: 'bg-fuchsia-100 text-fuchsia-800 border-fuchsia-200',
  tor: 'bg-violet-100 text-violet-800 border-violet-200',
};

const fmt = (n: number) => n.toLocaleString('pt-BR');
const segment = (active: boolean) =>
  `px-3 py-1.5 text-xs font-semibold rounded-md transition-colors ${
    active ? 'bg-white text-[var(--fw-heading)] shadow-xs' : 'text-[var(--fw-text-muted)] hover:text-[var(--fw-heading)]'
  }`;

const when = (iso: string | null) => (iso ? new Date(iso).toLocaleString('pt-BR', { dateStyle: 'short', timeStyle: 'short' }) : 'nunca');

export function BehaviorView({ vendor, refreshToken, onInvestigate }: BehaviorViewProps) {
  const [minutes, setMinutes] = useState(15);
  const [mode, setMode] = useState<MapMode>('realtime');
  const [report, setReport] = useState<BehaviorReport | null>(null);
  const [intel, setIntel] = useState<BehaviorIntelStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<string | null>(null);
  const [showSources, setShowSources] = useState(false);
  const [updateMsg, setUpdateMsg] = useState<string | null>(null);
  const countryOptions = useMemo(() => allCountries(), []);
  const timer = useRef<number | null>(null);

  const load = useCallback(
    async (signal?: AbortSignal) => {
      try {
        const res = await fetch(vendorApiUrl(vendor, `/behavior?minutes=${minutes}`), { signal });
        if (!res.ok) {
          const data = (await res.json().catch(() => ({}))) as { error?: string };
          throw new Error(data.error || `HTTP ${res.status}`);
        }
        const data = (await res.json()) as BehaviorReport;
        setReport(data);
        setIntel(data.intel);
        setError(null);
      } catch (err) {
        if ((err as Error).name === 'AbortError') return;
        setError(err instanceof Error ? err.message : 'Falha ao carregar o Behavior.');
      } finally {
        setLoading(false);
      }
    },
    [vendor, minutes]
  );

  useEffect(() => {
    const ctrl = new AbortController();
    setLoading(true);
    void load(ctrl.signal);
    // Tempo real: atualiza a cada 5 s; estático: a cada 30 s
    const id = window.setInterval(() => void load(ctrl.signal), mode === 'realtime' ? 5000 : 30000);
    return () => {
      ctrl.abort();
      window.clearInterval(id);
    };
  }, [load, mode, refreshToken]);

  // Acompanha a atualização das bases até terminar
  const pollIntel = useCallback(async () => {
    try {
      const res = await fetch(vendorApiUrl(vendor, '/behavior/intel'));
      if (!res.ok) return;
      const s = (await res.json()) as BehaviorIntelStatus;
      setIntel(s);
      if (s.updating) {
        timer.current = window.setTimeout(() => void pollIntel(), 3000);
      } else {
        const failed = s.sources.filter((x) => x.error).length;
        setUpdateMsg(failed > 0 ? `Atualização concluída com ${failed} fonte(s) com erro.` : 'Bases atualizadas.');
        void load();
      }
    } catch {
      /* tenta de novo no próximo ciclo */
    }
  }, [vendor, load]);

  useEffect(
    () => () => {
      if (timer.current) window.clearTimeout(timer.current);
    },
    []
  );

  const updateNow = async () => {
    setUpdateMsg(null);
    try {
      const res = await fetch(vendorApiUrl(vendor, '/behavior/intel/update'), { method: 'POST' });
      const data = (await res.json().catch(() => ({}))) as { error?: string; intel?: BehaviorIntelStatus };
      if (data.intel) setIntel(data.intel);
      if (!res.ok && res.status !== 409) throw new Error(data.error || `HTTP ${res.status}`);
      setUpdateMsg('Baixando as bases… isso pode levar alguns minutos.');
      void pollIntel();
    } catch (err) {
      setUpdateMsg(err instanceof Error ? err.message : 'Falha ao iniciar a atualização.');
    }
  };

  const changeOrigin = async (code: string) => {
    try {
      await fetch(vendorApiUrl(vendor, '/behavior/origin'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ country: code }),
      });
      await load();
    } catch {
      /* mantém o país atual */
    }
  };

  const recentByCountry = useMemo(() => {
    const m = new Map<string, number>();
    for (const f of report?.flows ?? []) m.set(f.country, (m.get(f.country) ?? 0) + 1);
    return m;
  }, [report]);

  const selectedIps = useMemo<BehaviorIp[]>(
    () => (selected ? (report?.ips ?? []).filter((i) => i.country === selected) : []),
    [report, selected]
  );
  const maxCountry = report?.countries[0]?.connections ?? 0;
  const t = report?.totals;
  const bases = intel?.ready ?? false;

  return (
    <div className="space-y-4">
      <div className="bg-white border border-[var(--fw-border)] rounded-lg p-3 flex flex-wrap items-center gap-3">
        <div className="flex items-center gap-1 p-1 bg-[var(--fw-surface-alt)] rounded-md" role="group" aria-label="Modo do mapa">
          <button type="button" onClick={() => setMode('realtime')} aria-pressed={mode === 'realtime'} className={segment(mode === 'realtime')}>
            Real Time View
          </button>
          <button type="button" onClick={() => setMode('static')} aria-pressed={mode === 'static'} className={segment(mode === 'static')}>
            Static View
          </button>
        </div>
        <div className="flex items-center gap-1 p-1 bg-[var(--fw-surface-alt)] rounded-md" role="group" aria-label="Período">
          {RANGES.map((r) => (
            <button key={r.minutes} type="button" onClick={() => setMinutes(r.minutes)} aria-pressed={minutes === r.minutes} className={segment(minutes === r.minutes)}>
              {r.label}
            </button>
          ))}
        </div>
        <label className="flex items-center gap-2 text-xs text-[var(--fw-text-muted)]">
          País do firewall
          <select
            value={report?.originCountry ?? 'BR'}
            onChange={(e) => void changeOrigin(e.target.value)}
            className="px-2 py-1.5 text-xs border border-[var(--fw-border-strong)] rounded-md bg-[var(--fw-bg-input)] text-[var(--fw-text-body)] max-w-44"
            aria-label="País onde o firewall está (origem das linhas)"
          >
            {countryOptions.map((c) => (
              <option key={c.code} value={c.code}>
                {c.name}
              </option>
            ))}
          </select>
        </label>
        <div className="md:ml-auto flex items-center gap-2">
          <button
            type="button"
            onClick={() => void updateNow()}
            disabled={intel?.updating}
            className="inline-flex items-center gap-2 px-3 py-1.5 text-xs font-semibold rounded-md border border-[var(--fw-border-strong)] bg-white text-[var(--fw-heading)] hover:bg-[var(--fw-surface)] disabled:opacity-60"
          >
            {intel?.updating ? <Loader2 className="w-3.5 h-3.5 animate-spin" aria-hidden="true" /> : <RefreshCw className="w-3.5 h-3.5" aria-hidden="true" />}
            {intel?.updating ? 'Atualizando bases…' : 'Atualizar bases agora'}
          </button>
        </div>
      </div>

      {!bases && !loading && (
        <div className="flex items-start gap-3 rounded-lg border border-amber-300 bg-amber-50 p-3 text-xs text-amber-900" role="status">
          <DatabaseZap className="w-4 h-4 mt-0.5 shrink-0" aria-hidden="true" />
          <p>
            As bases de GeoIP e reputação ainda não foram baixadas. Clique em <strong>Atualizar bases agora</strong> (o servidor precisa de acesso à
            internet só para baixar; os IPs dos logs nunca saem dele).
          </p>
        </div>
      )}
      {updateMsg && (
        <p className="text-xs text-[var(--fw-text-muted)]" role="status">
          {updateMsg}
        </p>
      )}
      {error && (
        <p className="text-xs text-red-700" role="alert">
          {error}
        </p>
      )}

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {[
          { label: 'Conexões externas', value: fmt(t?.connections ?? 0), hint: `${fmt(report?.publicIps ?? 0)} IPs públicos` },
          { label: 'Países', value: fmt(t?.countries ?? 0), hint: t?.unknownConnections ? `${fmt(t.unknownConnections)} sem país` : 'todos localizados' },
          { label: 'Bloqueadas', value: fmt(t?.blocked ?? 0), hint: 'drop / deny / reset' },
          { label: 'Contato com ameaça', value: fmt(t?.threatConnections ?? 0), hint: 'blacklist, botnet ou Tor', danger: (t?.threatConnections ?? 0) > 0 },
        ].map((c) => (
          <div key={c.label} className="bg-white border border-[var(--fw-border)] rounded-lg p-3">
            <p className="text-[11px] text-[var(--fw-text-muted)]">{c.label}</p>
            <p className={`text-xl font-semibold tabular-nums ${c.danger ? 'text-red-600' : 'text-[var(--fw-heading)]'}`}>{c.value}</p>
            <p className="text-[11px] text-[var(--fw-text-subtle)]">{c.hint}</p>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-[minmax(0,1fr)_340px] gap-4 items-start">
        <section className="bg-white border border-[var(--fw-border)] rounded-lg p-4" aria-label="Mapa mundi de tráfego">
          <div className="flex flex-wrap items-baseline justify-between gap-2 mb-3">
            <h2 className="text-sm font-semibold text-[var(--fw-heading)] inline-flex items-center gap-2">
              <Globe2 className="w-4 h-4" aria-hidden="true" />
              {mode === 'realtime' ? 'Tráfego em tempo real' : 'Mapa de calor por país'}
            </h2>
            <p className="text-[11px] text-[var(--fw-text-muted)] tabular-nums">
              {report ? `${fmt(report.analyzedEvents)} eventos analisados${report.truncated ? ' (limite de leitura atingido)' : ''}` : ''}
            </p>
          </div>
          {loading && !report ? (
            <div className="h-80 grid place-items-center text-xs text-[var(--fw-text-muted)]">Carregando…</div>
          ) : (
            <WorldMap
              countries={report?.countries ?? []}
              originCode={report?.originCountry ?? 'BR'}
              mode={mode}
              selected={selected}
              onSelect={setSelected}
              recentByCountry={recentByCountry}
            />
          )}
          <p className="mt-2 text-[11px] text-[var(--fw-text-muted)]">
            {mode === 'realtime'
              ? 'As linhas partem do país do firewall (ponto azul) para os países mais acessados; mais partículas e linha mais grossa = mais conexões. Vermelho = há IP em lista de ameaça; âmbar = muitos bloqueios.'
              : 'Cor do país = volume de conexões (quente = mais). Pontos vermelhos marcam os destinos, posicionados no centro do país (a base é por país, não por cidade).'}{' '}
            Clique em um país para ver os IPs.
          </p>
        </section>

        <aside className="space-y-4">
          <section className="bg-white border border-[var(--fw-border)] rounded-lg p-4" aria-label="Países mais acessados">
            <h3 className="text-sm font-semibold text-[var(--fw-heading)] mb-2">Países mais acessados</h3>
            {report && report.countries.length === 0 ? (
              <p className="text-xs text-[var(--fw-text-muted)]">Nenhum destino público localizado no período.</p>
            ) : (
              <ol className="space-y-1.5">
                {(report?.countries ?? []).slice(0, 10).map((c) => (
                  <li key={c.code}>
                    <button
                      type="button"
                      onClick={() => setSelected(selected === c.code ? null : c.code)}
                      className={`w-full text-left rounded-md px-2 py-1.5 hover:bg-[var(--fw-surface-alt)] ${selected === c.code ? 'bg-[var(--fw-surface-alt)]' : ''}`}
                    >
                      <div className="flex items-center justify-between gap-2 text-xs">
                        <span className="font-medium text-[var(--fw-heading)] truncate">
                          {flagEmoji(c.code)} {countryName(c.code)}
                        </span>
                        <span className="tabular-nums text-[var(--fw-text-muted)]">{fmt(c.connections)}</span>
                      </div>
                      <div className="mt-1 h-1.5 rounded-full bg-[var(--fw-surface-alt)] overflow-hidden">
                        <div className="h-full rounded-full" style={{ width: `${Math.max(3, (c.connections / maxCountry) * 100)}%`, background: c.threatIps > 0 ? '#ef4444' : '#38bdf8' }} />
                      </div>
                    </button>
                  </li>
                ))}
              </ol>
            )}
          </section>

          <section className="bg-white border border-[var(--fw-border)] rounded-lg p-4" aria-label="IPs em listas de ameaça">
            <h3 className="text-sm font-semibold text-[var(--fw-heading)] mb-2 inline-flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-red-600" aria-hidden="true" />
              Reputação: blacklist, botnet e Tor
            </h3>
            {!report || report.threats.length === 0 ? (
              <p className="text-xs text-[var(--fw-text-muted)]">
                {bases ? 'Nenhum IP contatado consta nas listas de ameaça neste período.' : 'Baixe as bases para habilitar a reputação.'}
              </p>
            ) : (
              <ul className="space-y-2 max-h-72 overflow-auto">
                {report.threats.slice(0, 30).map((ip) => (
                  <li key={ip.ip} className="text-xs rounded-md border border-[var(--fw-border)] p-2">
                    <div className="flex items-center justify-between gap-2">
                      <button type="button" onClick={() => onInvestigate(ip.ip)} className="font-mono font-semibold text-[var(--fw-heading)] hover:underline">
                        {ip.ip}
                      </button>
                      <span className="tabular-nums text-[var(--fw-text-muted)]">{fmt(ip.connections)}×</span>
                    </div>
                    <div className="mt-1 flex flex-wrap gap-1">
                      {ip.categories.map((c) => (
                        <span key={c} className={`px-1.5 py-0.5 rounded border text-[10px] font-semibold ${CATEGORY_STYLE[c]}`}>
                          {CATEGORY_LABEL[c]}
                        </span>
                      ))}
                      <span className="text-[10px] text-[var(--fw-text-muted)]">{ip.threats.join(', ')}</span>
                    </div>
                    <p className="mt-1 text-[11px] text-[var(--fw-text-muted)]">
                      {ip.country ? `${flagEmoji(ip.country)} ${countryName(ip.country)}` : 'país desconhecido'}
                      {ip.asnOrg ? ` · AS${ip.asn} ${ip.asnOrg}` : ''}
                    </p>
                    {ip.topSources.length > 0 && (
                      <p className="mt-0.5 text-[11px] text-[var(--fw-text-muted)]">
                        Acessado por: {ip.topSources.map((s) => s.ip).join(', ')}
                      </p>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </section>
        </aside>
      </div>

      {selected && (
        <section className="bg-white border border-[var(--fw-border)] rounded-lg p-4" aria-label="IPs do país selecionado">
          <div className="flex items-center justify-between gap-2 mb-2">
            <h3 className="text-sm font-semibold text-[var(--fw-heading)]">
              {flagEmoji(selected)} IPs em {countryName(selected)}
            </h3>
            <button type="button" onClick={() => setSelected(null)} className="text-xs text-[var(--fw-text-muted)] hover:text-[var(--fw-heading)]">
              Fechar
            </button>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="text-left text-[var(--fw-text-muted)]">
                  <th className="py-1.5 pr-3 font-medium">IP</th>
                  <th className="py-1.5 pr-3 font-medium">Organização (ASN)</th>
                  <th className="py-1.5 pr-3 font-medium text-right">Conexões</th>
                  <th className="py-1.5 pr-3 font-medium text-right">Bloq.</th>
                  <th className="py-1.5 pr-3 font-medium text-right">Volume</th>
                  <th className="py-1.5 font-medium">Reputação</th>
                </tr>
              </thead>
              <tbody>
                {selectedIps.slice(0, 50).map((ip) => (
                  <tr key={ip.ip} className="border-t border-[var(--fw-border)]">
                    <td className="py-1.5 pr-3 font-mono">
                      <button type="button" onClick={() => onInvestigate(ip.ip)} className="hover:underline">
                        {ip.ip}
                      </button>
                    </td>
                    <td className="py-1.5 pr-3 text-[var(--fw-text-muted)]">{ip.asnOrg ? `${ip.asnOrg} (AS${ip.asn})` : '—'}</td>
                    <td className="py-1.5 pr-3 text-right tabular-nums">{fmt(ip.connections)}</td>
                    <td className="py-1.5 pr-3 text-right tabular-nums">{fmt(ip.blocked)}</td>
                    <td className="py-1.5 pr-3 text-right tabular-nums">{formatBytes(ip.bytes)}</td>
                    <td className="py-1.5">
                      {ip.categories.length === 0 ? (
                        <span className="text-[var(--fw-text-subtle)]">limpo</span>
                      ) : (
                        ip.categories.map((c) => (
                          <span key={c} className={`mr-1 px-1.5 py-0.5 rounded border text-[10px] font-semibold ${CATEGORY_STYLE[c]}`}>
                            {CATEGORY_LABEL[c]}
                          </span>
                        ))
                      )}
                    </td>
                  </tr>
                ))}
                {selectedIps.length === 0 && (
                  <tr>
                    <td colSpan={6} className="py-3 text-[var(--fw-text-muted)]">
                      Sem IPs detalhados para este país nos maiores destinos do período.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </section>
      )}

      <section className="bg-white border border-[var(--fw-border)] rounded-lg p-3 text-xs" aria-label="Bases de inteligência">
        <button type="button" onClick={() => setShowSources((v) => !v)} className="font-semibold text-[var(--fw-heading)] inline-flex items-center gap-2" aria-expanded={showSources}>
          Bases offline · última verificação: {when(intel?.lastCheckAt ?? null)}
          {intel?.sources.some((s) => s.error) && <AlertTriangle className="w-3.5 h-3.5 text-amber-600" aria-label="Há fontes com erro" />}
        </button>
        {showSources && (
          <table className="mt-2 w-full">
            <thead>
              <tr className="text-left text-[var(--fw-text-muted)]">
                <th className="py-1 pr-3 font-medium">Fonte</th>
                <th className="py-1 pr-3 font-medium text-right">Registros</th>
                <th className="py-1 pr-3 font-medium">Atualizada em</th>
                <th className="py-1 font-medium">Situação</th>
              </tr>
            </thead>
            <tbody>
              {(intel?.sources ?? []).map((s) => (
                <tr key={s.id} className="border-t border-[var(--fw-border)]">
                  <td className="py-1 pr-3">{s.label}</td>
                  <td className="py-1 pr-3 text-right tabular-nums">{fmt(s.entries)}</td>
                  <td className="py-1 pr-3">{when(s.updatedAt)}</td>
                  <td className={`py-1 ${s.error ? 'text-red-700' : 'text-[var(--fw-text-muted)]'}`}>{s.error ?? (s.updatedAt ? 'ok' : 'não baixada')}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        <p className="mt-2 text-[11px] text-[var(--fw-text-subtle)]">
          GeoIP e ASN: DB-IP Lite (CC BY 4.0, db-ip.com). Reputação: FireHOL Level 1, Spamhaus DROP, abuse.ch Feodo Tracker e lista de saída do Tor. Só IPv4. Atualização
          automática diária (listas) e mensal (GeoIP); desative com INTEL_AUTO_UPDATE=false.
        </p>
      </section>
    </div>
  );
}
