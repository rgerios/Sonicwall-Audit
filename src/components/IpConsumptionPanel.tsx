import { useCallback, useEffect, useState } from 'react';
import {
  Activity,
  ArrowDownLeft,
  ArrowUpRight,
  Clock,
  Filter,
  RefreshCw,
  Search,
  X,
} from 'lucide-react';
import {
  Bar,
  CartesianGrid,
  ComposedChart,
  Line,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import type { FirewallVendor, IpConsumptionReport } from '../types.ts';
import { vendorApiUrl } from '../utils/vendorApi.ts';

interface IpConsumptionPanelProps {
  vendor: FirewallVendor;
  refreshToken: number;
  onFilterSyslogsByIp: (ip: string) => void;
}

const WINDOW_OPTIONS = [
  { value: 5, label: '5 min' },
  { value: 15, label: '15 min' },
  { value: 60, label: '1 hora' },
  { value: 360, label: '6 horas' },
  { value: 1440, label: '24 horas' },
];

function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let idx = 0;
  let val = bytes;
  while (val >= 1024 && idx < units.length - 1) {
    val /= 1024;
    idx += 1;
  }
  return `${val >= 100 ? val.toFixed(0) : val >= 10 ? val.toFixed(1) : val.toFixed(2)} ${units[idx]}`;
}

export function IpConsumptionPanel({
  vendor,
  refreshToken,
  onFilterSyslogsByIp,
}: IpConsumptionPanelProps) {
  const [ipInput, setIpInput] = useState('');
  const [activeIp, setActiveIp] = useState('');
  const [windowMinutes, setWindowMinutes] = useState(15);
  const [chartMode, setChartMode] = useState<'combo' | 'bar' | 'line'>('combo');
  const [report, setReport] = useState<IpConsumptionReport | null>(null);
  const [loading, setLoading] = useState(false);

  const fetchConsumption = useCallback(
    async (ip: string, win: number) => {
      setLoading(true);
      try {
        const params = new URLSearchParams({
          windowMinutes: String(win),
        });
        if (ip.trim()) params.set('ip', ip.trim());
        const res = await fetch(
          vendorApiUrl(vendor, `/syslogs/ip-consumption?${params.toString()}`)
        );
        if (res.ok) {
          const data = (await res.json()) as IpConsumptionReport;
          setReport(data);
        }
      } finally {
        setLoading(false);
      }
    },
    [vendor]
  );

  useEffect(() => {
    setActiveIp('');
    setIpInput('');
  }, [vendor]);

  useEffect(() => {
    void fetchConsumption(activeIp, windowMinutes);
  }, [fetchConsumption, activeIp, windowMinutes, refreshToken]);

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    setActiveIp(ipInput.trim());
  };

  const handleSelectIp = (ip: string) => {
    setIpInput(ip);
    setActiveIp(ip);
  };

  const handleClear = () => {
    setIpInput('');
    setActiveIp('');
  };

  return (
    <div className="bg-white border border-[var(--fw-border)] rounded-lg p-5 space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <Activity className="w-4 h-4 text-[var(--fw-accent)]" />
          <div>
            <h3 className="text-sm font-semibold text-[var(--fw-heading)]">
              Consumo de Banda por IP (via Syslog)
            </h3>
            <p className="text-[11px] text-[var(--fw-text-muted)]">
              Volume e vazão média estimada a partir dos bytes registrados nos eventos recentes
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <div className="inline-flex items-center gap-1 bg-[var(--fw-surface-alt)] p-0.5 rounded-md">
            <Clock className="w-3.5 h-3.5 text-[var(--fw-text-subtle)] ml-2" />
            {WINDOW_OPTIONS.map((opt) => (
              <button
                key={opt.value}
                type="button"
                onClick={() => setWindowMinutes(opt.value)}
                className={`px-2.5 py-1 text-[11px] font-medium rounded transition-colors cursor-pointer ${
                  windowMinutes === opt.value
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
            onClick={() => void fetchConsumption(activeIp, windowMinutes)}
            disabled={loading}
            className="inline-flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-medium text-[var(--fw-text-body)] bg-white border border-[var(--fw-border-strong)] rounded-md hover:bg-[var(--fw-bg)] cursor-pointer disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Atualizar
          </button>
        </div>
      </div>

      <form onSubmit={handleSearch} className="flex flex-wrap items-center gap-2">
        <div className="relative flex-1 min-w-[240px]">
          <Search className="w-3.5 h-3.5 text-[var(--fw-text-subtle)] absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={ipInput}
            onChange={(e) => setIpInput(e.target.value)}
            placeholder="Digite um IP para consultar consumo (ex: 10.20.4.45)..."
            className="w-full pl-9 pr-8 py-2 text-xs font-mono border border-[var(--fw-border-strong)] rounded-md bg-[var(--fw-bg-input)] focus:outline-none focus:ring-2 focus:ring-[var(--fw-accent-mid)]"
          />
          {(ipInput || activeIp) && (
            <button
              type="button"
              onClick={handleClear}
              title="Limpar IP"
              className="absolute right-2.5 top-1/2 -translate-y-1/2 text-[var(--fw-text-subtle)] hover:text-[var(--fw-heading)] cursor-pointer"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
        <button
          type="submit"
          disabled={loading}
          className="px-4 py-2 text-xs font-medium text-white bg-[var(--fw-accent)] rounded-md hover:bg-[var(--fw-accent-hover)] cursor-pointer disabled:opacity-50"
        >
          Consultar IP
        </button>
        {activeIp && (
          <button
            type="button"
            onClick={() => onFilterSyslogsByIp(activeIp)}
            className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-[var(--fw-text-body)] bg-[var(--fw-surface)] border border-[var(--fw-border-strong)] rounded-md hover:bg-[var(--fw-surface-alt)] cursor-pointer"
          >
            <Filter className="w-3.5 h-3.5" />
            Filtrar logs deste IP
          </button>
        )}
      </form>

      {report && report.topConsumers.length > 0 && (
        <div className="space-y-1.5">
          <div className="text-[11px] font-medium text-[var(--fw-text-muted)]">
            Top consumidores nos últimos {windowMinutes >= 60 ? `${windowMinutes / 60}h` : `${windowMinutes} min`} (clique para detalhar):
          </div>
          <div className="flex flex-wrap gap-1.5">
            {report.topConsumers.map((c) => {
              const selected = activeIp === c.ip;
              return (
                <button
                  key={c.ip}
                  type="button"
                  onClick={() => handleSelectIp(c.ip)}
                  className={`inline-flex items-center gap-2 px-2.5 py-1 rounded-md border text-[11px] font-mono transition-colors cursor-pointer ${
                    selected
                      ? 'bg-[var(--fw-accent)] text-white border-[var(--fw-accent)]'
                      : 'bg-[var(--fw-bg)] text-[var(--fw-heading)] border-[var(--fw-border)] hover:border-[var(--fw-border-strong)] hover:bg-[var(--fw-surface)]'
                  }`}
                >
                  <span>{c.ip}</span>
                  <span className={selected ? 'text-white/90' : 'text-[var(--fw-text-muted)]'}>
                    {formatBytes(c.totalBytes)} · {c.avgMbps.toFixed(2)} Mbps
                  </span>
                </button>
              );
            })}
          </div>
        </div>
      )}

      {report && activeIp && (
        <div className="pt-3 border-t border-[var(--fw-border-soft)] space-y-4">
          {report.eventCount === 0 ? (
            <div className="p-4 rounded-md bg-[var(--fw-bg)] border border-[var(--fw-border)] text-xs text-[var(--fw-text-muted)]">
              Nenhum evento de syslog encontrado para <span className="font-mono font-semibold text-[var(--fw-heading)]">{activeIp}</span> nos últimos{' '}
              {windowMinutes >= 60 ? `${windowMinutes / 60} hora(s)` : `${windowMinutes} minutos`}. Tente ampliar a janela de tempo acima.
            </div>
          ) : (
            <>
              <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
                <div className="p-3 rounded-md bg-[var(--fw-bg)] border border-[var(--fw-border)]">
                  <div className="text-[11px] text-[var(--fw-text-muted)]">Consumo Total</div>
                  <div className="text-base font-bold font-mono text-[var(--fw-heading)] mt-0.5 tabular-nums">
                    {formatBytes(report.totalBytes)}
                  </div>
                  <div className="text-[11px] text-[var(--fw-text-subtle)] mt-0.5">
                    {report.eventCount.toLocaleString('pt-BR')} eventos ({report.allowCount} allow / {report.blockedCount} bloq.)
                  </div>
                </div>

                <div className="p-3 rounded-md bg-[var(--fw-bg)] border border-[var(--fw-border)]">
                  <div className="text-[11px] text-[var(--fw-text-muted)] flex items-center gap-1">
                    <ArrowDownLeft className="w-3.5 h-3.5 text-emerald-600" /> Download (Recebido)
                  </div>
                  <div className="text-base font-bold font-mono text-[var(--fw-heading)] mt-0.5 tabular-nums">
                    {formatBytes(report.bytesRcvd)}
                  </div>
                  <div className="text-[11px] text-[var(--fw-text-subtle)] font-mono mt-0.5">
                    Média {report.rcvdMbps.toFixed(2)} Mbps
                  </div>
                </div>

                <div className="p-3 rounded-md bg-[var(--fw-bg)] border border-[var(--fw-border)]">
                  <div className="text-[11px] text-[var(--fw-text-muted)] flex items-center gap-1">
                    <ArrowUpRight className="w-3.5 h-3.5 text-blue-600" /> Upload (Enviado)
                  </div>
                  <div className="text-base font-bold font-mono text-[var(--fw-heading)] mt-0.5 tabular-nums">
                    {formatBytes(report.bytesSent)}
                  </div>
                  <div className="text-[11px] text-[var(--fw-text-subtle)] font-mono mt-0.5">
                    Média {report.sentMbps.toFixed(2)} Mbps
                  </div>
                </div>

                <div className="p-3 rounded-md bg-[var(--fw-bg)] border border-[var(--fw-border)]">
                  <div className="text-[11px] text-[var(--fw-text-muted)]">Vazão Média na Janela</div>
                  <div className="text-base font-bold font-mono text-[var(--fw-accent)] mt-0.5 tabular-nums">
                    {report.avgMbps.toFixed(2)} Mbps
                  </div>
                  <div className="text-[11px] text-[var(--fw-text-subtle)] mt-0.5 truncate">
                    Último evento: {report.lastSeenAt ? new Date(report.lastSeenAt).toLocaleTimeString('pt-BR') : '-'}
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                <div className="lg:col-span-2 p-3.5 rounded-md border border-[var(--fw-border)] bg-white">
                  <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
                    <div className="text-xs font-semibold text-[var(--fw-heading)]">
                      Vazão ao longo da janela (Mbps) — {activeIp}
                    </div>
                    <div className="inline-flex items-center gap-0.5 bg-[var(--fw-surface-alt)] p-0.5 rounded">
                      {(
                        [
                          { id: 'combo', label: 'Barras + Linha' },
                          { id: 'bar', label: 'Barras' },
                          { id: 'line', label: 'Linha' },
                        ] as const
                      ).map((m) => (
                        <button
                          key={m.id}
                          type="button"
                          onClick={() => setChartMode(m.id)}
                          className={`px-2 py-0.5 text-[10px] font-medium rounded transition-colors cursor-pointer ${
                            chartMode === m.id
                              ? 'bg-white text-[var(--fw-heading)] shadow-xs'
                              : 'text-[var(--fw-text-body)] hover:text-[var(--fw-heading)]'
                          }`}
                        >
                          {m.label}
                        </button>
                      ))}
                    </div>
                  </div>
                  <div className="h-44">
                    <ResponsiveContainer width="100%" height="100%">
                      <ComposedChart data={report.timeline}>
                        <CartesianGrid strokeDasharray="3 3" stroke="var(--fw-border)" />
                        <XAxis dataKey="bucketLabel" tick={{ fontSize: 10, fill: 'var(--fw-text-muted)' }} />
                        <YAxis tick={{ fontSize: 10, fill: 'var(--fw-text-muted)' }} width={36} />
                        <Tooltip
                          contentStyle={{
                            backgroundColor: 'var(--fw-surface)',
                            borderColor: 'var(--fw-border-strong)',
                            color: 'var(--fw-heading)',
                            fontSize: '12px',
                          }}
                          formatter={(val, name) => [`${Number(val ?? 0).toFixed(2)} Mbps`, String(name)]}
                          labelFormatter={(label) => `Horário: ${label}`}
                        />
                        {(chartMode === 'combo' || chartMode === 'bar') && (
                          <Bar
                            dataKey="mbps"
                            name="Vazão (Barras)"
                            fill="var(--fw-accent)"
                            fillOpacity={chartMode === 'combo' ? 0.65 : 0.9}
                            radius={[3, 3, 0, 0]}
                          />
                        )}
                        {(chartMode === 'combo' || chartMode === 'line') && (
                          <Line
                            type="monotone"
                            dataKey="mbps"
                            name="Tendência (Linha)"
                            stroke="var(--fw-accent-mid)"
                            strokeWidth={2.2}
                            dot={{ r: 3, fill: 'var(--fw-accent-mid)' }}
                            activeDot={{ r: 5 }}
                          />
                        )}
                      </ComposedChart>
                    </ResponsiveContainer>
                  </div>
                </div>

                <div className="p-3.5 rounded-md border border-[var(--fw-border)] bg-white space-y-2">
                  <div className="text-xs font-semibold text-[var(--fw-heading)]">
                    Principais Destinos / Pares
                  </div>
                  <div className="divide-y divide-[var(--fw-border-soft)] max-h-44 overflow-y-auto">
                    {report.topDestinations.map((d, i) => (
                      <div key={`${d.ip}-${d.port}-${i}`} className="py-1.5 flex items-center justify-between gap-2 text-[11px]">
                        <div className="min-w-0">
                          <div className="font-mono text-[var(--fw-heading)] truncate">
                            {d.ip}{d.port ? `:${d.port}` : ''}
                          </div>
                          <div className="text-[var(--fw-text-subtle)]">
                            {d.protocol} · {d.events} ev.
                          </div>
                        </div>
                        <div className="font-mono font-semibold text-[var(--fw-heading)] shrink-0 tabular-nums">
                          {formatBytes(d.totalBytes)}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
}
