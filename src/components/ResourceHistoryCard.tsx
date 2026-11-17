import { useEffect, useState } from 'react';
import { Activity, AlertTriangle, CheckCircle2, GitCompareArrows } from 'lucide-react';
import {
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import type { AuditOverview, FirewallVendor, MetricSample } from '../types.ts';
import { vendorApiUrl } from '../utils/vendorApi.ts';

interface ResourceHistoryCardProps {
  vendor: FirewallVendor;
  overview: AuditOverview;
}

const RANGES = [
  { hours: 6, label: '6 h' },
  { hours: 24, label: '24 h' },
  { hours: 168, label: '7 d' },
];

function formatTick(iso: string, hours: number): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  return hours > 24
    ? d.toLocaleString('pt-BR', { day: '2-digit', month: '2-digit', hour: '2-digit' }) + 'h'
    : d.toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' });
}

function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return 'nunca';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString('pt-BR', {
    day: '2-digit',
    month: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  });
}

/**
 * Histórico da coleta contínua via API: CPU, memória e banda WAN ao longo do tempo, estado da
 * sincronização automática e últimas mudanças de configuração detectadas.
 */
export function ResourceHistoryCard({ vendor, overview }: ResourceHistoryCardProps) {
  const [hours, setHours] = useState(24);
  const [samples, setSamples] = useState<MetricSample[]>([]);

  const siteId = overview.activeSite.id;
  const lastSyncAt = overview.appliance.lastSyncAt;

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const res = await fetch(vendorApiUrl(vendor, `/metrics?hours=${hours}`));
        if (res.ok && !cancelled) {
          const data = (await res.json()) as { samples: MetricSample[] };
          setSamples(data.samples || []);
        }
      } catch {
        // mantém o último conjunto exibido
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [vendor, siteId, hours, lastSyncAt]);

  const sync = overview.sync;
  const changes = overview.configChanges ?? [];
  const hasConnection = Boolean(overview.activeSite.connection.host);

  // Sem conexão de API e sem histórico não há o que mostrar
  if (!hasConnection && samples.length === 0 && changes.length === 0) return null;

  const autoSyncOn =
    Boolean(sync && sync.autoSyncMinutes > 0) && overview.activeSite.connection.hasSavedPassword;
  const failing = Boolean(sync?.lastError);

  const data = samples.map((s) => ({
    ts: s.ts,
    cpu: s.cpuPercent,
    mem: s.memoryPercent,
    rx: s.wanRxMbps,
    tx: s.wanTxMbps,
  }));

  return (
    <section
      aria-label="Histórico de recursos e coleta contínua"
      className="bg-white border border-[var(--fw-border)] rounded-lg p-4 space-y-3"
    >
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2 min-w-0">
          <Activity className="w-4 h-4 text-[var(--fw-accent)] shrink-0" aria-hidden="true" />
          <h2 className="text-sm font-semibold text-[var(--fw-heading)]">
            Coleta Contínua — Recursos e Banda WAN
          </h2>
        </div>
        <div className="flex items-center gap-1.5">
          {RANGES.map((r) => (
            <button
              key={r.hours}
              type="button"
              onClick={() => setHours(r.hours)}
              className={`px-2.5 py-1 rounded border text-xs font-medium ${
                hours === r.hours
                  ? 'bg-[var(--fw-accent)] text-white border-[var(--fw-accent)]'
                  : 'bg-white text-[var(--fw-text-body)] border-[var(--fw-border)] hover:bg-[var(--fw-bg)]'
              }`}
            >
              {r.label}
            </button>
          ))}
        </div>
      </div>

      <p className="text-xs text-[var(--fw-text-muted)] inline-flex flex-wrap items-center gap-1.5">
        {failing ? (
          <AlertTriangle className="w-3.5 h-3.5 text-red-700" aria-hidden="true" />
        ) : (
          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-700" aria-hidden="true" />
        )}
        {autoSyncOn
          ? `Sincronização automática a cada ${sync?.autoSyncMinutes} min`
          : 'Sincronização automática desligada (salve a credencial e defina o intervalo em Conexão)'}
        {' · '}última coleta com sucesso: {formatDateTime(lastSyncAt)}
        {failing && (
          <span className="text-red-700 font-medium">
            {' · '}
            {sync?.consecutiveFailures} falha(s) seguida(s): {sync?.lastError}
          </span>
        )}
      </p>

      {data.length < 2 ? (
        <p className="text-xs text-[var(--fw-text-muted)] bg-[var(--fw-surface)] border border-[var(--fw-border)] rounded-md px-4 py-3">
          Ainda não há amostras suficientes neste período. Cada sincronização com a API do
          firewall registra um ponto de CPU, memória, conexões e banda.
        </p>
      ) : (
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
          <div className="h-48">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={data} margin={{ top: 5, right: 12, left: -12, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--fw-border-soft)" />
                <XAxis
                  dataKey="ts"
                  tickFormatter={(v: string) => formatTick(v, hours)}
                  tick={{ fontSize: 10 }}
                  minTickGap={40}
                />
                <YAxis domain={[0, 100]} tick={{ fontSize: 10 }} unit="%" />
                <Tooltip labelFormatter={(v) => formatDateTime(String(v))} />
                <Legend wrapperStyle={{ fontSize: 11 }} />
                <Line type="monotone" dataKey="cpu" name="CPU" stroke="#B45309" dot={false} strokeWidth={2} connectNulls />
                <Line type="monotone" dataKey="mem" name="Memória" stroke="#1D4E89" dot={false} strokeWidth={2} connectNulls />
              </LineChart>
            </ResponsiveContainer>
          </div>
          <div className="h-48">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={data} margin={{ top: 5, right: 12, left: -12, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--fw-border-soft)" />
                <XAxis
                  dataKey="ts"
                  tickFormatter={(v: string) => formatTick(v, hours)}
                  tick={{ fontSize: 10 }}
                  minTickGap={40}
                />
                <YAxis tick={{ fontSize: 10 }} />
                <Tooltip
                  labelFormatter={(v) => formatDateTime(String(v))}
                  formatter={(value) => `${value} Mbps`}
                />
                <Legend wrapperStyle={{ fontSize: 11 }} />
                <Line type="monotone" dataKey="rx" name="WAN download (Mbps)" stroke="#047857" dot={false} strokeWidth={2} />
                <Line type="monotone" dataKey="tx" name="WAN upload (Mbps)" stroke="#7C3AED" dot={false} strokeWidth={2} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {changes.length > 0 && (
        <div className="border-t border-[var(--fw-border-soft)] pt-3 space-y-1.5">
          <p className="text-xs font-semibold text-[var(--fw-heading)] inline-flex items-center gap-1.5">
            <GitCompareArrows className="w-3.5 h-3.5 text-[var(--fw-accent)]" aria-hidden="true" />
            Mudanças de configuração detectadas entre coletas
          </p>
          <ul className="space-y-1 text-xs text-[var(--fw-text-body)]">
            {changes.slice(0, 5).map((c) => (
              <li key={c.at} className="flex flex-wrap gap-x-2">
                <span className="font-mono tabular-nums text-[var(--fw-text-subtle)]">
                  {formatDateTime(c.at)}
                </span>
                <span>
                  regras +{c.rulesAdded} / -{c.rulesRemoved} / ~{c.rulesModified} · NAT +{c.natsAdded} / -
                  {c.natsRemoved} / ~{c.natsModified}
                </span>
                <span className="text-[var(--fw-text-muted)]">{c.details.slice(0, 4).join(' · ')}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </section>
  );
}
