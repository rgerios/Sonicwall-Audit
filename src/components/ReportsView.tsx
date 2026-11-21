import { useEffect, useState } from 'react';
import { AccessReportView } from './AccessReportView.tsx';
import {
  AlertTriangle,
  Ban,
  Check,
  CheckCircle2,
  Copy,
  Download,
  FileDown,
  FileText,
  Printer,
  ShieldAlert,
} from 'lucide-react';
import type { AuditReportData, FirewallVendor } from '../types.ts';
import { exportAuditReportPdf } from '../utils/exportAuditPdf.ts';
import { vendorApiUrl } from '../utils/vendorApi.ts';
import { VENDOR_THEMES } from '../utils/vendorTheme.ts';

interface ReportsViewProps {
  vendor: FirewallVendor;
  refreshToken: number;
  onGoToConnect: () => void;
  onLoadSample: () => void;
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function AuditReportView({
  vendor,
  refreshToken,
  onGoToConnect,
  onLoadSample,
}: ReportsViewProps) {
  const theme = VENDOR_THEMES[vendor];
  const [report, setReport] = useState<AuditReportData | null>(null);
  const [loading, setLoading] = useState(true);
  const [copiedCli, setCopiedCli] = useState(false);
  const [exportingPdf, setExportingPdf] = useState(false);

  useEffect(() => {
    const loadReport = async () => {
      setLoading(true);
      try {
        const res = await fetch(vendorApiUrl(vendor, '/report'));
        if (res.ok) {
          const data = (await res.json()) as AuditReportData;
          setReport(data);
        }
      } finally {
        setLoading(false);
      }
    };
    void loadReport();
  }, [vendor, refreshToken]);

  const handleCopyCli = async () => {
    if (!report) return;
    try {
      await navigator.clipboard.writeText(report.cliDisableScript);
      setCopiedCli(true);
      setTimeout(() => setCopiedCli(false), 1800);
    } catch {
      // Clipboard ignored
    }
  };

  if (loading && !report) {
    return (
      <div className="space-y-4 animate-pulse">
        <div className="h-24 bg-white border border-[var(--fw-border)] rounded-lg" />
        <div className="h-64 bg-white border border-[var(--fw-border)] rounded-lg" />
      </div>
    );
  }

  const hasData =
    report &&
    (report.overview.totalSyslogs > 0 ||
      report.rules.length > 0 ||
      report.nats.length > 0);

  if (!report || !hasData) {
    return (
      <div className="bg-white border border-[var(--fw-border)] rounded-lg p-10 max-w-2xl">
        <h2 className="text-lg font-semibold text-[var(--fw-heading)]">
          Nenhum dado {theme.label} disponível para gerar o relatório
        </h2>
        <p className="text-xs text-[var(--fw-text-muted)] mt-2 leading-relaxed">
          Importe syslogs, conecte seu {theme.label} ou carregue a amostra de demonstração para
          montar o relatório consolidado de segurança, regras sem uso e políticas NAT.
        </p>
        <div className="mt-5 flex flex-wrap gap-3">
          <button
            type="button"
            onClick={onGoToConnect}
            className="px-4 py-2 text-xs font-medium text-white bg-[var(--fw-accent)] rounded-md hover:bg-[var(--fw-accent-hover)]"
          >
            Conectar ou Importar
          </button>
          <button
            type="button"
            onClick={onLoadSample}
            className="px-4 py-2 text-xs font-medium text-[var(--fw-text-body)] bg-white border border-[var(--fw-border-strong)] rounded-md hover:bg-[var(--fw-surface)]"
          >
            {theme.sampleButtonLabel}
          </button>
        </div>
      </div>
    );
  }

  const { overview } = report;
  const irregularRulesCount =
    overview.rulesSummary.unused +
    overview.rulesSummary.shadowed +
    overview.rulesSummary.disabled +
    overview.rulesSummary.overpermissive;
  const irregularNatsCount =
    overview.natsSummary.unused +
    overview.natsSummary.orphaned +
    overview.natsSummary.disabled;

  return (
    <div className="space-y-6">
      <div className="no-print bg-white border border-[var(--fw-border)] rounded-lg p-4 flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="text-sm font-semibold text-[var(--fw-heading)]">
            Relatório Consolidado de Auditoria {theme.label}
          </h2>
          <p className="text-xs text-[var(--fw-text-muted)] mt-0.5 tabular-nums">
            Gerado em {new Date(report.generatedAt).toLocaleString('pt-BR')} · Retenção configurada:{' '}
            {overview.retention.retentionDays} dias ({formatBytes(overview.retention.storeSizeBytes)})
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            disabled={exportingPdf}
            onClick={() => {
              setExportingPdf(true);
              try {
                exportAuditReportPdf(report);
              } finally {
                setExportingPdf(false);
              }
            }}
            className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-white bg-[var(--fw-accent)] rounded-md hover:bg-[var(--fw-accent-hover)] disabled:opacity-50 whitespace-nowrap"
          >
            <FileDown className="w-3.5 h-3.5" />
            {exportingPdf ? 'Gerando PDF...' : 'Exportar PDF'}
          </button>
          <button
            type="button"
            onClick={() => window.print()}
            className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-[var(--fw-text-body)] bg-white border border-[var(--fw-border-strong)] rounded-md hover:bg-[var(--fw-surface)] whitespace-nowrap"
          >
            <Printer className="w-3.5 h-3.5" />
            Imprimir
          </button>
          <a
            href={vendorApiUrl(vendor, '/report/download?format=html')}
            className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-[var(--fw-text-body)] bg-white border border-[var(--fw-border-strong)] rounded-md hover:bg-[var(--fw-surface)] whitespace-nowrap"
          >
            <Download className="w-3.5 h-3.5" />
            Baixar HTML
          </a>
          <a
            href={vendorApiUrl(vendor, '/report/download?format=md')}
            className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-[var(--fw-text-body)] bg-white border border-[var(--fw-border-strong)] rounded-md hover:bg-[var(--fw-surface)] whitespace-nowrap"
          >
            <FileText className="w-3.5 h-3.5" />
            Baixar Markdown
          </a>
          <a
            href={vendorApiUrl(vendor, '/report/download?format=json')}
            className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-[var(--fw-text-body)] bg-white border border-[var(--fw-border-strong)] rounded-md hover:bg-[var(--fw-surface)] whitespace-nowrap"
          >
            <Download className="w-3.5 h-3.5" />
            Exportar JSON
          </a>
        </div>
      </div>

      <div className="bg-white border border-[var(--fw-border)] rounded-lg p-8 space-y-8">
        <div className="border-b border-[var(--fw-border)] pb-6 flex flex-wrap items-start justify-between gap-4">
          <div>
            <p className="text-xs font-medium text-[var(--fw-accent)]">
              FW Audit · Auditoria de Segurança {theme.label} ({theme.platformSubtitle})
            </p>
            <h3 className="text-2xl font-semibold text-[var(--fw-heading)] mt-1">
              {overview.appliance.model}
            </h3>
            <p className="text-xs text-[var(--fw-text-muted)] mt-1 font-mono tabular-nums">
              Serial: {overview.appliance.serialNumber} · Host: {overview.appliance.host} · Firmware:{' '}
              {overview.appliance.firmware}
              {overview.appliance.romVersion ? ` · ROM: ${overview.appliance.romVersion}` : ''}
            </p>
            {(overview.appliance.uptimeFormatted ||
              overview.appliance.cpuPercent !== undefined ||
              overview.appliance.activeConnections !== undefined) && (
              <p className="text-xs text-[var(--fw-text-muted)] mt-1 font-mono tabular-nums">
                {overview.appliance.uptimeFormatted ? `Uptime: ${overview.appliance.uptimeFormatted}` : ''}
                {overview.appliance.cpuPercent !== undefined && overview.appliance.cpuPercent !== null
                  ? ` · CPU: ${overview.appliance.cpuPercent}%`
                  : ''}
                {overview.appliance.memoryPercent !== undefined &&
                overview.appliance.memoryPercent !== null
                  ? ` · RAM: ${overview.appliance.memoryPercent}%`
                  : ''}
                {overview.appliance.activeConnections !== undefined &&
                overview.appliance.activeConnections !== null
                  ? ` · Conexões: ${overview.appliance.activeConnections.toLocaleString('pt-BR')}${
                      overview.appliance.maxConnections
                        ? ` / ${overview.appliance.maxConnections.toLocaleString('pt-BR')}`
                        : ''
                    }`
                  : ''}
              </p>
            )}
          </div>
          <div className="text-right text-xs text-[var(--fw-text-muted)] tabular-nums">
            <p className="font-medium text-[var(--fw-heading)]">Janela de Retenção de Logs</p>
            <p className="mt-0.5">Expurgo automático: {overview.retention.retentionDays} dias</p>
            <p className="mt-0.5">Base local: {formatBytes(overview.retention.storeSizeBytes)}</p>
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="p-4 bg-[var(--fw-bg)] border border-[var(--fw-border)] rounded-md">
            <p className="text-xs text-[var(--fw-text-muted)]">Syslogs na Janela</p>
            <p className="text-2xl font-semibold font-mono tabular-nums text-[var(--fw-heading)] mt-1">
              {overview.totalSyslogs.toLocaleString('pt-BR')}
            </p>
            <p className="text-[11px] text-[var(--fw-text-muted)] mt-1 tabular-nums">
              {overview.syslogBreakdown.allow} permitidos · {overview.syslogBreakdown.blocked}{' '}
              bloqueados
            </p>
          </div>

          <div className="p-4 bg-[var(--fw-bg)] border border-[var(--fw-border)] rounded-md">
            <p className="text-xs text-[var(--fw-text-muted)]">Regras para Revisão</p>
            <p className="text-2xl font-semibold font-mono tabular-nums text-amber-800 mt-1">
              {irregularRulesCount}
              <span className="text-sm font-normal text-[var(--fw-text-subtle)]">
                {' '}
                / {overview.rulesSummary.total}
              </span>
            </p>
            <p className="text-[11px] text-[var(--fw-text-muted)] mt-1 tabular-nums">
              {overview.rulesSummary.unused} sem uso · {overview.rulesSummary.shadowed} sombreadas
            </p>
          </div>

          <div className="p-4 bg-[var(--fw-bg)] border border-[var(--fw-border)] rounded-md">
            <p className="text-xs text-[var(--fw-text-muted)]">
              {vendor === 'fortigate' ? 'VIPs / NATs para Revisão' : 'NATs para Revisão'}
            </p>
            <p className="text-2xl font-semibold font-mono tabular-nums text-amber-800 mt-1">
              {irregularNatsCount}
              <span className="text-sm font-normal text-[var(--fw-text-subtle)]">
                {' '}
                / {overview.natsSummary.total}
              </span>
            </p>
            <p className="text-[11px] text-[var(--fw-text-muted)] mt-1 tabular-nums">
              {overview.natsSummary.unused} sem uso · {overview.natsSummary.orphaned} órfãs
            </p>
          </div>

          <div className="p-4 bg-[var(--fw-bg)] border border-[var(--fw-border)] rounded-md">
            <p className="text-xs text-[var(--fw-text-muted)]">Achados Prioritários</p>
            <p className="text-2xl font-semibold font-mono tabular-nums text-[var(--fw-heading)] mt-1">
              {report.recommendations.length}
            </p>
            <p className="text-[11px] text-[var(--fw-text-muted)] mt-1">
              Ações recomendadas de limpeza
            </p>
          </div>
        </div>

        {(overview.telemetry?.interfaces?.length > 0 || overview.telemetry?.vpns?.length > 0) && (
          <section className="space-y-3">
            <h4 className="text-sm font-semibold text-[var(--fw-heading)] border-b border-[var(--fw-border-soft)] pb-2">
              00. Telemetria de Links, Interfaces e VPNs
            </h4>
            {overview.telemetry.interfaces.length > 0 && (
              <div className="overflow-x-auto border border-[var(--fw-border)] rounded-md">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="bg-[var(--fw-surface)] text-[var(--fw-text-body)] border-b border-[var(--fw-border)]">
                      <th className="py-2 px-3 text-left font-medium">Interface</th>
                      <th className="py-2 px-3 text-left font-medium">Zona</th>
                      <th className="py-2 px-3 text-left font-medium">IP</th>
                      <th className="py-2 px-3 text-left font-medium">Link</th>
                      <th className="py-2 px-3 text-right font-medium">Download (Rx)</th>
                      <th className="py-2 px-3 text-right font-medium">Upload (Tx)</th>
                      <th className="py-2 px-3 text-right font-medium">Uso</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[var(--fw-border-soft)]">
                    {overview.telemetry.interfaces.map((iface) => (
                      <tr key={iface.name}>
                        <td className="py-2 px-3 font-mono font-medium text-[var(--fw-heading)]">
                          {iface.name}
                        </td>
                        <td className="py-2 px-3 font-mono text-[var(--fw-text-muted)]">
                          {iface.zone}
                        </td>
                        <td className="py-2 px-3 font-mono text-[var(--fw-text-muted)]">
                          {iface.ip}
                        </td>
                        <td className="py-2 px-3 font-mono tabular-nums text-[var(--fw-text-body)]">
                          {iface.linkStatus.toUpperCase()} ({iface.linkSpeedMbps} Mbps)
                        </td>
                        <td className="py-2 px-3 text-right font-mono tabular-nums text-[var(--fw-heading)]">
                          {iface.rxMbps.toFixed(1)} Mbps
                        </td>
                        <td className="py-2 px-3 text-right font-mono tabular-nums text-[var(--fw-heading)]">
                          {iface.txMbps.toFixed(1)} Mbps
                        </td>
                        <td className="py-2 px-3 text-right font-mono tabular-nums font-semibold text-[var(--fw-accent)]">
                          {iface.utilizationPercent.toFixed(1)}%
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        )}

        <section className="space-y-3">
          <h4 className="text-sm font-semibold text-[var(--fw-heading)] border-b border-[var(--fw-border-soft)] pb-2">
            01. Plano de Ação e Recomendações
          </h4>
          {report.recommendations.length === 0 ? (
            <p className="text-xs text-[var(--fw-text-muted)]">
              Nenhuma irregularidade encontrada nas regras, NATs ou syslogs avaliados.
            </p>
          ) : (
            <div className="divide-y divide-[var(--fw-border-soft)] border border-[var(--fw-border)] rounded-md">
              {report.recommendations.map((rec, idx) => (
                <div key={idx} className="p-4 flex items-start justify-between gap-4 text-xs">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      {rec.severity === 'high' ? (
                        <span className="inline-flex items-center gap-1 text-red-700 font-semibold">
                          <Ban className="w-3.5 h-3.5" /> Alta
                        </span>
                      ) : rec.severity === 'medium' ? (
                        <span className="inline-flex items-center gap-1 text-amber-800 font-semibold">
                          <AlertTriangle className="w-3.5 h-3.5" /> Média
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-emerald-800 font-semibold">
                          <ShieldAlert className="w-3.5 h-3.5" /> Baixa
                        </span>
                      )}
                      <span className="text-[var(--fw-text-faint)]" aria-hidden="true">
                        ·
                      </span>
                      <span className="font-semibold text-[var(--fw-heading)]">{rec.title}</span>
                    </div>
                    <p className="text-[var(--fw-text-muted)]">{rec.detail}</p>
                  </div>
                  <span className="font-mono tabular-nums text-[var(--fw-heading)] font-medium whitespace-nowrap">
                    {rec.affectedCount} item(ns)
                  </span>
                </div>
              ))}
            </div>
          )}
        </section>

        <section className="space-y-3">
          <h4 className="text-sm font-semibold text-[var(--fw-heading)] border-b border-[var(--fw-border-soft)] pb-2">
            02. Inventário de Regras de Firewall ({report.rules.length})
          </h4>
          {report.rules.length === 0 ? (
            <p className="text-xs text-[var(--fw-text-muted)]">Nenhuma regra carregada.</p>
          ) : (
            <div className="overflow-x-auto border border-[var(--fw-border)] rounded-md">
              <table className="w-full text-xs">
                <thead>
                  <tr className="bg-[var(--fw-surface)] text-[var(--fw-text-body)] border-b border-[var(--fw-border)]">
                    <th className="py-2 px-3 text-left font-medium">ID</th>
                    <th className="py-2 px-3 text-left font-medium">Nome</th>
                    <th className="py-2 px-3 text-left font-medium">Zonas</th>
                    <th className="py-2 px-3 text-left font-medium">Origem → Destino</th>
                    <th className="py-2 px-3 text-right font-medium">
                      {vendor === 'fortigate' ? 'FortiOS' : 'SonicOS'}
                    </th>
                    <th className="py-2 px-3 text-right font-medium">Syslog</th>
                    <th className="py-2 px-3 text-left font-medium">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[var(--fw-border-soft)]">
                  {report.rules.map((r) => (
                    <tr key={r.id}>
                      <td className="py-2 px-3 font-mono text-[var(--fw-heading)]">{r.id}</td>
                      <td className="py-2 px-3 text-[var(--fw-heading)] font-medium">{r.name}</td>
                      <td className="py-2 px-3 font-mono text-[var(--fw-text-muted)]">
                        {r.fromZone} → {r.toZone}
                      </td>
                      <td className="py-2 px-3 font-mono text-[var(--fw-text-muted)]">
                        {r.source} → {r.destination} ({r.service})
                      </td>
                      <td className="py-2 px-3 text-right font-mono tabular-nums">
                        {r.applianceHits.toLocaleString('pt-BR')}
                      </td>
                      <td className="py-2 px-3 text-right font-mono tabular-nums">
                        {r.syslogHits.toLocaleString('pt-BR')}
                      </td>
                      <td className="py-2 px-3">
                        {r.status === 'active' ? (
                          <span className="inline-flex items-center gap-1 text-emerald-800 font-medium">
                            <CheckCircle2 className="w-3.5 h-3.5" /> Ativa
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 text-amber-800 font-medium">
                            <AlertTriangle className="w-3.5 h-3.5" /> {r.status}
                          </span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        <section className="space-y-3">
          <h4 className="text-sm font-semibold text-[var(--fw-heading)] border-b border-[var(--fw-border-soft)] pb-2">
            03. Inventário de {vendor === 'fortigate' ? 'VIPs, IP Pools & NAT' : 'Políticas NAT'} (
            {report.nats.length})
          </h4>
          {report.nats.length === 0 ? (
            <p className="text-xs text-[var(--fw-text-muted)]">Nenhuma política NAT carregada.</p>
          ) : (
            <div className="overflow-x-auto border border-[var(--fw-border)] rounded-md">
              <table className="w-full text-xs">
                <thead>
                  <tr className="bg-[var(--fw-surface)] text-[var(--fw-text-body)] border-b border-[var(--fw-border)]">
                    <th className="py-2 px-3 text-left font-medium">ID</th>
                    <th className="py-2 px-3 text-left font-medium">Nome</th>
                    <th className="py-2 px-3 text-left font-medium">Interfaces</th>
                    <th className="py-2 px-3 text-left font-medium">Destino (Orig → Trad)</th>
                    <th className="py-2 px-3 text-right font-medium">
                      {vendor === 'fortigate' ? 'FortiOS' : 'SonicOS'}
                    </th>
                    <th className="py-2 px-3 text-right font-medium">Syslog</th>
                    <th className="py-2 px-3 text-left font-medium">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[var(--fw-border-soft)]">
                  {report.nats.map((n) => (
                    <tr key={n.id}>
                      <td className="py-2 px-3 font-mono text-[var(--fw-heading)]">{n.id}</td>
                      <td className="py-2 px-3 text-[var(--fw-heading)] font-medium">{n.name}</td>
                      <td className="py-2 px-3 font-mono text-[var(--fw-text-muted)]">
                        {n.inboundInterface} → {n.outboundInterface}
                      </td>
                      <td className="py-2 px-3 font-mono text-[var(--fw-text-muted)]">
                        {n.origDestination} → {n.transDestination}
                      </td>
                      <td className="py-2 px-3 text-right font-mono tabular-nums">
                        {n.applianceHits.toLocaleString('pt-BR')}
                      </td>
                      <td className="py-2 px-3 text-right font-mono tabular-nums">
                        {n.syslogHits.toLocaleString('pt-BR')}
                      </td>
                      <td className="py-2 px-3">
                        {n.status === 'active' ? (
                          <span className="inline-flex items-center gap-1 text-emerald-800 font-medium">
                            <CheckCircle2 className="w-3.5 h-3.5" /> Ativa
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 text-amber-800 font-medium">
                            <AlertTriangle className="w-3.5 h-3.5" /> {n.status}
                          </span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        <section className="space-y-3">
          <div className="flex items-center justify-between border-b border-[var(--fw-border-soft)] pb-2">
            <h4 className="text-sm font-semibold text-[var(--fw-heading)]">
              04. Script Consolidado {theme.cliName} (Desabilitação Segura)
            </h4>
            <button
              type="button"
              onClick={() => void handleCopyCli()}
              className="no-print inline-flex items-center gap-1.5 text-xs font-medium text-[var(--fw-accent)] hover:underline"
            >
              {copiedCli ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
              {copiedCli ? 'Copiado' : 'Copiar script'}
            </button>
          </div>
          <pre className="p-4 bg-[var(--fw-terminal-bg)] text-[var(--fw-terminal-text)] rounded-md font-mono text-[11px] overflow-x-auto leading-5">
            {report.cliDisableScript}
          </pre>
        </section>
      </div>
    </div>
  );
}

/** SonicWall: relatório de Auditoria + relatório de Acessos e Consumo (FortiGate continua só com Auditoria). */
export function ReportsView(props: ReportsViewProps) {
  const [tab, setTab] = useState<'audit' | 'access'>('audit');
  if (props.vendor !== 'sonicwall') return <AuditReportView {...props} />;
  return (
    <div className="space-y-4">
      <div className="no-print inline-flex p-1 bg-[var(--fw-surface-alt)] rounded-lg" role="tablist" aria-label="Tipo de relatório">
        {(
          [
            { id: 'audit', label: 'Auditoria', hint: 'regras, NAT e segurança' },
            { id: 'access', label: 'Acessos e Consumo', hint: 'IPs, categorias, países e banda' },
          ] as const
        ).map((x) => (
          <button
            key={x.id}
            type="button"
            role="tab"
            aria-selected={tab === x.id}
            onClick={() => setTab(x.id)}
            className={`px-4 py-2 text-sm font-semibold rounded-md transition-colors ${
              tab === x.id ? 'bg-white text-[var(--fw-heading)] shadow-xs' : 'text-[var(--fw-text-muted)] hover:text-[var(--fw-heading)]'
            }`}
          >
            {x.label}
            <span className="ml-2 text-[11px] font-normal text-[var(--fw-text-subtle)] hidden sm:inline">{x.hint}</span>
          </button>
        ))}
      </div>
      {tab === 'audit' ? <AuditReportView {...props} /> : <AccessReportView vendor={props.vendor} refreshToken={props.refreshToken} />}
    </div>
  );
}
