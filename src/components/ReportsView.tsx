import { useEffect, useState } from 'react';
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
import type { AuditReportData } from '../types.ts';
import { exportAuditReportPdf } from '../utils/exportAuditPdf.ts';

interface ReportsViewProps {
  refreshToken: number;
  onGoToConnect: () => void;
  onLoadSample: () => void;
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

export function ReportsView({
  refreshToken,
  onGoToConnect,
  onLoadSample,
}: ReportsViewProps) {
  const [report, setReport] = useState<AuditReportData | null>(null);
  const [loading, setLoading] = useState(true);
  const [copiedCli, setCopiedCli] = useState(false);
  const [exportingPdf, setExportingPdf] = useState(false);

  useEffect(() => {
    const loadReport = async () => {
      setLoading(true);
      try {
        const res = await fetch('/api/report');
        if (res.ok) {
          const data = (await res.json()) as AuditReportData;
          setReport(data);
        }
      } finally {
        setLoading(false);
      }
    };
    void loadReport();
  }, [refreshToken]);

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
        <div className="h-24 bg-white border border-[#D4E4D8] rounded-lg" />
        <div className="h-64 bg-white border border-[#D4E4D8] rounded-lg" />
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
      <div className="bg-white border border-[#D4E4D8] rounded-lg p-10 max-w-2xl">
        <h2 className="text-lg font-semibold text-[#123325]">
          Nenhum dado disponível para gerar o relatório
        </h2>
        <p className="text-xs text-[#456354] mt-2 leading-relaxed">
          Importe syslogs, conecte seu SonicWall ou carregue a amostra de demonstração para montar
          o relatório consolidado de segurança, regras sem uso e políticas NAT.
        </p>
        <div className="mt-5 flex flex-wrap gap-3">
          <button
            type="button"
            onClick={onGoToConnect}
            className="px-4 py-2 text-xs font-medium text-white bg-[#1E4D3B] rounded-md hover:bg-[#163A2C]"
          >
            Conectar ou Importar
          </button>
          <button
            type="button"
            onClick={onLoadSample}
            className="px-4 py-2 text-xs font-medium text-[#1D3B2E] bg-white border border-[#BFD5C5] rounded-md hover:bg-[#EDF5EF]"
          >
            Carregar Amostra TZ470
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
      <div className="no-print bg-white border border-[#D4E4D8] rounded-lg p-4 flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="text-sm font-semibold text-[#123325]">
            Relatório Consolidado de Auditoria SonicWall
          </h2>
          <p className="text-xs text-[#456354] mt-0.5 tabular-nums">
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
            className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-white bg-[#1E4D3B] rounded-md hover:bg-[#163A2C] disabled:opacity-50 whitespace-nowrap"
          >
            <FileDown className="w-3.5 h-3.5" />
            {exportingPdf ? 'Gerando PDF...' : 'Exportar PDF'}
          </button>
          <button
            type="button"
            onClick={() => window.print()}
            className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-[#1D3B2E] bg-white border border-[#BFD5C5] rounded-md hover:bg-[#EDF5EF] whitespace-nowrap"
          >
            <Printer className="w-3.5 h-3.5" />
            Imprimir
          </button>
          <a
            href="/api/report/download?format=html"
            className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-[#1D3B2E] bg-white border border-[#BFD5C5] rounded-md hover:bg-[#EDF5EF] whitespace-nowrap"
          >
            <Download className="w-3.5 h-3.5" />
            Baixar HTML
          </a>
          <a
            href="/api/report/download?format=md"
            className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-[#1D3B2E] bg-white border border-[#BFD5C5] rounded-md hover:bg-[#EDF5EF] whitespace-nowrap"
          >
            <FileText className="w-3.5 h-3.5" />
            Baixar Markdown
          </a>
          <a
            href="/api/report/download?format=json"
            className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-[#1D3B2E] bg-white border border-[#BFD5C5] rounded-md hover:bg-[#EDF5EF] whitespace-nowrap"
          >
            <Download className="w-3.5 h-3.5" />
            Exportar JSON
          </a>
        </div>
      </div>

      <div className="bg-white border border-[#D4E4D8] rounded-lg p-8 space-y-8">
        <div className="border-b border-[#D4E4D8] pb-6 flex flex-wrap items-start justify-between gap-4">
          <div>
            <p className="text-xs font-medium text-[#2A6B52]">Auditoria de Segurança e Higiene de Políticas</p>
            <h3 className="text-2xl font-semibold text-[#123325] mt-1">
              {overview.appliance.model}
            </h3>
            <p className="text-xs text-[#456354] mt-1 font-mono tabular-nums">
              Serial: {overview.appliance.serialNumber} · Host: {overview.appliance.host} · Firmware:{' '}
              {overview.appliance.firmware}
              {overview.appliance.romVersion ? ` · ROM: ${overview.appliance.romVersion}` : ''}
            </p>
            {(overview.appliance.uptimeFormatted ||
              overview.appliance.cpuPercent !== undefined ||
              overview.appliance.activeConnections !== undefined) && (
              <p className="text-xs text-[#456354] mt-1 font-mono tabular-nums">
                {overview.appliance.uptimeFormatted ? `Uptime: ${overview.appliance.uptimeFormatted}` : ''}
                {overview.appliance.cpuPercent !== undefined && overview.appliance.cpuPercent !== null
                  ? ` · CPU: ${overview.appliance.cpuPercent}%`
                  : ''}
                {overview.appliance.memoryPercent !== undefined && overview.appliance.memoryPercent !== null
                  ? ` · RAM: ${overview.appliance.memoryPercent}%`
                  : ''}
                {overview.appliance.activeConnections !== undefined && overview.appliance.activeConnections !== null
                  ? ` · Conexões: ${overview.appliance.activeConnections.toLocaleString('pt-BR')}${
                      overview.appliance.maxConnections
                        ? ` / ${overview.appliance.maxConnections.toLocaleString('pt-BR')}`
                        : ''
                    }`
                  : ''}
              </p>
            )}
          </div>
          <div className="text-right text-xs text-[#456354] tabular-nums">
            <p className="font-medium text-[#123325]">Janela de Retenção de Logs</p>
            <p className="mt-0.5">Expurgo automático: {overview.retention.retentionDays} dias</p>
            <p className="mt-0.5">
              Base local: {formatBytes(overview.retention.storeSizeBytes)}
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="p-4 bg-[#F4F8F5] border border-[#D4E4D8] rounded-md">
            <p className="text-xs text-[#456354]">Syslogs na Janela</p>
            <p className="text-2xl font-semibold font-mono tabular-nums text-[#123325] mt-1">
              {overview.totalSyslogs.toLocaleString('pt-BR')}
            </p>
            <p className="text-[11px] text-[#456354] mt-1 tabular-nums">
              {overview.syslogBreakdown.allow} permitidos · {overview.syslogBreakdown.blocked} bloqueados
            </p>
          </div>

          <div className="p-4 bg-[#F4F8F5] border border-[#D4E4D8] rounded-md">
            <p className="text-xs text-[#456354]">Regras para Revisão</p>
            <p className="text-2xl font-semibold font-mono tabular-nums text-amber-800 mt-1">
              {irregularRulesCount}
              <span className="text-sm font-normal text-[#5C7A6B]">
                {' '}
                / {overview.rulesSummary.total}
              </span>
            </p>
            <p className="text-[11px] text-[#456354] mt-1 tabular-nums">
              {overview.rulesSummary.unused} sem uso · {overview.rulesSummary.shadowed} sombreadas
            </p>
          </div>

          <div className="p-4 bg-[#F4F8F5] border border-[#D4E4D8] rounded-md">
            <p className="text-xs text-[#456354]">NATs para Revisão</p>
            <p className="text-2xl font-semibold font-mono tabular-nums text-amber-800 mt-1">
              {irregularNatsCount}
              <span className="text-sm font-normal text-[#5C7A6B]">
                {' '}
                / {overview.natsSummary.total}
              </span>
            </p>
            <p className="text-[11px] text-[#456354] mt-1 tabular-nums">
              {overview.natsSummary.unused} sem uso · {overview.natsSummary.orphaned} órfãs
            </p>
          </div>

          <div className="p-4 bg-[#F4F8F5] border border-[#D4E4D8] rounded-md">
            <p className="text-xs text-[#456354]">Achados Prioritários</p>
            <p className="text-2xl font-semibold font-mono tabular-nums text-[#123325] mt-1">
              {report.recommendations.length}
            </p>
            <p className="text-[11px] text-[#456354] mt-1">
              Ações recomendadas de limpeza
            </p>
          </div>
        </div>

        {(overview.telemetry?.interfaces?.length > 0 || overview.telemetry?.vpns?.length > 0) && (
          <section className="space-y-3">
            <h4 className="text-sm font-semibold text-[#123325] border-b border-[#E6F0E8] pb-2">
              00. Telemetria de Links, Interfaces e VPNs
            </h4>
            {overview.telemetry.interfaces.length > 0 && (
              <div className="overflow-x-auto border border-[#D4E4D8] rounded-md">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="bg-[#EDF5EF] text-[#244838] border-b border-[#D4E4D8]">
                      <th className="py-2 px-3 text-left font-medium">Interface</th>
                      <th className="py-2 px-3 text-left font-medium">Zona</th>
                      <th className="py-2 px-3 text-left font-medium">IP</th>
                      <th className="py-2 px-3 text-left font-medium">Link</th>
                      <th className="py-2 px-3 text-right font-medium">Download (Rx)</th>
                      <th className="py-2 px-3 text-right font-medium">Upload (Tx)</th>
                      <th className="py-2 px-3 text-right font-medium">Uso</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#E6F0E8]">
                    {overview.telemetry.interfaces.map((iface) => (
                      <tr key={iface.name}>
                        <td className="py-2 px-3 font-mono font-medium text-[#123325]">{iface.name}</td>
                        <td className="py-2 px-3 font-mono text-[#456354]">{iface.zone}</td>
                        <td className="py-2 px-3 font-mono text-[#456354]">{iface.ip}</td>
                        <td className="py-2 px-3 font-mono tabular-nums text-[#244838]">
                          {iface.linkStatus.toUpperCase()} ({iface.linkSpeedMbps} Mbps)
                        </td>
                        <td className="py-2 px-3 text-right font-mono tabular-nums text-[#123325]">
                          {iface.rxMbps.toFixed(1)} Mbps
                        </td>
                        <td className="py-2 px-3 text-right font-mono tabular-nums text-[#123325]">
                          {iface.txMbps.toFixed(1)} Mbps
                        </td>
                        <td className="py-2 px-3 text-right font-mono tabular-nums font-semibold text-[#1E4D3B]">
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
          <h4 className="text-sm font-semibold text-[#123325] border-b border-[#E6F0E8] pb-2">
            01. Plano de Ação e Recomendações
          </h4>
          {report.recommendations.length === 0 ? (
            <p className="text-xs text-[#456354]">
              Nenhuma irregularidade encontrada nas regras, NATs ou syslogs avaliados.
            </p>
          ) : (
            <div className="divide-y divide-[#E6F0E8] border border-[#D4E4D8] rounded-md">
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
                      <span className="text-[#94B09F]" aria-hidden="true">
                        ·
                      </span>
                      <span className="font-semibold text-[#123325]">{rec.title}</span>
                    </div>
                    <p className="text-[#456354]">{rec.detail}</p>
                  </div>
                  <span className="font-mono tabular-nums text-[#123325] font-medium whitespace-nowrap">
                    {rec.affectedCount} item(ns)
                  </span>
                </div>
              ))}
            </div>
          )}
        </section>

        <section className="space-y-3">
          <h4 className="text-sm font-semibold text-[#123325] border-b border-[#E6F0E8] pb-2">
            02. Inventário de Regras de Firewall ({report.rules.length})
          </h4>
          {report.rules.length === 0 ? (
            <p className="text-xs text-[#456354]">Nenhuma regra carregada.</p>
          ) : (
            <div className="overflow-x-auto border border-[#D4E4D8] rounded-md">
              <table className="w-full text-xs">
                <thead>
                  <tr className="bg-[#EDF5EF] text-[#244838] border-b border-[#D4E4D8]">
                    <th className="py-2 px-3 text-left font-medium">ID</th>
                    <th className="py-2 px-3 text-left font-medium">Nome</th>
                    <th className="py-2 px-3 text-left font-medium">Zonas</th>
                    <th className="py-2 px-3 text-left font-medium">Origem → Destino</th>
                    <th className="py-2 px-3 text-right font-medium">SonicOS</th>
                    <th className="py-2 px-3 text-right font-medium">Syslog</th>
                    <th className="py-2 px-3 text-left font-medium">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#E6F0E8]">
                  {report.rules.map((r) => (
                    <tr key={r.id}>
                      <td className="py-2 px-3 font-mono text-[#123325]">{r.id}</td>
                      <td className="py-2 px-3 text-[#123325] font-medium">{r.name}</td>
                      <td className="py-2 px-3 font-mono text-[#456354]">
                        {r.fromZone} → {r.toZone}
                      </td>
                      <td className="py-2 px-3 font-mono text-[#456354]">
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
          <h4 className="text-sm font-semibold text-[#123325] border-b border-[#E6F0E8] pb-2">
            03. Inventário de Políticas NAT ({report.nats.length})
          </h4>
          {report.nats.length === 0 ? (
            <p className="text-xs text-[#456354]">Nenhuma política NAT carregada.</p>
          ) : (
            <div className="overflow-x-auto border border-[#D4E4D8] rounded-md">
              <table className="w-full text-xs">
                <thead>
                  <tr className="bg-[#EDF5EF] text-[#244838] border-b border-[#D4E4D8]">
                    <th className="py-2 px-3 text-left font-medium">ID</th>
                    <th className="py-2 px-3 text-left font-medium">Nome</th>
                    <th className="py-2 px-3 text-left font-medium">Interfaces</th>
                    <th className="py-2 px-3 text-left font-medium">Destino (Orig → Trad)</th>
                    <th className="py-2 px-3 text-right font-medium">SonicOS</th>
                    <th className="py-2 px-3 text-right font-medium">Syslog</th>
                    <th className="py-2 px-3 text-left font-medium">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#E6F0E8]">
                  {report.nats.map((n) => (
                    <tr key={n.id}>
                      <td className="py-2 px-3 font-mono text-[#123325]">{n.id}</td>
                      <td className="py-2 px-3 text-[#123325] font-medium">{n.name}</td>
                      <td className="py-2 px-3 font-mono text-[#456354]">
                        {n.inboundInterface} → {n.outboundInterface}
                      </td>
                      <td className="py-2 px-3 font-mono text-[#456354]">
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
          <div className="flex items-center justify-between border-b border-[#E6F0E8] pb-2">
            <h4 className="text-sm font-semibold text-[#123325]">
              04. Script Consolidado SonicOS CLI (Desabilitação Segura)
            </h4>
            <button
              type="button"
              onClick={() => void handleCopyCli()}
              className="no-print inline-flex items-center gap-1.5 text-xs font-medium text-[#1E4D3B] hover:underline"
            >
              {copiedCli ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
              {copiedCli ? 'Copiado' : 'Copiar script'}
            </button>
          </div>
          <pre className="p-4 bg-[#0E221A] text-[#E6F2EB] rounded-md font-mono text-[11px] overflow-x-auto leading-5">
            {report.cliDisableScript}
          </pre>
        </section>
      </div>
    </div>
  );
}
