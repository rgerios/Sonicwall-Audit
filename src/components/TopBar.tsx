import { Database, Upload } from 'lucide-react';
import type { ActiveSection, FirewallVendor } from '../types.ts';
import { VENDOR_THEMES } from '../utils/vendorTheme.ts';

interface TopBarProps {
  vendor: FirewallVendor;
  activeSection: ActiveSection;
  activeSiteName?: string;
  onLoadSample: () => void;
  onGoToConnect: () => void;
  loadingSample: boolean;
}

export function TopBar({
  vendor,
  activeSection,
  activeSiteName,
  onLoadSample,
  onGoToConnect,
  loadingSample,
}: TopBarProps) {
  const theme = VENDOR_THEMES[vendor];

  const sectionLabels: Record<ActiveSection, string> = {
    overview: 'Visão Geral',
    syslogs: 'Análise de Syslogs',
    rules: 'Regras de Firewall Sem Uso',
    nats: vendor === 'fortigate' ? 'VIPs, IP Pools & NAT Sem Uso' : 'Políticas NAT Sem Uso',
    reports: 'Relatório Consolidado',
    ai: 'Análise Humana com IA',
    connect: 'Localidades, Conexão e Linux',
  };

  return (
    <header className="h-16 bg-white border-b border-[var(--fw-border)] px-6 flex items-center justify-between gap-8 shrink-0">
      <div className="flex items-center gap-2 text-sm min-w-0">
        <span className="text-[var(--fw-text-muted)] whitespace-nowrap shrink-0">FW Audit</span>
        <span className="text-[var(--fw-text-faint)]" aria-hidden="true">
          /
        </span>
        <span className="font-medium text-[var(--fw-accent)] whitespace-nowrap shrink-0">
          {theme.label}
        </span>
        <span className="text-[var(--fw-text-faint)]" aria-hidden="true">
          /
        </span>
        <h1 className="font-semibold text-[var(--fw-heading)] truncate">
          {sectionLabels[activeSection]}
        </h1>
        {activeSiteName && (
          <>
            <span className="text-[var(--fw-text-faint)] hidden sm:inline" aria-hidden="true">
              ·
            </span>
            <span className="text-xs font-medium text-[var(--fw-accent-mid)] truncate hidden sm:inline">
              {activeSiteName}
            </span>
          </>
        )}
      </div>

      <div className="flex items-center gap-3 shrink-0">
        <button
          type="button"
          onClick={onLoadSample}
          disabled={loadingSample}
          className="inline-flex items-center gap-2 px-4 py-2 text-xs font-medium text-[var(--fw-text-body)] bg-[var(--fw-bg)] border border-[var(--fw-border-strong)] rounded-md hover:bg-[var(--fw-surface)] transition-colors whitespace-nowrap shrink-0 disabled:opacity-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--fw-accent-mid)]"
        >
          <Database className="w-3.5 h-3.5" aria-hidden="true" />
          {loadingSample ? 'Carregando...' : theme.sampleButtonLabel}
        </button>
        <button
          type="button"
          onClick={onGoToConnect}
          className="inline-flex items-center gap-2 px-4 py-2 text-xs font-medium text-white bg-[var(--fw-accent)] rounded-md hover:bg-[var(--fw-accent-hover)] transition-colors whitespace-nowrap shrink-0 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--fw-accent-mid)]"
        >
          <Upload className="w-3.5 h-3.5" aria-hidden="true" />
          Conectar ou Importar
        </button>
      </div>
    </header>
  );
}
