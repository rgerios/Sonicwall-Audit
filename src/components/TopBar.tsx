import { Database, Upload } from 'lucide-react';
import type { ActiveSection } from '../types.ts';

interface TopBarProps {
  activeSection: ActiveSection;
  activeSiteName?: string;
  onLoadSample: () => void;
  onGoToConnect: () => void;
  loadingSample: boolean;
}

const SECTION_LABELS: Record<ActiveSection, string> = {
  overview: 'Visão Geral',
  syslogs: 'Análise de Syslogs',
  rules: 'Regras de Firewall Sem Uso',
  nats: 'Políticas NAT Sem Uso',
  reports: 'Relatório Consolidado',
  ai: 'Análise Humana com IA',
  connect: 'Localidades, Conexão e Linux',
};

export function TopBar({
  activeSection,
  activeSiteName,
  onLoadSample,
  onGoToConnect,
  loadingSample,
}: TopBarProps) {
  return (
    <header className="h-16 bg-white border-b border-[#D4E4D8] px-6 flex items-center justify-between gap-8 shrink-0">
      <div className="flex items-center gap-2 text-sm min-w-0">
        <span className="text-[#4B6B5C] whitespace-nowrap shrink-0">SonicAudit</span>
        <span className="text-[#94B09F]" aria-hidden="true">
          /
        </span>
        <h1 className="font-semibold text-[#123325] truncate">{SECTION_LABELS[activeSection]}</h1>
        {activeSiteName && (
          <>
            <span className="text-[#94B09F] hidden sm:inline" aria-hidden="true">
              ·
            </span>
            <span className="text-xs font-medium text-[#2A6B52] truncate hidden sm:inline">
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
          className="inline-flex items-center gap-2 px-4 py-2 text-xs font-medium text-[#1D3B2E] bg-[#F4F8F5] border border-[#BFD5C5] rounded-md hover:bg-[#E7F2EA] transition-colors whitespace-nowrap shrink-0 disabled:opacity-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#2A6B52]"
        >
          <Database className="w-3.5 h-3.5" aria-hidden="true" />
          {loadingSample ? 'Carregando...' : 'Carregar Amostra TZ470'}
        </button>
        <button
          type="button"
          onClick={onGoToConnect}
          className="inline-flex items-center gap-2 px-4 py-2 text-xs font-medium text-white bg-[#1E4D3B] rounded-md hover:bg-[#163A2C] transition-colors whitespace-nowrap shrink-0 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#2A6B52]"
        >
          <Upload className="w-3.5 h-3.5" aria-hidden="true" />
          Conectar ou Importar
        </button>
      </div>
    </header>
  );
}
