import { useEffect, useMemo, useState } from 'react';
import {
  AlertTriangle,
  Ban,
  CheckCircle2,
  Download,
  Search,
  ShieldAlert,
  TerminalSquare,
} from 'lucide-react';
import type { FirewallRule } from '../types.ts';
import { CliScriptModal } from './CliScriptModal.tsx';

interface UnusedRulesViewProps {
  refreshToken: number;
  onGoToConnect: () => void;
}

type RuleFilter = 'flagged' | 'all' | 'unused' | 'shadowed' | 'disabled' | 'overpermissive';

export function UnusedRulesView({ refreshToken, onGoToConnect }: UnusedRulesViewProps) {
  const [rules, setRules] = useState<FirewallRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState<RuleFilter>('flagged');
  const [query, setQuery] = useState('');
  const [selectedIds, setSelectedIds] = useState<string[]>([]);

  const [cliModal, setCliModal] = useState<{
    script: string;
    mode: 'disable' | 'delete';
  } | null>(null);

  useEffect(() => {
    const load = async () => {
      setLoading(true);
      try {
        const res = await fetch('/api/rules');
        if (res.ok) {
          const data = await res.json();
          setRules(data.rules || []);
        }
      } finally {
        setLoading(false);
      }
    };
    void load();
  }, [refreshToken]);

  const filteredRules = useMemo(() => {
    return rules.filter((r) => {
      if (filter === 'flagged' && r.status === 'active') return false;
      if (filter !== 'flagged' && filter !== 'all' && r.status !== filter) return false;
      if (query.trim()) {
        const q = query.trim().toLowerCase();
        const hay = `${r.id} ${r.name} ${r.fromZone} ${r.toZone} ${r.source} ${r.destination} ${r.service} ${r.comment}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [rules, filter, query]);

  const toggleSelect = (id: string) => {
    setSelectedIds((prev) =>
      prev.includes(id) ? prev.filter((item) => item !== id) : [...prev, id]
    );
  };

  const toggleSelectAllFiltered = () => {
    const visibleIds = filteredRules.map((r) => r.id);
    const allSelected =
      visibleIds.length > 0 && visibleIds.every((id) => selectedIds.includes(id));
    if (allSelected) {
      setSelectedIds((prev) => prev.filter((id) => !visibleIds.includes(id)));
    } else {
      setSelectedIds((prev) => [...new Set([...prev, ...visibleIds])]);
    }
  };

  const openCliGenerator = async (mode: 'disable' | 'delete', targetIds?: string[]) => {
    const ids = targetIds ?? selectedIds;
    if (ids.length === 0) return;
    const res = await fetch('/api/export/cli', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ruleIds: ids, natIds: [], mode }),
    });
    if (res.ok) {
      const data = await res.json();
      setCliModal({ script: data.script, mode });
    }
  };

  const handleExportCsv = () => {
    const header = [
      'ID',
      'Nome',
      'Status',
      'Origem_Zona',
      'Destino_Zona',
      'Source',
      'Destination',
      'Service',
      'Acao',
      'Hits_Appliance',
      'Hits_Syslog',
      'Motivo',
    ];
    const rows = filteredRules.map((r) => [
      r.id,
      `"${r.name.replace(/"/g, '""')}"`,
      r.status,
      r.fromZone,
      r.toZone,
      `"${r.source}"`,
      `"${r.destination}"`,
      `"${r.service}"`,
      r.action,
      String(r.applianceHits),
      String(r.syslogHits),
      `"${r.findingReason.replace(/"/g, '""')}"`,
    ]);
    const csv = [header.join(','), ...rows.map((row) => row.join(','))].join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'sonicwall-regras-auditoria.csv';
    a.click();
    URL.revokeObjectURL(url);
  };

  const renderStatus = (status: FirewallRule['status']) => {
    switch (status) {
      case 'unused':
        return (
          <span className="inline-flex items-center gap-1.5 text-amber-800 font-medium whitespace-nowrap">
            <AlertTriangle className="w-3.5 h-3.5 shrink-0" /> Sem uso (0 hits)
          </span>
        );
      case 'shadowed':
        return (
          <span className="inline-flex items-center gap-1.5 text-amber-800 font-medium whitespace-nowrap">
            <ShieldAlert className="w-3.5 h-3.5 shrink-0" /> Sombreada
          </span>
        );
      case 'disabled':
        return (
          <span className="inline-flex items-center gap-1.5 text-[#5C7A6B] font-medium whitespace-nowrap">
            Desabilitada
          </span>
        );
      case 'overpermissive':
        return (
          <span className="inline-flex items-center gap-1.5 text-red-700 font-medium whitespace-nowrap">
            <Ban className="w-3.5 h-3.5 shrink-0" /> Permissiva (Any)
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1.5 text-emerald-800 font-medium whitespace-nowrap">
            <CheckCircle2 className="w-3.5 h-3.5 shrink-0" /> Ativa
          </span>
        );
    }
  };

  if (!loading && rules.length === 0) {
    return (
      <div className="bg-white border border-[#D4E4D8] rounded-lg p-10 max-w-2xl">
        <h2 className="text-lg font-semibold text-[#123325]">
          Nenhuma regra de firewall carregada
        </h2>
        <p className="text-xs text-[#456354] mt-2 leading-relaxed">
          Conecte-se à API SonicOS do seu firewall ou importe um arquivo de configuração{' '}
          <span className="font-mono">.exp</span> / <span className="font-mono">.json</span> para
          identificar regras com zero acertos, regras desabilitadas e regras sombreadas.
        </p>
        <button
          type="button"
          onClick={onGoToConnect}
          className="mt-5 px-4 py-2 text-xs font-medium text-white bg-[#1E4D3B] rounded-md hover:bg-[#163A2C]"
        >
          Ir para Conexão e Importação
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="bg-white border border-[#D4E4D8] rounded-lg p-4 flex flex-wrap items-center justify-between gap-4">
        <div className="flex flex-wrap items-center gap-3 flex-1 min-w-[260px]">
          <div className="relative flex-1 min-w-[220px] max-w-sm">
            <Search className="w-4 h-4 text-[#6D8B7B] absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Buscar regra, zona, IP, serviço..."
              className="w-full pl-9 pr-3 py-2 text-xs border border-[#BFD5C5] rounded-md focus:outline-none focus:ring-2 focus:ring-[#2A6B52]"
            />
          </div>

          <div className="flex flex-wrap items-center gap-1 p-1 bg-[#E5EFE8] rounded-md">
            {(
              [
                { id: 'flagged', label: 'Apenas Irregulares' },
                { id: 'unused', label: 'Sem Uso' },
                { id: 'shadowed', label: 'Sombreadas' },
                { id: 'disabled', label: 'Desabilitadas' },
                { id: 'overpermissive', label: 'Permissivas' },
                { id: 'all', label: 'Todas' },
              ] as const
            ).map((tab) => (
              <button
                key={tab.id}
                type="button"
                onClick={() => setFilter(tab.id)}
                className={`px-3 py-1.5 text-xs font-medium rounded transition-colors whitespace-nowrap ${
                  filter === tab.id
                    ? 'bg-white text-[#123325] shadow-xs'
                    : 'text-[#456354] hover:text-[#123325]'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <button
            type="button"
            disabled={selectedIds.length === 0}
            onClick={() => void openCliGenerator('disable')}
            className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-white bg-[#1E4D3B] rounded-md hover:bg-[#163A2C] disabled:opacity-40 whitespace-nowrap"
          >
            <TerminalSquare className="w-3.5 h-3.5" />
            Gerar CLI ({selectedIds.length})
          </button>
          <button
            type="button"
            onClick={handleExportCsv}
            className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-[#1D3B2E] bg-white border border-[#BFD5C5] rounded-md hover:bg-[#EDF5EF] whitespace-nowrap"
          >
            <Download className="w-3.5 h-3.5" />
            Exportar CSV
          </button>
        </div>
      </div>

      <div className="bg-white border border-[#D4E4D8] rounded-lg overflow-hidden">
        <div className="px-4 py-2.5 border-b border-[#D4E4D8] bg-[#EDF5EF] flex items-center justify-between text-xs text-[#2C4B3D]">
          <span className="tabular-nums">
            {filteredRules.length.toLocaleString('pt-BR')} regras exibidas de{' '}
            {rules.length.toLocaleString('pt-BR')} carregadas
          </span>
          <span>Selecione as regras sem uso para gerar script seguro de desabilitação SonicOS</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-[#D4E4D8] text-[#456354] bg-[#F4F8F5]">
                <th className="py-2.5 pl-4 pr-2 text-left w-8">
                  <input
                    type="checkbox"
                    aria-label="Selecionar todas as regras visíveis"
                    checked={
                      filteredRules.length > 0 &&
                      filteredRules.every((r) => selectedIds.includes(r.id))
                    }
                    onChange={toggleSelectAllFiltered}
                    className="rounded border-[#9EC2AA]"
                  />
                </th>
                <th className="py-2.5 px-3 text-left font-medium">Regra</th>
                <th className="py-2.5 px-3 text-left font-medium">Zonas</th>
                <th className="py-2.5 px-3 text-left font-medium">Origem → Destino</th>
                <th className="py-2.5 px-3 text-left font-medium">Serviço</th>
                <th className="py-2.5 px-3 text-left font-medium">Ação</th>
                <th className="py-2.5 px-3 text-right font-medium">Hits SonicOS</th>
                <th className="py-2.5 px-3 text-right font-medium">Hits Syslog</th>
                <th className="py-2.5 px-4 text-left font-medium">Diagnóstico</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#E6F0E8]">
              {filteredRules.map((rule) => (
                <tr key={rule.id} className="hover:bg-[#F6FAF7] transition-colors">
                  <td className="py-3 pl-4 pr-2 align-top">
                    <input
                      type="checkbox"
                      aria-label={`Selecionar ${rule.name}`}
                      checked={selectedIds.includes(rule.id)}
                      onChange={() => toggleSelect(rule.id)}
                      className="rounded border-[#9EC2AA] mt-0.5"
                    />
                  </td>
                  <td className="py-3 px-3 align-top">
                    <p className="font-medium text-[#123325]">{rule.name}</p>
                    <p className="font-mono text-[11px] text-[#4B6B5C] mt-0.5">
                      {rule.id} · Prioridade {rule.priority}
                    </p>
                  </td>
                  <td className="py-3 px-3 font-mono text-[#2C4B3D] whitespace-nowrap align-top">
                    {rule.fromZone} → {rule.toZone}
                  </td>
                  <td className="py-3 px-3 font-mono text-[#2C4B3D] align-top">
                    <span>{rule.source}</span>
                    <span className="text-[#7CA08A] mx-1">→</span>
                    <span>{rule.destination}</span>
                  </td>
                  <td className="py-3 px-3 font-mono text-[#2C4B3D] whitespace-nowrap align-top">
                    {rule.service}
                  </td>
                  <td className="py-3 px-3 font-mono uppercase text-[#2C4B3D] whitespace-nowrap align-top">
                    {rule.action}
                  </td>
                  <td className="py-3 px-3 text-right font-mono tabular-nums text-[#123325] align-top">
                    {rule.applianceHits.toLocaleString('pt-BR')}
                  </td>
                  <td className="py-3 px-3 text-right font-mono tabular-nums text-[#123325] align-top">
                    {rule.syslogHits.toLocaleString('pt-BR')}
                  </td>
                  <td className="py-3 px-4 align-top max-w-xs">
                    <div>{renderStatus(rule.status)}</div>
                    <p className="text-[11px] text-[#4B6B5C] mt-1 leading-snug">
                      {rule.findingReason}
                    </p>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {cliModal && (
        <CliScriptModal
          title="Script SonicOS CLI — Regras de Firewall"
          script={cliModal.script}
          mode={cliModal.mode}
          onModeChange={(nextMode) => void openCliGenerator(nextMode)}
          onClose={() => setCliModal(null)}
        />
      )}
    </div>
  );
}
