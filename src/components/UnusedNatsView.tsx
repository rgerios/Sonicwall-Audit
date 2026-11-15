import { useEffect, useMemo, useState } from 'react';
import {
  AlertTriangle,
  Ban,
  CheckCircle2,
  Download,
  Search,
  TerminalSquare,
} from 'lucide-react';
import type { NatPolicy } from '../types.ts';
import { CliScriptModal } from './CliScriptModal.tsx';

interface UnusedNatsViewProps {
  refreshToken: number;
  onGoToConnect: () => void;
}

type NatFilter = 'flagged' | 'all' | 'unused' | 'orphaned' | 'disabled';

export function UnusedNatsView({ refreshToken, onGoToConnect }: UnusedNatsViewProps) {
  const [nats, setNats] = useState<NatPolicy[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState<NatFilter>('flagged');
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
        const res = await fetch('/api/nats');
        if (res.ok) {
          const data = await res.json();
          setNats(data.nats || []);
        }
      } finally {
        setLoading(false);
      }
    };
    void load();
  }, [refreshToken]);

  const filteredNats = useMemo(() => {
    return nats.filter((n) => {
      if (filter === 'flagged' && n.status === 'active') return false;
      if (filter !== 'flagged' && filter !== 'all' && n.status !== filter) return false;
      if (query.trim()) {
        const q = query.trim().toLowerCase();
        const hay = `${n.id} ${n.name} ${n.origSource} ${n.transSource} ${n.origDestination} ${n.transDestination} ${n.origService} ${n.inboundInterface} ${n.outboundInterface}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [nats, filter, query]);

  const toggleSelect = (id: string) => {
    setSelectedIds((prev) =>
      prev.includes(id) ? prev.filter((item) => item !== id) : [...prev, id]
    );
  };

  const toggleSelectAllFiltered = () => {
    const visibleIds = filteredNats.map((n) => n.id);
    const allSelected =
      visibleIds.length > 0 && visibleIds.every((id) => selectedIds.includes(id));
    if (allSelected) {
      setSelectedIds((prev) => prev.filter((id) => !visibleIds.includes(id)));
    } else {
      setSelectedIds((prev) => [...new Set([...prev, ...visibleIds])]);
    }
  };

  const openCliGenerator = async (mode: 'disable' | 'delete') => {
    if (selectedIds.length === 0) return;
    const res = await fetch('/api/export/cli', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ruleIds: [], natIds: selectedIds, mode }),
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
      'Interface_Entrada',
      'Interface_Saida',
      'Orig_Src',
      'Trans_Src',
      'Orig_Dst',
      'Trans_Dst',
      'Orig_Svc',
      'Trans_Svc',
      'Hits_Appliance',
      'Hits_Syslog',
      'Motivo',
    ];
    const rows = filteredNats.map((n) => [
      n.id,
      `"${n.name.replace(/"/g, '""')}"`,
      n.status,
      n.inboundInterface,
      n.outboundInterface,
      `"${n.origSource}"`,
      `"${n.transSource}"`,
      `"${n.origDestination}"`,
      `"${n.transDestination}"`,
      `"${n.origService}"`,
      `"${n.transService}"`,
      String(n.applianceHits),
      String(n.syslogHits),
      `"${n.findingReason.replace(/"/g, '""')}"`,
    ]);
    const csv = [header.join(','), ...rows.map((row) => row.join(','))].join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'sonicwall-nats-auditoria.csv';
    a.click();
    URL.revokeObjectURL(url);
  };

  const renderStatus = (status: NatPolicy['status']) => {
    switch (status) {
      case 'unused':
        return (
          <span className="inline-flex items-center gap-1.5 text-amber-800 font-medium whitespace-nowrap">
            <AlertTriangle className="w-3.5 h-3.5 shrink-0" /> Sem uso (0 hits)
          </span>
        );
      case 'orphaned':
        return (
          <span className="inline-flex items-center gap-1.5 text-red-700 font-medium whitespace-nowrap">
            <Ban className="w-3.5 h-3.5 shrink-0" /> NAT Órfão
          </span>
        );
      case 'disabled':
        return (
          <span className="inline-flex items-center gap-1.5 text-[#5C7A6B] font-medium whitespace-nowrap">
            Desabilitada
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

  if (!loading && nats.length === 0) {
    return (
      <div className="bg-white border border-[#D4E4D8] rounded-lg p-10 max-w-2xl">
        <h2 className="text-lg font-semibold text-[#123325]">Nenhuma política NAT carregada</h2>
        <p className="text-xs text-[#456354] mt-2 leading-relaxed">
          Conecte-se à API do SonicWall ou importe seu arquivo <span className="font-mono">.exp</span> /{' '}
          <span className="font-mono">.json</span> para auditar traduções SNAT/DNAT sem tráfego e
          políticas órfãs.
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
              placeholder="Buscar NAT, IP público/interno, porta..."
              className="w-full pl-9 pr-3 py-2 text-xs border border-[#BFD5C5] rounded-md focus:outline-none focus:ring-2 focus:ring-[#2A6B52]"
            />
          </div>

          <div className="flex flex-wrap items-center gap-1 p-1 bg-[#E5EFE8] rounded-md">
            {(
              [
                { id: 'flagged', label: 'Apenas Sem Uso' },
                { id: 'unused', label: '0 Hits' },
                { id: 'orphaned', label: 'Órfãs' },
                { id: 'disabled', label: 'Desabilitadas' },
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
            {filteredNats.length.toLocaleString('pt-BR')} políticas NAT exibidas de{' '}
            {nats.length.toLocaleString('pt-BR')} carregadas
          </span>
          <span>Tradução Original → Traduzido verificada contra os logs</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-[#D4E4D8] text-[#456354] bg-[#F4F8F5]">
                <th className="py-2.5 pl-4 pr-2 text-left w-8">
                  <input
                    type="checkbox"
                    aria-label="Selecionar todas as políticas NAT visíveis"
                    checked={
                      filteredNats.length > 0 &&
                      filteredNats.every((n) => selectedIds.includes(n.id))
                    }
                    onChange={toggleSelectAllFiltered}
                    className="rounded border-[#9EC2AA]"
                  />
                </th>
                <th className="py-2.5 px-3 text-left font-medium">Política NAT</th>
                <th className="py-2.5 px-3 text-left font-medium">Interfaces</th>
                <th className="py-2.5 px-3 text-left font-medium">Origem (Orig → Trad)</th>
                <th className="py-2.5 px-3 text-left font-medium">Destino (Orig → Trad)</th>
                <th className="py-2.5 px-3 text-left font-medium">Serviço</th>
                <th className="py-2.5 px-3 text-right font-medium">Hits SonicOS</th>
                <th className="py-2.5 px-3 text-right font-medium">Hits Syslog</th>
                <th className="py-2.5 px-4 text-left font-medium">Diagnóstico</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#E6F0E8]">
              {filteredNats.map((nat) => (
                <tr key={nat.id} className="hover:bg-[#F6FAF7] transition-colors">
                  <td className="py-3 pl-4 pr-2 align-top">
                    <input
                      type="checkbox"
                      aria-label={`Selecionar ${nat.name}`}
                      checked={selectedIds.includes(nat.id)}
                      onChange={() => toggleSelect(nat.id)}
                      className="rounded border-[#9EC2AA] mt-0.5"
                    />
                  </td>
                  <td className="py-3 px-3 align-top">
                    <p className="font-medium text-[#123325]">{nat.name}</p>
                    <p className="font-mono text-[11px] text-[#4B6B5C] mt-0.5">
                      {nat.id} · Prioridade {nat.priority}
                    </p>
                  </td>
                  <td className="py-3 px-3 font-mono text-[#2C4B3D] whitespace-nowrap align-top">
                    {nat.inboundInterface} → {nat.outboundInterface}
                  </td>
                  <td className="py-3 px-3 font-mono text-[#2C4B3D] align-top">
                    {nat.origSource} → {nat.transSource}
                  </td>
                  <td className="py-3 px-3 font-mono text-[#2C4B3D] align-top">
                    {nat.origDestination} → {nat.transDestination}
                  </td>
                  <td className="py-3 px-3 font-mono text-[#2C4B3D] whitespace-nowrap align-top">
                    {nat.origService}
                    {nat.transService !== 'Original' && nat.transService !== nat.origService
                      ? ` → ${nat.transService}`
                      : ''}
                  </td>
                  <td className="py-3 px-3 text-right font-mono tabular-nums text-[#123325] align-top">
                    {nat.applianceHits.toLocaleString('pt-BR')}
                  </td>
                  <td className="py-3 px-3 text-right font-mono tabular-nums text-[#123325] align-top">
                    {nat.syslogHits.toLocaleString('pt-BR')}
                  </td>
                  <td className="py-3 px-4 align-top max-w-xs">
                    <div>{renderStatus(nat.status)}</div>
                    <p className="text-[11px] text-[#4B6B5C] mt-1 leading-snug">
                      {nat.findingReason}
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
          title="Script SonicOS CLI — Políticas NAT"
          script={cliModal.script}
          mode={cliModal.mode}
          onModeChange={(nextMode) => void openCliGenerator(nextMode)}
          onClose={() => setCliModal(null)}
        />
      )}
    </div>
  );
}
