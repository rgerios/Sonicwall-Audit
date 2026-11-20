import { AlertTriangle, CheckCircle2 } from 'lucide-react';

export interface ImpactItem {
  id: string;
  name: string;
  status: string;
  applianceHits: number;
  syslogHits: number;
  lastHitAt: string | null;
}

interface SelectionImpactProps {
  noun: { singular: string; plural: string };
  items: ImpactItem[];
}

/** Resumo do que acontece se os itens selecionados forem desabilitados: há tráfego recente? */
export function SelectionImpact({ noun, items }: SelectionImpactProps) {
  if (items.length === 0) return null;
  const withTraffic = items
    .filter((i) => i.applianceHits > 0 || i.syslogHits > 0)
    .sort((a, b) => b.applianceHits + b.syslogHits - (a.applianceHits + a.syslogHits));
  const totalHits = withTraffic.reduce((sum, i) => sum + i.applianceHits + i.syslogHits, 0);
  const label = items.length === 1 ? noun.singular : noun.plural;
  const safe = withTraffic.length === 0;

  return (
    <div
      role="status"
      className={`rounded-lg border px-4 py-3 text-xs flex items-start gap-3 ${
        safe
          ? 'bg-emerald-50 border-emerald-200 text-emerald-900'
          : 'bg-amber-50 border-amber-300 text-amber-900'
      }`}
    >
      {safe ? (
        <CheckCircle2 className="w-4 h-4 mt-0.5 shrink-0" aria-hidden="true" />
      ) : (
        <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0" aria-hidden="true" />
      )}
      <div className="min-w-0">
        <p className="font-semibold">
          {safe
            ? `Impacto estimado: nenhum. ${items.length} ${label} sem tráfego observado.`
            : `Atenção: ${withTraffic.length} de ${items.length} ${label} têm tráfego (${totalHits.toLocaleString('pt-BR')} acertos).`}
        </p>
        {!safe && (
          <ul className="mt-1 space-y-0.5">
            {withTraffic.slice(0, 3).map((i) => (
              <li key={i.id} className="truncate">
                <span className="font-medium">{i.name}</span>
                <span className="font-mono">
                  {' '}
                  · {i.applianceHits.toLocaleString('pt-BR')} no appliance · {i.syslogHits.toLocaleString('pt-BR')} em syslog
                </span>
                {i.lastHitAt && <span> · último {new Date(i.lastHitAt).toLocaleString('pt-BR')}</span>}
              </li>
            ))}
            {withTraffic.length > 3 && <li>… e mais {withTraffic.length - 3}</li>}
          </ul>
        )}
        <p className="mt-1 opacity-80">
          {safe
            ? 'Recomendado: desabilitar primeiro (reversível) e remover só depois de um ciclo completo sem reclamações.'
            : 'Desabilitar estes itens pode interromper o tráfego acima. Revise antes de gerar o script.'}
        </p>
      </div>
    </div>
  );
}
