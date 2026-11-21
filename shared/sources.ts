/**
 * Origens (quem consome): tipos e resumos compartilhados entre servidor e interface.
 * Espelha shared/destinations.ts, mas agrupando o tráfego pelo IP de origem.
 */
import type { DestinationMetric, DestinationScope, DestinationService } from './destinations.ts';

export interface SourceNode {
  /** IP de origem (chave estável). */
  id: string;
  ip: string;
  label: string;
  user: string | null;
  zone: string;
  /** Sub-rede (/24 em IPv4) usada para agrupar as bolhas. */
  group: string | null;
  scope: DestinationScope;
  connections: number;
  blocked: number;
  bytes: number;
  /** Quantos destinos distintos esta origem contatou. */
  destinations: number;
  topDestinations: Array<{ label: string; count: number }>;
  /** Categorias dos destinos que mais acessa. */
  categories: Array<{ name: string; count: number }>;
  services: DestinationService[];
  lastSeen: string | null;
}

export interface SourcesReport {
  generatedAt: string;
  minutes: number;
  analyzedEvents: number;
  windowSize: number;
  totalConnections: number;
  nodes: SourceNode[];
  omitted: { sources: number; connections: number };
  /** Filtros aplicados (vazios = sem filtro). */
  srcIp?: string;
  dst?: string;
  dstIps?: string[];
  dataSource?: 'memory' | 'database';
  truncated?: boolean;
}

/** Agrupa IPs por sub-rede: /24 no IPv4, /64 no IPv6. Devolve null se não for um IP válido. */
export function subnetGroup(ip: string): string | null {
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(ip)) {
    const [a, b, c] = ip.split('.');
    return `${a}.${b}.${c}.0/24`;
  }
  if (ip.includes(':') && /^[0-9a-f:.]+$/i.test(ip)) {
    const parts = ip.split(':').filter((p) => p !== '');
    if (parts.length < 2) return null;
    return `${parts.slice(0, 4).join(':')}::/64`;
  }
  return null;
}

export function sourceValue(node: SourceNode, metric: DestinationMetric): number {
  return metric === 'bytes' ? node.bytes : node.connections;
}

export interface SourcesSummary {
  total: number;
  top: Array<{ node: SourceNode; value: number; share: number }>;
  categories: Array<{ category: string; value: number; share: number }>;
  facts: string[];
}

export function summarizeSources(
  nodes: SourceNode[],
  metric: DestinationMetric,
  extra?: { omittedValue?: number }
): SourcesSummary {
  const sorted = [...nodes].sort((a, b) => sourceValue(b, metric) - sourceValue(a, metric));
  const total = sorted.reduce((s, n) => s + sourceValue(n, metric), 0) + (extra?.omittedValue ?? 0);
  const share = (v: number) => (total > 0 ? v / total : 0);

  const top = sorted.slice(0, 5).map((node) => ({
    node,
    value: sourceValue(node, metric),
    share: share(sourceValue(node, metric)),
  }));

  // O que as origens mais acessam: soma as categorias de destino de todas
  const byCategory = new Map<string, number>();
  for (const n of sorted) for (const c of n.categories) byCategory.set(c.name, (byCategory.get(c.name) ?? 0) + c.count);
  const catTotal = [...byCategory.values()].reduce((s, v) => s + v, 0);
  const categories = [...byCategory.entries()]
    .map(([category, value]) => ({ category, value, share: catTotal > 0 ? value / catTotal : 0 }))
    .sort((a, b) => b.value - a.value)
    .slice(0, 5);

  const facts: string[] = [];
  if (total > 0 && sorted.length > 0) {
    const top3 = sorted.slice(0, 3).reduce((s, n) => s + sourceValue(n, metric), 0);
    const unit = metric === 'bytes' ? 'do volume' : 'das conexões';
    facts.push(`${(share(top3) * 100).toFixed(1)}% ${unit} vêm das ${Math.min(3, sorted.length)} maiores origens.`);
    facts.push(`${sorted.length.toLocaleString('pt-BR')} ${sorted.length === 1 ? 'origem distinta' : 'origens distintas'} no período.`);
    const connTotal = nodes.reduce((s, n) => s + n.connections, 0);
    const blocked = nodes.reduce((s, n) => s + n.blocked, 0);
    if (connTotal > 0 && blocked > 0) {
      const worst = [...nodes].sort((a, b) => b.blocked - a.blocked)[0];
      facts.push(
        `${((blocked / connTotal) * 100).toFixed(1)}% das conexões foram bloqueadas; a origem com mais bloqueios é ${worst.ip} (${worst.blocked.toLocaleString('pt-BR')}).`
      );
    }
  }
  return { total, top, categories, facts };
}
