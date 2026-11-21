/**
 * Empacotamento de círculos (sem dependências) para o radar de destinos.
 * Algoritmo guloso: do maior para o menor, cada círculo vai para a posição livre mais próxima
 * do centro, varrendo uma espiral (opcionalmente achatada em elipse para preencher telas largas).
 */
export interface PackItem {
  id: string;
  r: number;
}

export interface PlacedCircle {
  id: string;
  x: number;
  y: number;
  r: number;
}

function overlaps(x: number, y: number, r: number, placed: PlacedCircle[], gap: number): boolean {
  for (const c of placed) {
    const dx = x - c.x;
    const dy = y - c.y;
    const min = r + c.r + gap;
    if (dx * dx + dy * dy < min * min) return true;
  }
  return false;
}

export function packCircles(
  items: PackItem[],
  options: { gap?: number; aspect?: number } = {}
): { placed: PlacedCircle[]; radius: number } {
  const gap = options.gap ?? 3;
  const aspect = options.aspect ?? 1;
  const sorted = [...items].sort((a, b) => b.r - a.r);
  const placed: PlacedCircle[] = [];

  for (const item of sorted) {
    if (placed.length === 0) {
      placed.push({ id: item.id, x: 0, y: 0, r: item.r });
      continue;
    }
    const step = Math.max(2, item.r / 3);
    let found: { x: number; y: number } | null = null;
    // Cresce a espiral até achar espaço; o limite evita laço infinito com entradas absurdas
    for (let d = 0; d < 20000 && !found; d += step) {
      const circumference = Math.max(1, 2 * Math.PI * Math.max(d, step));
      const samples = Math.max(8, Math.ceil(circumference / step));
      // Fase aleatória determinística: evita alinhar todos os círculos no eixo x
      const phase = (placed.length * 2.399963) % (2 * Math.PI);
      for (let i = 0; i < samples; i += 1) {
        const a = phase + (i / samples) * 2 * Math.PI;
        const x = Math.cos(a) * d * aspect;
        const y = Math.sin(a) * d;
        if (!overlaps(x, y, item.r, placed, gap)) {
          found = { x, y };
          break;
        }
      }
    }
    const pos = found ?? { x: 0, y: 0 };
    placed.push({ id: item.id, x: pos.x, y: pos.y, r: item.r });
  }

  // Recentraliza pelo centro de massa (área) e calcula o raio que envolve tudo
  let area = 0;
  let cx = 0;
  let cy = 0;
  for (const c of placed) {
    const a = c.r * c.r;
    area += a;
    cx += c.x * a;
    cy += c.y * a;
  }
  if (area > 0) {
    cx /= area;
    cy /= area;
  }
  let radius = 0;
  for (const c of placed) {
    c.x -= cx;
    c.y -= cy;
    radius = Math.max(radius, Math.hypot(c.x, c.y) + c.r);
  }
  return { placed, radius };
}

export interface BubbleNodeInput {
  id: string;
  value: number;
  group: string | null;
}

export interface BubbleLayout {
  nodes: Map<string, PlacedCircle>;
  groups: Map<string, PlacedCircle>;
  bounds: { minX: number; minY: number; maxX: number; maxY: number };
}

/** Raios mínimo e máximo das bolhas; a cor do mapa de calor segue a posição entre os dois. */
export const MIN_RADIUS = 15;
export const MAX_RADIUS = 74;

export function radiusFor(value: number, maxValue: number, minR = MIN_RADIUS, maxR = MAX_RADIUS): number {
  if (maxValue <= 0) return minR;
  return minR + (maxR - minR) * Math.sqrt(Math.max(0, value) / maxValue);
}

/**
 * Dois níveis: destinos que compartilham o domínio registrável (≥ 2) formam um círculo-grupo;
 * os demais flutuam soltos. O resultado já vem em coordenadas absolutas.
 */
export function layoutBubbles(inputs: BubbleNodeInput[], options: { aspect?: number } = {}): BubbleLayout {
  const maxValue = inputs.reduce((m, n) => Math.max(m, n.value), 0);
  const radii = new Map(inputs.map((n) => [n.id, radiusFor(n.value, maxValue)]));

  const byGroup = new Map<string, BubbleNodeInput[]>();
  for (const n of inputs) {
    if (!n.group) continue;
    const list = byGroup.get(n.group) ?? [];
    list.push(n);
    byGroup.set(n.group, list);
  }

  const GROUP_PAD = 14;
  const top: PackItem[] = [];
  const innerLayouts = new Map<string, { placed: PlacedCircle[]; radius: number }>();

  for (const [group, members] of byGroup) {
    if (members.length < 2) continue;
    const inner = packCircles(members.map((m) => ({ id: m.id, r: radii.get(m.id)! })), { gap: 3 });
    innerLayouts.set(group, inner);
    top.push({ id: `group:${group}`, r: inner.radius + GROUP_PAD });
  }
  const grouped = new Set<string>();
  for (const [group] of innerLayouts) for (const m of byGroup.get(group)!) grouped.add(m.id);
  for (const n of inputs) if (!grouped.has(n.id)) top.push({ id: n.id, r: radii.get(n.id)! });

  // aspect = largura/altura da área disponível: telas largas viram elipses, celulares ficam altos
  const aspect = Math.min(1.8, Math.max(0.6, options.aspect ?? 1.55));
  const { placed } = packCircles(top, { gap: 6, aspect });

  const nodes = new Map<string, PlacedCircle>();
  const groups = new Map<string, PlacedCircle>();
  for (const p of placed) {
    if (p.id.startsWith('group:')) {
      const group = p.id.slice(6);
      groups.set(group, p);
      for (const child of innerLayouts.get(group)!.placed) {
        nodes.set(child.id, { id: child.id, x: p.x + child.x, y: p.y + child.y, r: child.r });
      }
    } else {
      nodes.set(p.id, p);
    }
  }

  let minX = Infinity;
  let minY = Infinity;
  let maxX = -Infinity;
  let maxY = -Infinity;
  for (const c of placed) {
    minX = Math.min(minX, c.x - c.r);
    minY = Math.min(minY, c.y - c.r);
    maxX = Math.max(maxX, c.x + c.r);
    maxY = Math.max(maxY, c.y + c.r);
  }
  if (!Number.isFinite(minX)) [minX, minY, maxX, maxY] = [-100, -100, 100, 100];
  return { nodes, groups, bounds: { minX, minY, maxX, maxY } };
}
