import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { layoutBubbles, packCircles, radiusFor } from '../src/utils/bubblePack.ts';

function noOverlap(circles: Array<{ x: number; y: number; r: number }>): boolean {
  for (let i = 0; i < circles.length; i += 1) {
    for (let j = i + 1; j < circles.length; j += 1) {
      const d = Math.hypot(circles[i].x - circles[j].x, circles[i].y - circles[j].y);
      if (d < circles[i].r + circles[j].r - 1e-6) return false;
    }
  }
  return true;
}

describe('packCircles', () => {
  it('não sobrepõe círculos e devolve um raio que envolve todos', () => {
    const items = Array.from({ length: 40 }, (_, i) => ({ id: `n${i}`, r: 10 + ((i * 7) % 40) }));
    const { placed, radius } = packCircles(items);
    assert.equal(placed.length, 40);
    assert.ok(noOverlap(placed));
    for (const c of placed) assert.ok(Math.hypot(c.x, c.y) + c.r <= radius + 1e-6);
  });
  it('lida com lista vazia e com um único círculo', () => {
    assert.equal(packCircles([]).placed.length, 0);
    const one = packCircles([{ id: 'a', r: 20 }]);
    assert.equal(one.radius, 20);
  });
});

describe('layoutBubbles', () => {
  it('agrupa por domínio com ≥ 2 membros e mantém filhos dentro do grupo', () => {
    const layout = layoutBubbles([
      { id: 'a.ms.com', value: 50, group: 'ms.com' },
      { id: 'b.ms.com', value: 30, group: 'ms.com' },
      { id: 'solo.org', value: 20, group: 'solo.org' },
      { id: '1.2.3.4', value: 10, group: null },
    ]);
    assert.equal(layout.groups.size, 1);
    const g = layout.groups.get('ms.com')!;
    for (const id of ['a.ms.com', 'b.ms.com']) {
      const n = layout.nodes.get(id)!;
      assert.ok(Math.hypot(n.x - g.x, n.y - g.y) + n.r <= g.r + 1e-6);
    }
    assert.ok(noOverlap([...layout.nodes.values()].filter((n) => !['a.ms.com', 'b.ms.com'].includes(n.id))));
    assert.ok(layout.bounds.maxX > layout.bounds.minX);
  });
  it('mapeia valor para raio de forma monotônica', () => {
    assert.ok(radiusFor(100, 100) > radiusFor(25, 100));
    assert.equal(radiusFor(0, 0), 15);
  });
});
