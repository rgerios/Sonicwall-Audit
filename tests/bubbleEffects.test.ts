import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createBody, stepBodies, type Body, type Pointer } from '../src/effects/bubblePhysics.ts';
import { heatGradientCss, heatHue, heatStyle } from '../src/utils/heat.ts';

const OFF: Pointer = { x: 0, y: 0, active: false };

function run(bodies: Body[], pointer: Pointer, seconds: number, drift = 0) {
  let t = 0;
  for (let i = 0; i < seconds * 60; i += 1) {
    stepBodies(bodies, pointer, 1 / 60, t, { drift });
    t += 1000 / 60;
  }
}

describe('escala de calor', () => {
  it('vai do azul (pequeno) ao vermelho (grande) de forma contínua', () => {
    assert.equal(Math.round(heatHue(0)), 218);
    assert.ok(Math.abs(heatHue(1) - 2) < 1e-9);
    let last = Infinity;
    for (let t = 0; t <= 1.0001; t += 0.05) {
      const h = heatHue(t);
      assert.ok(h <= last + 1e-9, `matiz não pode subir (t=${t})`);
      last = h;
    }
    assert.equal(heatHue(-5), heatHue(0));
    assert.equal(heatHue(9), heatHue(1));
    assert.equal(heatHue(Number.NaN), heatHue(0));
  });

  it('bolhas maiores ficam mais evidentes (brilho e contorno crescem)', () => {
    const cold = heatStyle(0);
    const hot = heatStyle(1);
    assert.ok(hot.strokeWidth > cold.strokeWidth);
    assert.ok(hot.glowRadius > cold.glowRadius);
    assert.match(hot.stroke, /^hsl\(2 /);
    assert.match(heatGradientCss(), /^linear-gradient\(90deg, hsl\(218/);
  });
});

describe('física das bolhas', () => {
  it('sem o ponteiro e sem deriva, as bolhas voltam ao repouso', () => {
    const b = createBody('a', 100, 100, 20);
    b.ox = 40;
    b.oy = -25;
    run([b], OFF, 3);
    assert.ok(Math.abs(b.ox) < 0.05 && Math.abs(b.oy) < 0.05, `${b.ox},${b.oy}`);
  });

  it('o ponteiro empurra a bolha para longe dele', () => {
    const b = createBody('a', 100, 0, 20);
    run([b], { x: 0, y: 0, active: true }, 2);
    assert.ok(b.ox > 5, `deveria afastar para a direita, ox=${b.ox}`);
    const above = createBody('b', 0, -100, 20);
    run([above], { x: 0, y: 0, active: true }, 2);
    assert.ok(above.oy < -5, `deveria afastar para cima, oy=${above.oy}`);
  });

  it('o efeito diminui com a distância e some fora do alcance', () => {
    const near = createBody('n', 60, 0, 20);
    const far = createBody('f', 400, 0, 20);
    run([near, far], { x: 0, y: 0, active: true }, 2);
    assert.ok(Math.hypot(near.ox, near.oy) > Math.hypot(far.ox, far.oy));
    assert.ok(Math.hypot(far.ox, far.oy) < 1e-6);
  });

  it('a bolha sob o ponteiro não foge (continua clicável)', () => {
    const b = createBody('under', 50, 50, 30);
    run([b], { x: 55, y: 52, active: true }, 2);
    assert.ok(Math.hypot(b.ox, b.oy) < 0.05);
  });

  it('bolhas pequenas se movem mais que as grandes à mesma distância', () => {
    const small = createBody('s', 120, 0, 12);
    const big = createBody('b', 120, 0, 60);
    // mesma borda efetiva: compara o deslocamento relativo ao alcance
    run([small], { x: 0, y: 0, active: true }, 2);
    run([big], { x: 0, y: 0, active: true }, 2);
    assert.ok(Math.hypot(small.ox, small.oy) > Math.hypot(big.ox, big.oy));
  });

  it('filhos de um grupo não saem do círculo do grupo', () => {
    const parent = { x: 0, y: 0, r: 80 };
    const child = createBody('c', 30, 0, 20, parent);
    // ponteiro do lado de dentro empurrando o filho para fora
    run([child], { x: -60, y: 0, active: true }, 3);
    const dist = Math.hypot(child.x + child.ox - parent.x, child.y + child.oy - parent.y);
    assert.ok(dist <= parent.r - child.r + 1e-6, `dist=${dist}`);
  });

  it('é estável com quadros muito longos e com dt zero', () => {
    const b = createBody('a', 10, 10, 15);
    stepBodies([b], { x: 0, y: 0, active: true }, 5, 0);
    stepBodies([b], OFF, 0, 0);
    assert.ok(Number.isFinite(b.ox) && Number.isFinite(b.oy));
    assert.ok(Math.hypot(b.ox, b.oy) < 200);
  });

  it('a deriva ociosa é pequena e limitada', () => {
    const b = createBody('a', 0, 0, 15);
    let max = 0;
    let t = 0;
    for (let i = 0; i < 600; i += 1) {
      stepBodies([b], OFF, 1 / 60, t, { drift: 2.4 });
      max = Math.max(max, Math.hypot(b.ox, b.oy));
      t += 1000 / 60;
    }
    assert.ok(max > 0.3 && max < 6, `max=${max}`);
  });
});
