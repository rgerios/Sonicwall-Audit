import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { DEFAULT_PARTICLE_OPTIONS, readThemeOptions } from '../src/effects/particleField.ts';

const style = (vars: Record<string, string>) =>
  ({ getPropertyValue: (name: string) => vars[name] ?? '' }) as unknown as CSSStyleDeclaration;

describe('readThemeOptions', () => {
  it('usa os valores padrão quando o tema não define variáveis', () => {
    assert.deepEqual(readThemeOptions(DEFAULT_PARTICLE_OPTIONS, style({})), DEFAULT_PARTICLE_OPTIONS);
  });
  it('lê cor e matizes das variáveis --fx-*', () => {
    const o = readThemeOptions(
      DEFAULT_PARTICLE_OPTIONS,
      style({ '--fx-rest': ' rgba(1,2,3,0.5) ', '--fx-hue-base': '355', '--fx-hue-range': '45' })
    );
    assert.equal(o.rest, 'rgba(1,2,3,0.5)');
    assert.equal(o.hueBase, 355);
    assert.equal(o.hueRange, 45);
    assert.equal(o.radius, 200);
  });
  it('ignora valores numéricos inválidos', () => {
    assert.equal(readThemeOptions(DEFAULT_PARTICLE_OPTIONS, style({ '--fx-hue-base': 'x' })).hueBase, 190);
  });
});
