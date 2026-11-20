import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { csvCell, toCsv } from '../src/utils/csv.ts';

describe('csv', () => {
  it('neutraliza injeção de fórmula e escapa aspas', () => {
    assert.equal(csvCell('=HYPERLINK("http://x")'), `"'=HYPERLINK(""http://x"")"`);
    assert.equal(csvCell('+cmd'), "'+cmd");
    assert.equal(csvCell('regra, "x"'), '"regra, ""x"""');
  });
  it('preserva números (inclusive negativos) e vazios', () => {
    assert.equal(csvCell(-5), '-5');
    assert.equal(csvCell(null), '');
    assert.equal(csvCell(0), '0');
  });
  it('gera BOM e quebras CRLF', () => {
    const out = toCsv(['a', 'b'], [[1, 'x']]);
    assert.ok(out.startsWith('﻿a,b\r\n1,x'));
  });
});
