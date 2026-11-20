/**
 * Exportação CSV segura e compatível com Excel:
 * - aspas escapadas em todas as células (antes só alguns campos eram escapados);
 * - células que começam com = + - @ recebem um apóstrofo, evitando injeção de fórmula
 *   (nomes de regra e comentários vêm do firewall e podem ser controlados por terceiros);
 * - BOM UTF-8 para o Excel preservar acentos.
 */
const FORMULA_START = /^[=+\-@\t\r]/;

export function csvCell(value: unknown): string {
  let text = value === null || value === undefined ? '' : String(value);
  // números negativos legítimos não devem ser tratados como fórmula
  if (FORMULA_START.test(text) && !(typeof value === 'number' && Number.isFinite(value))) {
    text = `'${text}`;
  }
  return /[",\r\n;]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

export function toCsv(header: string[], rows: unknown[][]): string {
  const lines = [header, ...rows].map((row) => row.map(csvCell).join(','));
  return `﻿${lines.join('\r\n')}`;
}

export function downloadCsv(filename: string, header: string[], rows: unknown[][]): void {
  const blob = new Blob([toCsv(header, rows)], { type: 'text/csv;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
