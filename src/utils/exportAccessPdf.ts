import { jsPDF } from 'jspdf';
import autoTable from 'jspdf-autotable';
import type { AccessReportData } from '../types.ts';
import { formatBytes } from '../../shared/destinations.ts';
import { countryName } from './worldGeo.ts';
import { VENDOR_THEMES } from './vendorTheme.ts';

/** jsPDF (Helvetica) não desenha todos os acentos: normaliza para ASCII legível. */
const a = (text: string) => text.normalize('NFD').replace(/[̀-ͯ]/g, '').replace(/[^\x20-\x7E]/g, '?');
const n = (v: number) => v.toLocaleString('pt-BR');
const pct = (part: number, whole: number) => (whole > 0 ? `${((part / whole) * 100).toFixed(1)}%` : '-');

export function periodLabel(minutes: number): string {
  if (minutes >= 1440 && minutes % 1440 === 0) return `${minutes / 1440} dia(s)`;
  if (minutes >= 60 && minutes % 60 === 0) return `${minutes / 60} h`;
  return `${minutes} min`;
}

export function exportAccessReportPdf(report: AccessReportData, siteName: string): void {
  const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });
  const theme = VENDOR_THEMES[report.vendor];
  const W = doc.internal.pageSize.getWidth();
  const t = report.totals;

  doc.setFillColor(...theme.pdfHeaderRgb);
  doc.setDrawColor(...theme.pdfBorderRgb);
  doc.roundedRect(14, 12, W - 28, 26, 2, 2, 'FD');
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(14);
  doc.setTextColor(...theme.pdfHeadingRgb);
  doc.text(a(`FW Audit - Relatorio de Acessos e Consumo (${theme.label})`), 19, 20);
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8.5);
  doc.setTextColor(...theme.pdfMutedRgb);
  doc.text(a(`${siteName}  |  Periodo: ultimos ${periodLabel(report.minutes)}  |  Gerado em ${new Date(report.generatedAt).toLocaleString('pt-BR')}`), 19, 26.5);
  doc.text(a(`${n(report.analyzedEvents)} eventos de trafego analisados${report.coveragePct < 100 ? ` (detalhe cobre ${report.coveragePct}%)` : ''}`), 19, 32);

  const kpi = [
    ['Conexoes', n(t.connections)],
    ['Bloqueadas', `${n(t.blocked)} (${pct(t.blocked, t.connections)})`],
    ['Volume total', formatBytes(t.totalBytes)],
    ['Download / Upload', `${formatBytes(t.downloadBytes)} / ${formatBytes(t.uploadBytes)}`],
    ['Banda media', `${t.avgMbps.toLocaleString('pt-BR')} Mbps`],
    ['Pico (hora)', `${t.peakHourMbps.toLocaleString('pt-BR')} Mbps`],
    ['IPs de origem', n(t.sources)],
    ['Paises / Destinos', `${n(t.countries)} / ${n(t.destinations)}`],
  ];
  autoTable(doc, {
    startY: 44,
    body: [kpi.slice(0, 4).flatMap(([l, v]) => [l, v]), kpi.slice(4).flatMap(([l, v]) => [l, v])],
    theme: 'grid',
    styles: { fontSize: 8, cellPadding: 2 },
    columnStyles: { 0: { fontStyle: 'bold', fillColor: [245, 247, 250] }, 2: { fontStyle: 'bold', fillColor: [245, 247, 250] }, 4: { fontStyle: 'bold', fillColor: [245, 247, 250] }, 6: { fontStyle: 'bold', fillColor: [245, 247, 250] } },
  });

  const section = (title: string, head: string[], rows: string[][]) => {
    const last = (doc as unknown as { lastAutoTable?: { finalY?: number } }).lastAutoTable?.finalY ?? 50;
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(11);
    doc.setTextColor(...theme.pdfHeadingRgb);
    const y = last + 9 > 270 ? (doc.addPage(), 18) : last + 9;
    doc.text(a(title), 14, y);
    autoTable(doc, {
      startY: y + 2,
      head: [head],
      body: rows.length ? rows : [['Sem dados no periodo', ...head.slice(1).map(() => '')]],
      theme: 'striped',
      headStyles: { fillColor: theme.pdfHeadingRgb, fontSize: 8 },
      styles: { fontSize: 7.6, cellPadding: 1.6 },
    });
  };

  section(
    'Consumo de banda por IP de origem (Top 25)',
    ['IP', 'Download', 'Upload', 'Total', '% do total', 'Conexoes', 'Bloq.', 'Principal categoria', 'Pais mais acessado'],
    report.sources.map((s) => [s.ip, formatBytes(s.downloadBytes), formatBytes(s.uploadBytes), formatBytes(s.totalBytes), pct(s.totalBytes, t.totalBytes), n(s.connections), n(s.blocked), a(s.topCategory ?? '-'), s.topCountry ? a(countryName(s.topCountry)) : '-'])
  );
  section(
    'Destinos mais acessados (Top 25)',
    ['Destino', 'Categoria', 'Pais', 'Organizacao (ASN)', 'Conexoes', 'Volume', 'Reputacao'],
    report.destinations.map((d) => [a(d.host ?? d.ip), a(d.category), d.country ? a(countryName(d.country)) : '-', a(d.asnOrg ?? '-'), n(d.connections), formatBytes(d.totalBytes), d.threats.length ? a(d.threats.join(', ')) : 'limpo'])
  );
  section(
    'Categorias mais acessadas',
    ['Categoria', 'Conexoes', '% conexoes', 'Volume', 'Destinos'],
    report.categories.slice(0, 15).map((c) => [a(c.name), n(c.connections), pct(c.connections, t.connections), formatBytes(c.totalBytes), n(c.destinations)])
  );
  section(
    'Paises mais acessados',
    ['Pais', 'Conexoes', '% conexoes', 'Bloqueadas', 'Volume', 'IPs'],
    report.countries.map((c) => [a(countryName(c.code)), n(c.connections), pct(c.connections, t.connections), n(c.blocked), formatBytes(c.totalBytes), n(c.ips)])
  );
  section(
    'Servicos mais usados',
    ['Servico', 'Conexoes', '% conexoes', 'Volume'],
    report.services.map((s) => [a(s.name), n(s.connections), pct(s.connections, t.connections), formatBytes(s.totalBytes)])
  );

  const pages = doc.getNumberOfPages();
  for (let i = 1; i <= pages; i += 1) {
    doc.setPage(i);
    doc.setFontSize(7.5);
    doc.setTextColor(120, 120, 120);
    doc.text(a(`FW Audit - Acessos e Consumo  |  pagina ${i}/${pages}`), 14, 289);
  }
  doc.save(`fwaudit-acessos-${report.vendor}-${new Date().toISOString().slice(0, 10)}.pdf`);
}
