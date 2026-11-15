import { jsPDF } from 'jspdf';
import autoTable from 'jspdf-autotable';
import type { AuditReportData } from '../types.ts';

function getLastAutoTableY(doc: jsPDF, fallback: number): number {
  const internal = doc as unknown as { lastAutoTable?: { finalY?: number } };
  return internal.lastAutoTable?.finalY ?? fallback;
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function ensureSpace(doc: jsPDF, currentY: number, neededHeight: number): number {
  const pageHeight = doc.internal.pageSize.getHeight();
  if (currentY + neededHeight > pageHeight - 18) {
    doc.addPage();
    return 18;
  }
  return currentY;
}

function drawSectionHeading(doc: jsPDF, title: string, y: number): number {
  const nextY = ensureSpace(doc, y, 16);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(18, 51, 37);
  doc.text(title, 14, nextY);
  doc.setDrawColor(212, 228, 216);
  doc.setLineWidth(0.35);
  doc.line(14, nextY + 2.2, 196, nextY + 2.2);
  return nextY + 7;
}

export function exportAuditReportPdf(report: AuditReportData): void {
  const doc = new jsPDF({
    orientation: 'portrait',
    unit: 'mm',
    format: 'a4',
  });

  const { overview } = report;
  const pageWidth = doc.internal.pageSize.getWidth();

  const ap = overview.appliance;
  const telemetry = overview.telemetry || { interfaces: [], vpns: [], licenses: [] };

  // Header Banner (Pastel Mint)
  doc.setFillColor(237, 245, 239);
  doc.setDrawColor(212, 228, 216);
  doc.roundedRect(14, 12, pageWidth - 28, 30, 2, 2, 'FD');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(14);
  doc.setTextColor(18, 51, 37);
  doc.text('Relatorio Consolidado de Auditoria SonicWall', 19, 20);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8.2);
  doc.setTextColor(69, 99, 84);
  const siteLabel = overview.activeSite
    ? `${overview.activeSite.name}${overview.activeSite.location ? ` (${overview.activeSite.location})` : ''}  |  `
    : '';
  doc.text(
    `${siteLabel}Appliance: ${ap.model}  |  Serial: ${ap.serialNumber}  |  Firmware: ${ap.firmware}  |  Host: ${ap.host}`,
    19,
    26.5
  );
  const hwDetails: string[] = [];
  if (ap.uptimeFormatted) hwDetails.push(`Uptime: ${ap.uptimeFormatted}`);
  if (ap.cpuPercent !== undefined && ap.cpuPercent !== null) hwDetails.push(`CPU: ${ap.cpuPercent}%`);
  if (ap.memoryPercent !== undefined && ap.memoryPercent !== null) hwDetails.push(`RAM: ${ap.memoryPercent}%`);
  if (ap.activeConnections !== undefined && ap.activeConnections !== null) {
    hwDetails.push(`Conexoes: ${ap.activeConnections}${ap.maxConnections ? `/${ap.maxConnections}` : ''}`);
  }
  doc.text(
    `Gerado em: ${new Date(report.generatedAt).toLocaleString('pt-BR')}  |  Retencao: ${overview.retention.retentionDays} dias (${formatBytes(overview.retention.storeSizeBytes)})`,
    19,
    32
  );
  if (hwDetails.length > 0) {
    doc.text(hwDetails.join('  |  '), 19, 37.5);
  }

  // 4-Column KPI Summary Strip
  const irregularRulesCount =
    overview.rulesSummary.unused +
    overview.rulesSummary.shadowed +
    overview.rulesSummary.disabled +
    overview.rulesSummary.overpermissive;
  const irregularNatsCount =
    overview.natsSummary.unused +
    overview.natsSummary.orphaned +
    overview.natsSummary.disabled;

  const kpis = [
    {
      label: 'Syslogs Analisados',
      value: overview.totalSyslogs.toLocaleString('pt-BR'),
      sub: `${overview.syslogBreakdown.allow} allow / ${overview.syslogBreakdown.blocked} drop`,
    },
    {
      label: 'Eventos Bloqueados',
      value: overview.syslogBreakdown.blocked.toLocaleString('pt-BR'),
      sub: `${overview.syslogBreakdown.criticalAndError} criticos/erro`,
    },
    {
      label: 'Regras Irregulares',
      value: `${irregularRulesCount} / ${overview.rulesSummary.total}`,
      sub: `${overview.rulesSummary.unused} zero hits / ${overview.rulesSummary.shadowed} sombr.`,
    },
    {
      label: 'NATs Irregulares',
      value: `${irregularNatsCount} / ${overview.natsSummary.total}`,
      sub: `${overview.natsSummary.unused} sem uso / ${overview.natsSummary.orphaned} orfas`,
    },
  ];

  const cardGap = 3;
  const cardWidth = (pageWidth - 28 - cardGap * 3) / 4;
  let y = 47;

  kpis.forEach((kpi, idx) => {
    const x = 14 + idx * (cardWidth + cardGap);
    doc.setFillColor(244, 248, 245);
    doc.setDrawColor(212, 228, 216);
    doc.roundedRect(x, y, cardWidth, 19, 1.5, 1.5, 'FD');

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.5);
    doc.setTextColor(69, 99, 84);
    doc.text(kpi.label, x + 3, y + 5.5);

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(12);
    doc.setTextColor(18, 51, 37);
    doc.text(kpi.value, x + 3, y + 12);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(6.8);
    doc.setTextColor(92, 122, 107);
    doc.text(kpi.sub, x + 3, y + 16.5);
  });

  y += 27;

  if (telemetry.interfaces.length > 0) {
    y = drawSectionHeading(doc, `Consumo de Link e Interfaces (${telemetry.interfaces.length})`, y);
    autoTable(doc, {
      startY: y,
      margin: { left: 14, right: 14 },
      head: [['Interface', 'Zona', 'IP', 'Status', 'Link', 'Download (Rx)', 'Upload (Tx)', 'Uso']],
      body: telemetry.interfaces.map((i) => [
        i.name,
        i.zone,
        i.ip,
        i.linkStatus.toUpperCase(),
        `${i.linkSpeedMbps} Mbps`,
        `${i.rxMbps.toFixed(1)} Mbps`,
        `${i.txMbps.toFixed(1)} Mbps`,
        `${i.utilizationPercent.toFixed(1)}%`,
      ]),
      styles: {
        fontSize: 7.5,
        cellPadding: 2.2,
        textColor: [22, 40, 32],
        lineColor: [225, 237, 229],
        lineWidth: 0.2,
      },
      headStyles: {
        fillColor: [30, 77, 59],
        textColor: [255, 255, 255],
        fontStyle: 'bold',
      },
      alternateRowStyles: {
        fillColor: [248, 251, 249],
      },
      columnStyles: {
        4: { halign: 'right' },
        5: { halign: 'right' },
        6: { halign: 'right' },
        7: { halign: 'right', fontStyle: 'bold' },
      },
    });
    y = getLastAutoTableY(doc, y) + 9;
  }

  if (telemetry.vpns.length > 0 || telemetry.licenses.length > 0) {
    y = drawSectionHeading(doc, 'Tuneis VPN e Licenciamento SonicWall', y);
    if (telemetry.vpns.length > 0) {
      autoTable(doc, {
        startY: y,
        margin: { left: 14, right: 14 },
        head: [['Tunel / Servico', 'Tipo', 'Peer / Sessoes', 'Status']],
        body: telemetry.vpns.map((v) => [v.name, v.type.toUpperCase(), v.peer, v.status.toUpperCase()]),
        styles: {
          fontSize: 7.5,
          cellPadding: 2.2,
          textColor: [22, 40, 32],
          lineColor: [225, 237, 229],
          lineWidth: 0.2,
        },
        headStyles: {
          fillColor: [30, 77, 59],
          textColor: [255, 255, 255],
          fontStyle: 'bold',
        },
        alternateRowStyles: {
          fillColor: [248, 251, 249],
        },
      });
      y = getLastAutoTableY(doc, y) + 6;
    }
    if (telemetry.licenses.length > 0) {
      autoTable(doc, {
        startY: y,
        margin: { left: 14, right: 14 },
        head: [['Servico de Seguranca', 'Status', 'Expiracao']],
        body: telemetry.licenses.map((l) => [l.service, l.status.toUpperCase(), l.expiresAt || '-']),
        styles: {
          fontSize: 7.5,
          cellPadding: 2.2,
          textColor: [22, 40, 32],
          lineColor: [225, 237, 229],
          lineWidth: 0.2,
        },
        headStyles: {
          fillColor: [30, 77, 59],
          textColor: [255, 255, 255],
          fontStyle: 'bold',
        },
        alternateRowStyles: {
          fillColor: [248, 251, 249],
        },
      });
      y = getLastAutoTableY(doc, y) + 9;
    }
  }

  // Section 1: Recommendations
  y = drawSectionHeading(doc, '1. Plano de Acao e Recomendacoes', y);
  autoTable(doc, {
    startY: y,
    margin: { left: 14, right: 14 },
    head: [['Prioridade', 'Recomendacao', 'Detalhamento', 'Qtd.']],
    body:
      report.recommendations.length > 0
        ? report.recommendations.map((rec) => [
            rec.severity.toUpperCase(),
            rec.title,
            rec.detail,
            String(rec.affectedCount),
          ])
        : [['INFO', 'Ambiente limpo', 'Nenhuma anomalia critica ou item sem uso detectado.', '0']],
    styles: {
      fontSize: 8,
      cellPadding: 2.5,
      textColor: [22, 40, 32],
      lineColor: [225, 237, 229],
      lineWidth: 0.2,
    },
    headStyles: {
      fillColor: [30, 77, 59],
      textColor: [255, 255, 255],
      fontStyle: 'bold',
    },
    alternateRowStyles: {
      fillColor: [248, 251, 249],
    },
    columnStyles: {
      0: { cellWidth: 22, fontStyle: 'bold' },
      1: { cellWidth: 50, fontStyle: 'bold' },
      3: { cellWidth: 14, halign: 'right' },
    },
  });
  y = getLastAutoTableY(doc, y) + 10;

  // Section 2: Firewall Rules
  y = drawSectionHeading(doc, `2. Inventario de Regras de Firewall (${report.rules.length})`, y);
  autoTable(doc, {
    startY: y,
    margin: { left: 14, right: 14 },
    head: [['ID', 'Nome', 'Zonas', 'Origem -> Destino', 'Servico', 'SonicOS', 'Syslog', 'Status']],
    body:
      report.rules.length > 0
        ? report.rules.map((r) => [
            r.id,
            r.name,
            `${r.fromZone} -> ${r.toZone}`,
            `${r.source} -> ${r.destination}`,
            r.service,
            r.applianceHits.toLocaleString('pt-BR'),
            r.syslogHits.toLocaleString('pt-BR'),
            r.status,
          ])
        : [['-', 'Nenhuma regra de firewall carregada', '-', '-', '-', '0', '0', '-']],
    styles: {
      fontSize: 7.4,
      cellPadding: 2.2,
      textColor: [22, 40, 32],
      lineColor: [225, 237, 229],
      lineWidth: 0.2,
    },
    headStyles: {
      fillColor: [30, 77, 59],
      textColor: [255, 255, 255],
      fontStyle: 'bold',
    },
    alternateRowStyles: {
      fillColor: [248, 251, 249],
    },
    columnStyles: {
      0: { cellWidth: 15 },
      2: { cellWidth: 19 },
      4: { cellWidth: 20 },
      5: { cellWidth: 16, halign: 'right' },
      6: { cellWidth: 15, halign: 'right' },
      7: { cellWidth: 22, fontStyle: 'bold' },
    },
  });
  y = getLastAutoTableY(doc, y) + 10;

  // Section 3: NAT Policies
  y = drawSectionHeading(doc, `3. Inventario de Politicas NAT (${report.nats.length})`, y);
  autoTable(doc, {
    startY: y,
    margin: { left: 14, right: 14 },
    head: [['ID', 'Nome', 'Interfaces', 'Destino (Orig -> Trad)', 'Servico', 'SonicOS', 'Syslog', 'Status']],
    body:
      report.nats.length > 0
        ? report.nats.map((n) => [
            n.id,
            n.name,
            `${n.inboundInterface} -> ${n.outboundInterface}`,
            `${n.origDestination} -> ${n.transDestination}`,
            n.origService,
            n.applianceHits.toLocaleString('pt-BR'),
            n.syslogHits.toLocaleString('pt-BR'),
            n.status,
          ])
        : [['-', 'Nenhuma politica NAT carregada', '-', '-', '-', '0', '0', '-']],
    styles: {
      fontSize: 7.4,
      cellPadding: 2.2,
      textColor: [22, 40, 32],
      lineColor: [225, 237, 229],
      lineWidth: 0.2,
    },
    headStyles: {
      fillColor: [30, 77, 59],
      textColor: [255, 255, 255],
      fontStyle: 'bold',
    },
    alternateRowStyles: {
      fillColor: [248, 251, 249],
    },
    columnStyles: {
      0: { cellWidth: 15 },
      2: { cellWidth: 19 },
      4: { cellWidth: 20 },
      5: { cellWidth: 16, halign: 'right' },
      6: { cellWidth: 15, halign: 'right' },
      7: { cellWidth: 20, fontStyle: 'bold' },
    },
  });
  y = getLastAutoTableY(doc, y) + 10;

  // Section 4: Critical / Blocked Syslogs
  if (report.criticalEvents.length > 0) {
    y = drawSectionHeading(
      doc,
      `4. Eventos Criticos e Bloqueios Recentes (${report.criticalEvents.length})`,
      y
    );
    autoTable(doc, {
      startY: y,
      margin: { left: 14, right: 14 },
      head: [['Data/Hora', 'Acao', 'Origem', 'Destino', 'Proto', 'Mensagem']],
      body: report.criticalEvents.map((ev) => [
        ev.timestamp,
        ev.action.toUpperCase(),
        `${ev.srcIp}${ev.srcPort ? `:${ev.srcPort}` : ''}`,
        `${ev.dstIp}${ev.dstPort ? `:${ev.dstPort}` : ''}`,
        ev.protocol,
        ev.message,
      ]),
      styles: {
        fontSize: 7.2,
        cellPadding: 2,
        textColor: [22, 40, 32],
        lineColor: [225, 237, 229],
        lineWidth: 0.2,
      },
      headStyles: {
        fillColor: [30, 77, 59],
        textColor: [255, 255, 255],
        fontStyle: 'bold',
      },
      alternateRowStyles: {
        fillColor: [248, 251, 249],
      },
      columnStyles: {
        0: { cellWidth: 30 },
        1: { cellWidth: 14, fontStyle: 'bold' },
        2: { cellWidth: 32 },
        3: { cellWidth: 32 },
        4: { cellWidth: 13 },
      },
    });
    y = getLastAutoTableY(doc, y) + 10;
  }

  // Section 5: SonicOS CLI Remediation Script
  const sectionIdx = report.criticalEvents.length > 0 ? 5 : 4;
  y = drawSectionHeading(doc, `${sectionIdx}. Script SonicOS CLI (Desabilitacao Segura)`, y);

  const scriptLines = doc.splitTextToSize(report.cliDisableScript, pageWidth - 36) as string[];
  const lineHeight = 4.2;
  const pageHeight = doc.internal.pageSize.getHeight();

  let lineCursor = 0;
  while (lineCursor < scriptLines.length) {
    const availableHeight = pageHeight - 20 - y;
    const maxLinesHere = Math.max(1, Math.floor((availableHeight - 6) / lineHeight));
    const chunk = scriptLines.slice(lineCursor, lineCursor + maxLinesHere);
    const boxHeight = chunk.length * lineHeight + 6;

    doc.setFillColor(14, 34, 26);
    doc.roundedRect(14, y, pageWidth - 28, boxHeight, 1.5, 1.5, 'F');
    doc.setFont('courier', 'normal');
    doc.setFontSize(7.8);
    doc.setTextColor(230, 242, 235);

    chunk.forEach((line, idx) => {
      doc.text(line, 18, y + 5 + idx * lineHeight);
    });

    lineCursor += chunk.length;
    if (lineCursor < scriptLines.length) {
      doc.addPage();
      y = 18;
    } else {
      y += boxHeight + 6;
    }
  }

  // Add footer pagination across all pages
  const totalPages = doc.getNumberOfPages();
  for (let p = 1; p <= totalPages; p += 1) {
    doc.setPage(p);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.5);
    doc.setTextColor(92, 122, 107);
    doc.text('SonicAudit · Auditoria de Syslog, NAT e Firewall SonicWall', 14, pageHeight - 9);
    doc.text(`Pagina ${p} de ${totalPages}`, pageWidth - 14, pageHeight - 9, { align: 'right' });
  }

  const stamp = new Date().toISOString().slice(0, 10);
  doc.save(`relatorio-auditoria-sonicwall-${stamp}.pdf`);
}
