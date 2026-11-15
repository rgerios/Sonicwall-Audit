import { generateSonicOsCli } from './parsers.ts';
import type {
  AuditOverview,
  AuditReportData,
  FirewallRule,
  NatPolicy,
  SyslogEvent,
} from './types.ts';

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export function buildAuditReport(
  overview: AuditOverview,
  syslogs: SyslogEvent[],
  rules: FirewallRule[],
  nats: NatPolicy[]
): AuditReportData {
  const recommendations: AuditReportData['recommendations'] = [];

  if (overview.rulesSummary.overpermissive > 0) {
    recommendations.push({
      severity: 'high',
      title: 'Restringir regras permissivas (Any → Any)',
      detail: `${overview.rulesSummary.overpermissive} regra(s) permitem tráfego irrestrito envolvendo zonas críticas. Substitua por objetos de endereço e serviços específicos.`,
      affectedCount: overview.rulesSummary.overpermissive,
    });
  }

  if (overview.natsSummary.orphaned > 0) {
    recommendations.push({
      severity: 'high',
      title: 'Remover ou revisar políticas NAT órfãs',
      detail: `${overview.natsSummary.orphaned} política(s) NAT possuem zero tráfego e não têm mais regra de firewall correspondente.`,
      affectedCount: overview.natsSummary.orphaned,
    });
  }

  if (overview.rulesSummary.unused > 0) {
    recommendations.push({
      severity: 'medium',
      title: 'Desabilitar regras de firewall com 0 hits',
      detail: `${overview.rulesSummary.unused} regra(s) não registraram nenhum acerto no SonicOS nem nos syslogs analisados.`,
      affectedCount: overview.rulesSummary.unused,
    });
  }

  if (overview.rulesSummary.shadowed > 0) {
    recommendations.push({
      severity: 'medium',
      title: 'Eliminar regras sombreadas por políticas superiores',
      detail: `${overview.rulesSummary.shadowed} regra(s) nunca são alcançadas porque regras mais amplas acima interceptam o tráfego antes.`,
      affectedCount: overview.rulesSummary.shadowed,
    });
  }

  if (overview.natsSummary.unused > 0) {
    recommendations.push({
      severity: 'medium',
      title: 'Limpar traduções NAT sem uso',
      detail: `${overview.natsSummary.unused} política(s) NAT não apresentaram traduções durante o período monitorado.`,
      affectedCount: overview.natsSummary.unused,
    });
  }

  if (overview.rulesSummary.disabled + overview.natsSummary.disabled > 0) {
    const disabledCount = overview.rulesSummary.disabled + overview.natsSummary.disabled;
    recommendations.push({
      severity: 'low',
      title: 'Consolidar objetos já desabilitados',
      detail: `${disabledCount} item(ns) desabilitado(s) permanecem na configuração ativa e podem ser arquivados após validação.`,
      affectedCount: disabledCount,
    });
  }

  const criticalEvents = syslogs
    .filter(
      (ev) =>
        ev.priority <= 4 ||
        ev.action === 'drop' ||
        ev.action === 'deny' ||
        ev.action === 'reset'
    )
    .slice(0, 25);

  const flaggedRules = rules.filter((r) => r.status !== 'active');
  const flaggedNats = nats.filter((n) => n.status !== 'active');
  const cliDisableScript = generateSonicOsCli(flaggedRules, flaggedNats, 'disable');

  return {
    generatedAt: new Date().toISOString(),
    overview,
    recommendations,
    criticalEvents,
    rules,
    nats,
    cliDisableScript,
  };
}

export function renderReportMarkdown(report: AuditReportData): string {
  const { overview } = report;
  const ap = overview.appliance;
  const telemetry = overview.telemetry || { interfaces: [], vpns: [], licenses: [] };
  const lines: string[] = [
    `# Relatório Consolidado de Auditoria SonicWall`,
    ``,
    `- **Gerado em:** ${new Date(report.generatedAt).toLocaleString('pt-BR')}`,
    ...(overview.activeSite
      ? [
          `- **Localidade:** ${overview.activeSite.name}${overview.activeSite.location ? ` (${overview.activeSite.location})` : ''}`,
        ]
      : []),
    `- **Appliance:** ${ap.model} (Serial: ${ap.serialNumber})`,
    `- **Firmware / Origem:** ${ap.firmware}${ap.romVersion ? ` · ROM ${ap.romVersion}` : ''}${ap.safemodeVersion ? ` · SafeMode ${ap.safemodeVersion}` : ''} · Host: ${ap.host}`,
    ...(ap.uptimeFormatted ? [`- **Uptime / HA:** ${ap.uptimeFormatted}${ap.haRole ? ` (${ap.haRole})` : ''}`] : []),
    ...(ap.cpuPercent !== undefined && ap.cpuPercent !== null
      ? [
          `- **Recursos:** CPU ${ap.cpuPercent}% · RAM ${ap.memoryPercent ?? '-'}% · Conexões ${ap.activeConnections ?? '-'}${ap.maxConnections ? ` / ${ap.maxConnections}` : ''}`,
        ]
      : []),
    `- **Política de Retenção:** Expurgo automático após ${overview.retention.retentionDays} dias`,
    ``,
    `## 1. Resumo Executivo`,
    ``,
    `| Indicador | Valor |`,
    `| :--- | ---: |`,
    `| Syslogs analisados (janela ativa) | ${overview.totalSyslogs} |`,
    `| Tráfego permitido | ${overview.syslogBreakdown.allow} |`,
    `| Tráfego bloqueado (Drop / Deny / Reset) | ${overview.syslogBreakdown.blocked} |`,
    `| Regras de Firewall (Total / Irregulares) | ${overview.rulesSummary.total} / ${overview.rulesSummary.unused + overview.rulesSummary.shadowed + overview.rulesSummary.disabled + overview.rulesSummary.overpermissive} |`,
    `| Políticas NAT (Total / Irregulares) | ${overview.natsSummary.total} / ${overview.natsSummary.unused + overview.natsSummary.orphaned + overview.natsSummary.disabled} |`,
    ``,
    ...(telemetry.interfaces.length > 0
      ? [
          `## 1.1 Consumo de Link e Interfaces`,
          ``,
          `| Interface | Zona | IP | Status | Link | Download (Rx) | Upload (Tx) | Uso |`,
          `| :--- | :--- | :--- | :--- | ---: | ---: | ---: | ---: |`,
          ...telemetry.interfaces.map(
            (i) =>
              `| ${i.name} | ${i.zone} | ${i.ip} | ${i.linkStatus.toUpperCase()} | ${i.linkSpeedMbps} Mbps | ${i.rxMbps} Mbps | ${i.txMbps} Mbps | ${i.utilizationPercent}% |`
          ),
          ``,
        ]
      : []),
    ...(telemetry.vpns.length > 0
      ? [
          `## 1.2 Túneis VPN e SSL VPN`,
          ``,
          `| Túnel / Serviço | Tipo | Peer / Sessões | Status |`,
          `| :--- | :--- | :--- | :--- |`,
          ...telemetry.vpns.map(
            (v) => `| ${v.name} | ${v.type.toUpperCase()} | ${v.peer} | ${v.status.toUpperCase()} |`
          ),
          ``,
        ]
      : []),
    ...(telemetry.licenses.length > 0
      ? [
          `## 1.3 Licenças de Segurança SonicWall`,
          ``,
          `| Serviço | Status | Expiração |`,
          `| :--- | :--- | :--- |`,
          ...telemetry.licenses.map(
            (l) => `| ${l.service} | ${l.status} | ${l.expiresAt || '-'} |`
          ),
          ``,
        ]
      : []),
    `## 2. Recomendações Prioritárias`,
    ``,
  ];

  if (report.recommendations.length === 0) {
    lines.push(`Nenhuma anomalia crítica ou item sem uso foi detectado no conjunto analisado.`);
  } else {
    for (const rec of report.recommendations) {
      lines.push(`- **[${rec.severity.toUpperCase()}] ${rec.title}** — ${rec.detail}`);
    }
  }

  lines.push('', `## 3. Principais Origens Bloqueadas`, '');
  if (overview.topBlockedSources.length === 0) {
    lines.push(`Sem origens bloqueadas registradas.`);
  } else {
    lines.push(`| IP de Origem | Zona | Ocorrências |`, `| :--- | :--- | ---: |`);
    for (const src of overview.topBlockedSources) {
      lines.push(`| ${src.ip} | ${src.zone} | ${src.count} |`);
    }
  }

  lines.push('', `## 4. Portas Mais Visadas`, '');
  if (overview.topTargetedPorts.length === 0) {
    lines.push(`Sem portas registradas.`);
  } else {
    lines.push(`| Protocolo/Porta | Total | Bloqueios |`, `| :--- | ---: | ---: |`);
    for (const p of overview.topTargetedPorts) {
      lines.push(`| ${p.protocol}/${p.port} | ${p.count} | ${p.blocked} |`);
    }
  }

  lines.push('', `## 5. Auditoria de Regras de Firewall`, '');
  if (report.rules.length === 0) {
    lines.push(`Nenhuma regra de firewall importada.`);
  } else {
    lines.push(
      `| ID | Nome | Zonas | Origem → Destino | Serviço | Hits SonicOS | Hits Syslog | Status | Diagnóstico |`,
      `| :--- | :--- | :--- | :--- | :--- | ---: | ---: | :--- | :--- |`
    );
    for (const r of report.rules) {
      lines.push(
        `| ${r.id} | ${r.name} | ${r.fromZone}→${r.toZone} | ${r.source} → ${r.destination} | ${r.service} | ${r.applianceHits} | ${r.syslogHits} | ${r.status} | ${r.findingReason} |`
      );
    }
  }

  lines.push('', `## 6. Auditoria de Políticas NAT`, '');
  if (report.nats.length === 0) {
    lines.push(`Nenhuma política NAT importada.`);
  } else {
    lines.push(
      `| ID | Nome | Interfaces | Origem (O→T) | Destino (O→T) | Hits SonicOS | Hits Syslog | Status | Diagnóstico |`,
      `| :--- | :--- | :--- | :--- | :--- | ---: | ---: | :--- | :--- |`
    );
    for (const n of report.nats) {
      lines.push(
        `| ${n.id} | ${n.name} | ${n.inboundInterface}→${n.outboundInterface} | ${n.origSource}→${n.transSource} | ${n.origDestination}→${n.transDestination} | ${n.applianceHits} | ${n.syslogHits} | ${n.status} | ${n.findingReason} |`
      );
    }
  }

  lines.push(
    '',
    `## 7. Script de Remediação Segura (SonicOS CLI)`,
    '',
    '```text',
    report.cliDisableScript,
    '```',
    ''
  );

  return lines.join('\n');
}

export function renderReportHtml(report: AuditReportData): string {
  const { overview } = report;
  const issueRules =
    overview.rulesSummary.unused +
    overview.rulesSummary.shadowed +
    overview.rulesSummary.disabled +
    overview.rulesSummary.overpermissive;
  const issueNats =
    overview.natsSummary.unused +
    overview.natsSummary.orphaned +
    overview.natsSummary.disabled;

  const recRows = report.recommendations
    .map(
      (r) => `
      <tr>
        <td><strong>${escapeHtml(r.severity.toUpperCase())}</strong></td>
        <td><strong>${escapeHtml(r.title)}</strong></td>
        <td>${escapeHtml(r.detail)}</td>
        <td class="num">${r.affectedCount}</td>
      </tr>`
    )
    .join('');

  const ruleRows = report.rules
    .map(
      (r) => `
      <tr>
        <td class="mono">${escapeHtml(r.id)}</td>
        <td>${escapeHtml(r.name)}</td>
        <td class="mono">${escapeHtml(r.fromZone)} → ${escapeHtml(r.toZone)}</td>
        <td class="mono">${escapeHtml(r.source)} → ${escapeHtml(r.destination)}</td>
        <td class="mono">${escapeHtml(r.service)}</td>
        <td class="num">${r.applianceHits.toLocaleString('pt-BR')}</td>
        <td class="num">${r.syslogHits.toLocaleString('pt-BR')}</td>
        <td><strong>${escapeHtml(r.status)}</strong></td>
        <td>${escapeHtml(r.findingReason)}</td>
      </tr>`
    )
    .join('');

  const natRows = report.nats
    .map(
      (n) => `
      <tr>
        <td class="mono">${escapeHtml(n.id)}</td>
        <td>${escapeHtml(n.name)}</td>
        <td class="mono">${escapeHtml(n.inboundInterface)} → ${escapeHtml(n.outboundInterface)}</td>
        <td class="mono">${escapeHtml(n.origSource)} → ${escapeHtml(n.transSource)}</td>
        <td class="mono">${escapeHtml(n.origDestination)} → ${escapeHtml(n.transDestination)}</td>
        <td class="num">${n.applianceHits.toLocaleString('pt-BR')}</td>
        <td class="num">${n.syslogHits.toLocaleString('pt-BR')}</td>
        <td><strong>${escapeHtml(n.status)}</strong></td>
        <td>${escapeHtml(n.findingReason)}</td>
      </tr>`
    )
    .join('');

  const eventRows = report.criticalEvents
    .map(
      (ev) => `
      <tr>
        <td class="mono">${escapeHtml(ev.timestamp)}</td>
        <td class="mono">${escapeHtml(ev.action.toUpperCase())}</td>
        <td class="mono">${escapeHtml(ev.srcIp)}${ev.srcPort ? `:${ev.srcPort}` : ''}</td>
        <td class="mono">${escapeHtml(ev.dstIp)}${ev.dstPort ? `:${ev.dstPort}` : ''}</td>
        <td class="mono">${escapeHtml(ev.protocol)}</td>
        <td>${escapeHtml(ev.message)}</td>
      </tr>`
    )
    .join('');

  const telemetry = overview.telemetry || { interfaces: [], vpns: [], licenses: [] };
  const ap = overview.appliance;

  const ifaceRows = telemetry.interfaces
    .map(
      (i) => `
      <tr>
        <td class="mono"><strong>${escapeHtml(i.name)}</strong></td>
        <td class="mono">${escapeHtml(i.zone)}</td>
        <td class="mono">${escapeHtml(i.ip)}</td>
        <td><strong>${escapeHtml(i.linkStatus.toUpperCase())}</strong></td>
        <td class="num">${i.linkSpeedMbps} Mbps</td>
        <td class="num">${i.rxMbps.toFixed(1)} Mbps</td>
        <td class="num">${i.txMbps.toFixed(1)} Mbps</td>
        <td class="num">${i.utilizationPercent.toFixed(1)}%</td>
      </tr>`
    )
    .join('');

  const vpnRows = telemetry.vpns
    .map(
      (v) => `
      <tr>
        <td><strong>${escapeHtml(v.name)}</strong></td>
        <td class="mono">${escapeHtml(v.type.toUpperCase())}</td>
        <td class="mono">${escapeHtml(v.peer)}</td>
        <td><strong>${escapeHtml(v.status.toUpperCase())}</strong></td>
      </tr>`
    )
    .join('');

  const licenseRows = telemetry.licenses
    .map(
      (l) => `
      <tr>
        <td>${escapeHtml(l.service)}</td>
        <td><strong>${escapeHtml(l.status)}</strong></td>
        <td class="mono">${escapeHtml(l.expiresAt || '-')}</td>
      </tr>`
    )
    .join('');

  const healthMetaParts: string[] = [];
  if (ap.uptimeFormatted) healthMetaParts.push(`Uptime: ${escapeHtml(ap.uptimeFormatted)}`);
  if (ap.romVersion) healthMetaParts.push(`ROM: ${escapeHtml(ap.romVersion)}`);
  if (ap.cpuPercent !== undefined && ap.cpuPercent !== null) healthMetaParts.push(`CPU: ${ap.cpuPercent}%`);
  if (ap.memoryPercent !== undefined && ap.memoryPercent !== null) healthMetaParts.push(`RAM: ${ap.memoryPercent}%`);
  if (ap.activeConnections !== undefined && ap.activeConnections !== null) {
    healthMetaParts.push(
      `Conexões: ${ap.activeConnections.toLocaleString('pt-BR')}${ap.maxConnections ? ` / ${ap.maxConnections.toLocaleString('pt-BR')}` : ''}`
    );
  }

  return `<!doctype html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8" />
  <title>Relatório de Auditoria SonicWall — ${escapeHtml(ap.model)}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #f4f8f5; color: #162820; margin: 0; padding: 32px; line-height: 1.5; }
    .container { max-width: 1120px; margin: 0 auto; background: #ffffff; border: 1px solid #d4e4d8; border-radius: 10px; padding: 32px; }
    h1 { font-size: 22px; margin: 0 0 6px; color: #123325; }
    h2 { font-size: 15px; margin: 28px 0 12px; padding-bottom: 6px; border-bottom: 1px solid #d4e4d8; color: #1e4d3b; }
    .meta { font-size: 12px; color: #4b6859; margin-bottom: 24px; }
    .kpis { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 24px; }
    .kpi { background: #f4f8f5; border: 1px solid #d4e4d8; border-radius: 8px; padding: 14px; }
    .kpi-label { font-size: 11px; color: #4b6859; }
    .kpi-value { font-size: 22px; font-weight: 700; font-family: ui-monospace, monospace; margin-top: 4px; color: #123325; }
    table { width: 100%; border-collapse: collapse; font-size: 12px; margin-top: 8px; }
    th, td { padding: 8px 10px; border-bottom: 1px solid #e5efe8; text-align: left; vertical-align: top; }
    th { background: #edf5ef; color: #244838; font-weight: 600; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 11px; }
    .num { font-family: ui-monospace, monospace; text-align: right; }
    pre { background: #0e221a; color: #e6f2eb; padding: 16px; border-radius: 8px; font-size: 11px; overflow-x: auto; font-family: ui-monospace, monospace; }
    @media print { body { background: #fff; padding: 0; } .container { border: none; padding: 0; } }
  </style>
</head>
<body>
  <div class="container">
    <h1>Relatório Consolidado de Auditoria SonicWall</h1>
    <div class="meta">
      Gerado em ${escapeHtml(new Date(report.generatedAt).toLocaleString('pt-BR'))} ·
      ${overview.activeSite ? `Localidade: <strong>${escapeHtml(overview.activeSite.name)}</strong>${overview.activeSite.location ? ` (${escapeHtml(overview.activeSite.location)})` : ''} · ` : ''}
      Appliance: ${escapeHtml(ap.model)} (${escapeHtml(ap.serialNumber)}) ·
      Firmware: ${escapeHtml(ap.firmware)} ·
      Host: ${escapeHtml(ap.host)} ·
      Retenção de syslogs: ${overview.retention.retentionDays} dias
      ${healthMetaParts.length > 0 ? `<br/>${healthMetaParts.join(' · ')}` : ''}
    </div>

    <div class="kpis">
      <div class="kpi"><div class="kpi-label">Syslogs Analisados</div><div class="kpi-value">${overview.totalSyslogs.toLocaleString('pt-BR')}</div></div>
      <div class="kpi"><div class="kpi-label">Eventos Bloqueados</div><div class="kpi-value">${overview.syslogBreakdown.blocked.toLocaleString('pt-BR')}</div></div>
      <div class="kpi"><div class="kpi-label">Regras Irregulares</div><div class="kpi-value">${issueRules} / ${overview.rulesSummary.total}</div></div>
      <div class="kpi"><div class="kpi-label">NATs Irregulares</div><div class="kpi-value">${issueNats} / ${overview.natsSummary.total}</div></div>
    </div>

    ${
      ifaceRows
        ? `<h2>Consumo de Link e Interfaces (${telemetry.interfaces.length})</h2>
    <table>
      <thead><tr><th>Interface</th><th>Zona</th><th>IP</th><th>Status</th><th class="num">Capacidade</th><th class="num">Download (Rx)</th><th class="num">Upload (Tx)</th><th class="num">Uso</th></tr></thead>
      <tbody>${ifaceRows}</tbody>
    </table>`
        : ''
    }

    ${
      vpnRows || licenseRows
        ? `<h2>Túneis VPN e Licenciamento SonicWall</h2>
    ${
      vpnRows
        ? `<table><thead><tr><th>Túnel / Serviço</th><th>Tipo</th><th>Peer / Sessões</th><th>Status</th></tr></thead><tbody>${vpnRows}</tbody></table>`
        : ''
    }
    ${
      licenseRows
        ? `<table style="margin-top:16px"><thead><tr><th>Serviço de Segurança</th><th>Status</th><th>Expiração</th></tr></thead><tbody>${licenseRows}</tbody></table>`
        : ''
    }`
        : ''
    }

    <h2>1. Plano de Ação e Recomendações</h2>
    <table>
      <thead><tr><th>Prioridade</th><th>Recomendação</th><th>Detalhamento</th><th class="num">Qtd.</th></tr></thead>
      <tbody>${recRows || '<tr><td colspan="4">Nenhuma recomendação crítica encontrada.</td></tr>'}</tbody>
    </table>

    <h2>2. Regras de Firewall (${report.rules.length})</h2>
    <table>
      <thead><tr><th>ID</th><th>Nome</th><th>Zonas</th><th>Origem → Destino</th><th>Serviço</th><th class="num">SonicOS</th><th class="num">Syslog</th><th>Status</th><th>Diagnóstico</th></tr></thead>
      <tbody>${ruleRows || '<tr><td colspan="9">Nenhuma regra carregada.</td></tr>'}</tbody>
    </table>

    <h2>3. Políticas NAT (${report.nats.length})</h2>
    <table>
      <thead><tr><th>ID</th><th>Nome</th><th>Interfaces</th><th>Origem (O→T)</th><th>Destino (O→T)</th><th class="num">SonicOS</th><th class="num">Syslog</th><th>Status</th><th>Diagnóstico</th></tr></thead>
      <tbody>${natRows || '<tr><td colspan="9">Nenhuma política NAT carregada.</td></tr>'}</tbody>
    </table>

    <h2>4. Eventos Críticos e Bloqueios Recentes (${report.criticalEvents.length})</h2>
    <table>
      <thead><tr><th>Data/Hora</th><th>Ação</th><th>Origem</th><th>Destino</th><th>Proto</th><th>Mensagem</th></tr></thead>
      <tbody>${eventRows || '<tr><td colspan="6">Sem eventos críticos no período.</td></tr>'}</tbody>
    </table>

    <h2>5. Script SonicOS CLI — Desabilitação Segura</h2>
    <pre>${escapeHtml(report.cliDisableScript)}</pre>
  </div>
</body>
</html>`;
}
