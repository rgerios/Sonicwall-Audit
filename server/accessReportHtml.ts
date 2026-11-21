import type { AccessReportData } from '../shared/accessReport.ts';

/**
 * HTML ESTÁTICO e autossuficiente do relatório de Acessos e Consumo: sem JavaScript, sem fontes nem
 * imagens externas (CSS e gráfico em SVG inline). Abre em qualquer navegador, imprime bem e pode ser
 * enviado por e-mail sem perder o formato.
 */

const esc = (v: unknown) =>
  String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c] as string);
const num = (v: number) => v.toLocaleString('pt-BR');
const pct = (part: number, whole: number) => (whole > 0 ? (part / whole) * 100 : 0);

export function formatBytesBr(value: number): string {
  if (!Number.isFinite(value) || value <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  let v = value;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${v.toLocaleString('pt-BR', { maximumFractionDigits: i === 0 ? 0 : 2 })} ${units[i]}`;
}

let regionNames: Intl.DisplayNames | null = null;
function countryLabel(code: string | null): string {
  if (!code) return '—';
  try {
    regionNames ??= new Intl.DisplayNames(['pt-BR'], { type: 'region' });
    const name = regionNames.of(code) ?? code;
    const flag = /^[A-Z]{2}$/.test(code) ? String.fromCodePoint(...[...code].map((c) => 0x1f1e6 + c.charCodeAt(0) - 65)) : '';
    return `${flag} ${name}`.trim();
  } catch {
    return code;
  }
}

export function periodText(minutes: number): string {
  if (minutes >= 1440 && minutes % 1440 === 0) return `${minutes / 1440} dia(s)`;
  if (minutes >= 60 && minutes % 60 === 0) return `${minutes / 60} hora(s)`;
  return `${minutes} min`;
}

const when = (iso: string | null) =>
  iso ? new Date(iso).toLocaleString('pt-BR', { dateStyle: 'short', timeStyle: 'short' }) : '—';

function bar(value: number, color: string): string {
  return `<div class="bar"><i style="width:${Math.max(2, Math.min(100, value)).toFixed(1)}%;background:${color}"></i></div>`;
}

/** Gráfico de área duplo (download/upload) em SVG, médias em Mbps por hora. */
function timelineSvg(report: AccessReportData): string {
  const pts = report.timeline;
  if (pts.length === 0) return '<p class="muted">Sem dados com volume no período.</p>';
  const W = 880;
  const H = 220;
  const L = 52;
  const R = 12;
  const T = 12;
  const B = 28;
  const down = pts.map((p) => (p.downloadBytes * 8) / 3600 / 1e6);
  const up = pts.map((p) => (p.uploadBytes * 8) / 3600 / 1e6);
  const max = Math.max(0.001, ...down, ...up) * 1.1;
  const x = (i: number) => L + (pts.length === 1 ? (W - L - R) / 2 : (i / (pts.length - 1)) * (W - L - R));
  const y = (v: number) => T + (1 - v / max) * (H - T - B);
  const path = (vals: number[]) => vals.map((v, i) => `${i === 0 ? 'M' : 'L'}${x(i).toFixed(1)} ${y(v).toFixed(1)}`).join(' ');
  const area = (vals: number[]) =>
    `${path(vals)} L${x(vals.length - 1).toFixed(1)} ${y(0).toFixed(1)} L${x(0).toFixed(1)} ${y(0).toFixed(1)} Z`;
  const grid = [0, 0.25, 0.5, 0.75, 1]
    .map((f) => {
      const v = max * f;
      return `<line x1="${L}" x2="${W - R}" y1="${y(v).toFixed(1)}" y2="${y(v).toFixed(1)}" stroke="#e5e9f0"/><text x="${L - 6}" y="${(y(v) + 3).toFixed(1)}" text-anchor="end" font-size="10" fill="#6b7686">${v.toLocaleString('pt-BR', { maximumFractionDigits: v < 1 ? 3 : 1 })}</text>`;
    })
    .join('');
  const labelEvery = Math.max(1, Math.ceil(pts.length / 8));
  const labels = pts
    .map((p, i) =>
      i % labelEvery === 0
        ? `<text x="${x(i).toFixed(1)}" y="${H - 8}" text-anchor="middle" font-size="10" fill="#6b7686">${esc(new Date(p.t).toLocaleString('pt-BR', { day: '2-digit', month: '2-digit', hour: '2-digit' }))}h</text>`
        : ''
    )
    .join('');
  const dots = pts.length <= 2 ? pts.map((_, i) => `<circle cx="${x(i)}" cy="${y(down[i])}" r="3" fill="#0ea5e9"/><circle cx="${x(i)}" cy="${y(up[i])}" r="3" fill="#8b5cf6"/>`).join('') : '';
  return `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Banda ao longo do tempo" class="chart">${grid}
<path d="${area(down)}" fill="#0ea5e9" fill-opacity=".18"/><path d="${path(down)}" fill="none" stroke="#0ea5e9" stroke-width="2"/>
<path d="${area(up)}" fill="#8b5cf6" fill-opacity=".18"/><path d="${path(up)}" fill="none" stroke="#8b5cf6" stroke-width="2"/>${dots}${labels}</svg>
<p class="legend"><span><i style="background:#0ea5e9"></i>Download</span><span><i style="background:#8b5cf6"></i>Upload</span><span class="muted">Mbps, média por hora</span></p>`;
}

export function renderAccessReportHtml(report: AccessReportData, siteName: string, brand: { label: string; accent: string }): string {
  const t = report.totals;
  const maxSrc = report.sources[0]?.totalBytes ?? 0;
  const maxCat = report.categories[0]?.connections ?? 0;
  const maxCountry = report.countries[0]?.connections ?? 0;
  const maxSvc = report.services[0]?.connections ?? 0;
  const accent = brand.accent;

  const sourcesRows = report.sources
    .map(
      (s) => `<tr><td class="mono">${esc(s.ip)}</td><td class="w">${bar(pct(s.totalBytes, maxSrc), '#0ea5e9')}</td>
<td class="r">${formatBytesBr(s.downloadBytes)}</td><td class="r">${formatBytesBr(s.uploadBytes)}</td><td class="r b">${formatBytesBr(s.totalBytes)}</td>
<td class="r">${pct(s.totalBytes, t.totalBytes).toFixed(1)}%</td><td class="r">${num(s.connections)}</td><td class="r">${num(s.blocked)}</td>
<td>${esc(s.topCategory ?? '—')}</td><td>${esc(countryLabel(s.topCountry))}</td></tr>`
    )
    .join('');
  const destRows = report.destinations
    .map(
      (d) => `<tr><td><b>${esc(d.host ?? d.ip)}</b>${d.host ? `<br><span class="mono sub">${esc(d.ip)}</span>` : ''}</td><td>${esc(d.category)}</td>
<td>${esc(countryLabel(d.country))}</td><td>${esc(d.asnOrg ?? '—')}</td><td class="r">${num(d.connections)}</td><td class="r">${formatBytesBr(d.totalBytes)}</td>
<td>${d.threats.length ? `<span class="tag bad">${esc(d.threats.join(', '))}</span>` : '<span class="muted">limpo</span>'}</td></tr>`
    )
    .join('');
  const list = (rows: Array<{ label: string; right: string; value: number }>, color: string) =>
    rows.map((r) => `<li><div class="row"><span>${esc(r.label)}</span><span class="muted">${esc(r.right)}</span></div>${bar(r.value, color)}</li>`).join('');

  const catList = list(
    report.categories.slice(0, 12).map((c) => ({ label: c.name, right: `${num(c.connections)} (${pct(c.connections, t.connections).toFixed(1)}%) · ${formatBytesBr(c.totalBytes)}`, value: pct(c.connections, maxCat) })),
    '#8b5cf6'
  );
  const countryList = list(
    report.countries.slice(0, 12).map((c) => ({ label: countryLabel(c.code), right: `${num(c.connections)} (${pct(c.connections, t.connections).toFixed(1)}%) · ${formatBytesBr(c.totalBytes)}`, value: pct(c.connections, maxCountry) })),
    '#10b981'
  );
  const svcList = list(
    report.services.map((s) => ({ label: s.name, right: `${num(s.connections)} · ${formatBytesBr(s.totalBytes)}`, value: pct(s.connections, maxSvc) })),
    '#f59e0b'
  );

  const kpis = [
    ['Conexões', num(t.connections), `${num(t.blocked)} bloqueadas (${pct(t.blocked, t.connections).toFixed(1)}%)`],
    ['Volume total', formatBytesBr(t.totalBytes), `↓ ${formatBytesBr(t.downloadBytes)} · ↑ ${formatBytesBr(t.uploadBytes)}`],
    ['Banda média / pico', `${t.avgMbps.toLocaleString('pt-BR')} Mbps`, `pico em 1 h: ${t.peakHourMbps.toLocaleString('pt-BR')} Mbps`],
    ['Alcance', `${num(t.sources)} IPs`, `${num(t.destinations)} destinos · ${num(t.countries)} países`],
  ]
    .map(([l, v, s]) => `<div class="kpi"><p class="l">${esc(l)}</p><p class="v">${esc(v)}</p><p class="s">${esc(s)}</p></div>`)
    .join('');

  return `<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Acessos e Consumo — ${esc(siteName)} — ${esc(when(report.periodEnd))}</title>
<style>
:root{--ink:#14202e;--muted:#6b7686;--line:#e5e9f0;--soft:#f5f7fa;--accent:${accent}}
*{box-sizing:border-box}body{margin:0;background:#eef1f6;color:var(--ink);font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
.page{max-width:1040px;margin:24px auto;background:#fff;border-radius:14px;box-shadow:0 8px 30px rgba(20,32,46,.08);overflow:hidden}
header{padding:28px 36px;background:linear-gradient(135deg,var(--accent),#0f172a);color:#fff}
header .brand{font-size:12px;letter-spacing:.08em;text-transform:uppercase;opacity:.85}
header h1{margin:6px 0 4px;font-size:26px;font-weight:650}header p{margin:0;opacity:.9;font-size:13px}
main{padding:28px 36px 36px}section{margin-top:30px}h2{font-size:16px;margin:0 0 10px;padding-bottom:6px;border-bottom:2px solid var(--line)}
.kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}.kpi{border:1px solid var(--line);border-radius:10px;padding:12px 14px;background:var(--soft)}
.kpi .l{margin:0;font-size:11px;color:var(--muted)}.kpi .v{margin:2px 0;font-size:21px;font-weight:650}.kpi .s{margin:0;font-size:11px;color:var(--muted)}
.alert{margin-top:14px;padding:10px 12px;border:1px solid #fecaca;background:#fef2f2;color:#991b1b;border-radius:8px;font-size:13px}
table{width:100%;border-collapse:collapse;font-size:12px}th{text-align:left;color:var(--muted);font-weight:600;padding:6px 8px 6px 0;border-bottom:1px solid var(--line)}
td{padding:7px 8px 7px 0;border-bottom:1px solid var(--line);vertical-align:top}.r{text-align:right;font-variant-numeric:tabular-nums}.b{font-weight:650}.w{width:130px}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}.sub{font-size:10px;color:var(--muted)}.muted{color:var(--muted)}
.bar{height:6px;background:#e9edf3;border-radius:99px;overflow:hidden;margin-top:4px}.bar i{display:block;height:100%;border-radius:99px}
.tag{display:inline-block;padding:1px 7px;border-radius:6px;font-size:10.5px;font-weight:650}.bad{background:#fee2e2;color:#991b1b;border:1px solid #fecaca}
ul.l{list-style:none;margin:0;padding:0}ul.l li{margin-bottom:10px}.row{display:flex;justify-content:space-between;gap:10px;font-size:12.5px}
.two{display:grid;grid-template-columns:1fr 1fr;gap:28px}.chart{width:100%;height:auto}.legend{display:flex;gap:16px;align-items:center;font-size:12px;margin:4px 0 0}
.legend i{display:inline-block;width:10px;height:10px;border-radius:3px;margin-right:5px}
footer{padding:16px 36px 24px;color:var(--muted);font-size:11px;border-top:1px solid var(--line)}
@media(max-width:760px){.kpis{grid-template-columns:1fr 1fr}.two{grid-template-columns:1fr}main,header{padding-left:18px;padding-right:18px}.page{margin:0;border-radius:0}table{display:block;overflow-x:auto}}
@media print{body{background:#fff}.page{box-shadow:none;margin:0;border-radius:0}header{-webkit-print-color-adjust:exact;print-color-adjust:exact}section{break-inside:avoid}}
</style></head><body><div class="page">
<header><div class="brand">FW Audit · ${esc(brand.label)} · Acessos e Consumo</div>
<h1>${esc(siteName)}</h1>
<p>Últimos ${esc(periodText(report.minutes))} · ${esc(when(report.periodStart ?? report.generatedAt))} até ${esc(when(report.periodEnd))} · ${num(report.analyzedEvents)} eventos de tráfego${report.coveragePct < 100 ? ` · detalhe cobre ${report.coveragePct}% (maiores fluxos)` : ''}</p></header>
<main>
<div class="kpis">${kpis}</div>
${t.threatConnections > 0 ? `<div class="alert"><b>Atenção:</b> ${num(t.threatConnections)} conexões foram para IPs em listas de ameaça (blacklist, botnet ou Tor). Veja a coluna Reputação em Destinos.</div>` : ''}
${report.timedOut ? '<div class="alert">O banco não terminou o cálculo no tempo limite: este relatório está incompleto. Use um período menor.</div>' : ''}
<section><h2>Banda ao longo do tempo</h2>${timelineSvg(report)}</section>
<section><h2>Consumo de banda por IP de origem (Top ${report.sources.length})</h2>
<table><thead><tr><th>IP</th><th>Consumo</th><th class="r">Download</th><th class="r">Upload</th><th class="r">Total</th><th class="r">%</th><th class="r">Conexões</th><th class="r">Bloq.</th><th>Categoria principal</th><th>País</th></tr></thead><tbody>${sourcesRows}</tbody></table>
${report.othersSources.count > 0 ? `<p class="muted" style="font-size:11px">+ ${num(report.othersSources.count)} outros IPs somam ${formatBytesBr(report.othersSources.totalBytes)} (${pct(report.othersSources.totalBytes, t.totalBytes).toFixed(1)}% do volume).</p>` : ''}</section>
<section class="two"><div><h2>Categorias mais acessadas</h2><ul class="l">${catList}</ul></div><div><h2>Países mais acessados</h2><ul class="l">${countryList || '<li class="muted">Sem países (bases de GeoIP não baixadas).</li>'}</ul></div></section>
<section><h2>Destinos mais acessados (Top ${report.destinations.length})</h2>
<table><thead><tr><th>Destino</th><th>Categoria</th><th>País</th><th>Organização (ASN)</th><th class="r">Conexões</th><th class="r">Volume</th><th>Reputação</th></tr></thead><tbody>${destRows}</tbody></table></section>
<section><h2>Serviços mais usados</h2><ul class="l">${svcList}</ul></section>
</main>
<footer>Gerado em ${esc(when(report.generatedAt))} pelo FW Audit. Metodologia: conexões e bytes somados dos syslogs de tráfego (eventos de sistema excluídos); Download = bytes recebidos pelo cliente, Upload = bytes enviados; país, ASN e reputação vêm de bases offline (DB-IP Lite, FireHOL, Spamhaus DROP, abuse.ch, Tor). Banda por hora = volume ÷ 3600 s.</footer>
</div></body></html>`;
}
