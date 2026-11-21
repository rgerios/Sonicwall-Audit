import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import type { AccessReportData, ReportFileInfo, ReportScheduleConfig, ReportScheduleState } from '../shared/accessReport.ts';
import { renderAccessReportHtml } from './accessReportHtml.ts';

const ALLOWED_HOURS = [24, 72, 168];
const DEFAULT_CONFIG: ReportScheduleConfig = {
  enabled: false,
  everyHours: 24,
  timeOfDay: '06:00',
  keep: 30,
  nextRunAt: null,
  lastRunAt: null,
  lastError: null,
};

const safeId = (s: string) => /^[a-z0-9-]{8,80}$/.test(s);
const safeSite = (s: string) => s.replace(/[^A-Za-z0-9_-]/g, '_').slice(0, 80);

/** Próxima ocorrência de HH:MM (horário local do servidor) estritamente depois de `after`. */
export function nextOccurrence(after: number, timeOfDay: string): number {
  const [h, m] = timeOfDay.split(':').map(Number);
  const d = new Date(after);
  d.setHours(h, m, 0, 0);
  if (d.getTime() <= after) d.setDate(d.getDate() + 1);
  return d.getTime();
}

/** Avança um horário agendado em múltiplos do intervalo até ficar no futuro (recupera atrasos sem rajada). */
export function advanceSlot(slot: number, everyHours: number, now: number): number {
  const step = everyHours * 3600_000;
  let next = slot + step;
  if (next <= now) next += Math.ceil((now - next + 1) / step) * step;
  return next;
}

export interface ScheduledReports {
  state(siteId: string): Promise<ReportScheduleState>;
  save(siteId: string, input: Partial<Pick<ReportScheduleConfig, 'enabled' | 'everyHours' | 'timeOfDay' | 'keep'>>): Promise<ReportScheduleState>;
  runNow(siteId: string, trigger: 'manual' | 'scheduled', minutes?: number): Promise<ReportFileInfo>;
  isRunning(): boolean;
  filePath(siteId: string, id: string): Promise<{ file: string; filename: string } | null>;
  remove(siteId: string, id: string): Promise<boolean>;
  start(): void;
  stop(): void;
}

export function createScheduledReports(deps: {
  dataDir: string;
  brand: { label: string; accent: string };
  listSites: () => Array<{ id: string; name: string }>;
  generate: (siteId: string, minutes: number) => Promise<AccessReportData>;
  log: (level: 'info' | 'warn', message: string, detail?: string) => void;
}): ScheduledReports {
  const root = path.join(deps.dataDir, 'reports');
  const scheduleFile = path.join(root, 'schedule.json');
  let running = false;
  let runningInfo: { since: string; minutes: number } | null = null;
  let timer: NodeJS.Timeout | null = null;
  let configs: Record<string, ReportScheduleConfig> | null = null;

  async function loadConfigs() {
    if (configs) return configs;
    try {
      configs = JSON.parse(await fs.readFile(scheduleFile, 'utf8')) as Record<string, ReportScheduleConfig>;
    } catch {
      configs = {};
    }
    return configs;
  }
  async function persistConfigs() {
    await fs.mkdir(root, { recursive: true });
    await fs.writeFile(scheduleFile, JSON.stringify(configs ?? {}, null, 2));
  }
  const dirFor = (siteId: string) => path.join(root, safeSite(siteId));
  const indexFile = (siteId: string) => path.join(dirFor(siteId), 'index.json');

  async function readIndex(siteId: string): Promise<ReportFileInfo[]> {
    try {
      return JSON.parse(await fs.readFile(indexFile(siteId), 'utf8')) as ReportFileInfo[];
    } catch {
      return [];
    }
  }
  const writeIndex = (siteId: string, list: ReportFileInfo[]) => fs.writeFile(indexFile(siteId), JSON.stringify(list, null, 2));

  async function cfgFor(siteId: string): Promise<ReportScheduleConfig> {
    const all = await loadConfigs();
    return { ...DEFAULT_CONFIG, ...(all[siteId] ?? {}) };
  }

  async function state(siteId: string): Promise<ReportScheduleState> {
    return {
      config: await cfgFor(siteId),
      files: (await readIndex(siteId)).sort((a, b) => b.createdAt.localeCompare(a.createdAt)),
      running,
      runningSince: running ? (runningInfo?.since ?? null) : null,
      runningMinutes: running ? (runningInfo?.minutes ?? null) : null,
    };
  }

  async function runNow(siteId: string, trigger: 'manual' | 'scheduled', minutesOverride?: number): Promise<ReportFileInfo> {
    if (running) throw new Error('Já existe um relatório sendo gerado.');
    running = true;
    try {
      const cfg = await cfgFor(siteId);
      const minutes = minutesOverride ?? cfg.everyHours * 60;
      runningInfo = { since: new Date().toISOString(), minutes };
      const report = await deps.generate(siteId, minutes);
      if (report.timedOut) throw new Error('O banco excedeu o tempo limite ao calcular o relatório (muitos logs no período).');
      const site = deps.listSites().find((s) => s.id === siteId);
      const html = renderAccessReportHtml(report, site?.name ?? 'Localidade', deps.brand);
      const stamp = new Date().toISOString().replace(/[-:T]/g, '').slice(0, 12);
      const id = `${stamp}-${crypto.randomBytes(4).toString('hex')}`;
      const dir = dirFor(siteId);
      await fs.mkdir(dir, { recursive: true });
      const filename = `fwaudit-acessos-${stamp.slice(0, 8)}-${stamp.slice(8)}-${minutes >= 1440 ? `${Math.round(minutes / 1440)}d` : `${Math.round(minutes / 60)}h`}.html`;
      await fs.writeFile(path.join(dir, `${id}.html`), html);
      const info: ReportFileInfo = {
        id,
        createdAt: new Date().toISOString(),
        trigger,
        minutes,
        periodStart: report.periodStart,
        periodEnd: report.periodEnd,
        sizeBytes: Buffer.byteLength(html),
        connections: report.totals.connections,
        totalBytes: report.totals.totalBytes,
        sources: report.totals.sources,
        filename,
      };
      let index = [info, ...(await readIndex(siteId))].sort((a, b) => b.createdAt.localeCompare(a.createdAt));
      const keep = Math.max(1, Math.min(200, cfg.keep));
      for (const old of index.slice(keep)) await fs.rm(path.join(dir, `${old.id}.html`), { force: true });
      index = index.slice(0, keep);
      await writeIndex(siteId, index);
      deps.log('info', `Relatório de acessos gerado (${trigger})`, `${filename} · ${info.sizeBytes} bytes · ${info.connections} conexões`);
      return info;
    } finally {
      running = false;
      runningInfo = null;
    }
  }

  async function tick() {
    if (running) return;
    const all = await loadConfigs();
    const now = Date.now();
    for (const site of deps.listSites()) {
      const cfg = all[site.id];
      if (!cfg?.enabled || !cfg.nextRunAt || Date.parse(cfg.nextRunAt) > now) continue;
      try {
        await runNow(site.id, 'scheduled');
        all[site.id] = { ...cfg, lastRunAt: new Date().toISOString(), lastError: null, nextRunAt: new Date(advanceSlot(Date.parse(cfg.nextRunAt), cfg.everyHours, Date.now())).toISOString() };
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        deps.log('warn', 'Falha ao gerar o relatório agendado', msg);
        // tenta de novo em 30 min, sem perder o horário da grade
        all[site.id] = { ...cfg, lastError: msg, nextRunAt: new Date(Date.now() + 30 * 60_000).toISOString() };
      }
      await persistConfigs();
    }
  }

  return {
    state,
    isRunning: () => running,
    runNow,
    async save(siteId, input) {
      const all = await loadConfigs();
      const cur = await cfgFor(siteId);
      const everyHours = input.everyHours !== undefined && ALLOWED_HOURS.includes(input.everyHours) ? input.everyHours : cur.everyHours;
      const timeOfDay = input.timeOfDay !== undefined && /^([01]\d|2[0-3]):[0-5]\d$/.test(input.timeOfDay) ? input.timeOfDay : cur.timeOfDay;
      const keep = input.keep !== undefined && Number.isInteger(input.keep) ? Math.max(1, Math.min(200, input.keep)) : cur.keep;
      const enabled = input.enabled ?? cur.enabled;
      const changed = enabled !== cur.enabled || everyHours !== cur.everyHours || timeOfDay !== cur.timeOfDay;
      const next: ReportScheduleConfig = {
        ...cur,
        enabled,
        everyHours,
        timeOfDay,
        keep,
        nextRunAt: !enabled ? null : changed || !cur.nextRunAt ? new Date(nextOccurrence(Date.now(), timeOfDay)).toISOString() : cur.nextRunAt,
      };
      all[siteId] = next;
      await persistConfigs();
      return state(siteId);
    },
    async filePath(siteId, id) {
      if (!safeId(id)) return null;
      const info = (await readIndex(siteId)).find((f) => f.id === id);
      if (!info) return null;
      return { file: path.join(dirFor(siteId), `${id}.html`), filename: info.filename };
    },
    async remove(siteId, id) {
      if (!safeId(id)) return false;
      const index = await readIndex(siteId);
      if (!index.some((f) => f.id === id)) return false;
      await fs.rm(path.join(dirFor(siteId), `${id}.html`), { force: true });
      await writeIndex(siteId, index.filter((f) => f.id !== id));
      return true;
    },
    start() {
      if (timer) return;
      timer = setInterval(() => void tick().catch(() => undefined), 60_000);
      timer.unref();
    },
    stop() {
      if (timer) clearInterval(timer);
      timer = null;
    },
  };
}
