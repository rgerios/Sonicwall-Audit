/** Relatório de Acessos e Consumo: tipos compartilhados entre servidor e interface. */
export interface AccessTimelinePoint {
  /** Início da hora (ISO). */
  t: string;
  connections: number;
  blocked: number;
  uploadBytes: number;
  downloadBytes: number;
}

export interface AccessSourceRow {
  ip: string;
  connections: number;
  blocked: number;
  uploadBytes: number;
  downloadBytes: number;
  totalBytes: number;
  /** Destinos distintos contatados. */
  destinations: number;
  topCategory: string | null;
  topCountry: string | null;
}

export interface AccessDestinationRow {
  ip: string;
  host: string | null;
  category: string;
  country: string | null;
  asnOrg: string | null;
  connections: number;
  blocked: number;
  totalBytes: number;
  threats: string[];
}

export interface AccessCategoryRow {
  name: string;
  connections: number;
  totalBytes: number;
  destinations: number;
}

export interface AccessCountryRow {
  code: string;
  connections: number;
  blocked: number;
  totalBytes: number;
  ips: number;
}

export interface AccessServiceRow {
  name: string;
  connections: number;
  totalBytes: number;
}

export interface AccessReportData {
  generatedAt: string;
  vendor: 'sonicwall' | 'fortigate';
  minutes: number;
  periodStart: string | null;
  periodEnd: string;
  analyzedEvents: number;
  dataSource: 'memory' | 'database';
  /** Percentual dos eventos coberto pelos maiores agrupamentos detalhados (100 = completo). */
  coveragePct: number;
  timedOut: boolean;
  totals: {
    connections: number;
    blocked: number;
    uploadBytes: number;
    downloadBytes: number;
    totalBytes: number;
    sources: number;
    destinations: number;
    countries: number;
    avgMbps: number;
    peakHourMbps: number;
    threatConnections: number;
  };
  timeline: AccessTimelinePoint[];
  sources: AccessSourceRow[];
  destinations: AccessDestinationRow[];
  categories: AccessCategoryRow[];
  countries: AccessCountryRow[];
  services: AccessServiceRow[];
  /** Quanto os demais (fora do Top) representam. */
  othersSources: { count: number; totalBytes: number };
}

/** Agendamento do relatório de Acessos e Consumo (por localidade). */
export interface ReportScheduleConfig {
  enabled: boolean;
  /** Intervalo em horas: 24, 72 ou 168. O período analisado é igual ao intervalo. */
  everyHours: number;
  /** Horário do dia (HH:MM, fuso do servidor) em que o relatório é gerado. */
  timeOfDay: string;
  /** Quantos relatórios guardar (os mais antigos são apagados). */
  keep: number;
  nextRunAt: string | null;
  lastRunAt: string | null;
  lastError: string | null;
}

export interface ReportFileInfo {
  id: string;
  createdAt: string;
  trigger: 'scheduled' | 'manual';
  minutes: number;
  periodStart: string | null;
  periodEnd: string;
  sizeBytes: number;
  connections: number;
  totalBytes: number;
  sources: number;
  filename: string;
}

export interface ReportScheduleState {
  config: ReportScheduleConfig;
  files: ReportFileInfo[];
  running: boolean;
  /** Quando a geração em andamento começou e o período (min) que ela cobre. */
  runningSince?: string | null;
  runningMinutes?: number | null;
}
