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
