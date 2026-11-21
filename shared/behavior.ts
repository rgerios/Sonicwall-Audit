export type BehaviorThreatCategory = 'blacklist' | 'botnet' | 'tor';

export interface BehaviorCountry {
  code: string;
  connections: number;
  blocked: number;
  bytes: number;
  ips: number;
  threatIps: number;
}

export interface BehaviorIp {
  ip: string;
  country: string | null;
  asn: number | null;
  asnOrg: string | null;
  connections: number;
  blocked: number;
  bytes: number;
  threats: string[];
  categories: BehaviorThreatCategory[];
  topSources: Array<{ ip: string; count: number }>;
  lastSeen: string | null;
}

/** Conexão recente (para a animação em tempo real). */
export interface BehaviorFlow {
  at: string;
  country: string;
  blocked: boolean;
  threat: boolean;
}

export interface BehaviorIntelSource {
  id: string;
  label: string;
  kind: 'geo' | 'asn' | 'list';
  category?: BehaviorThreatCategory;
  updatedAt: string | null;
  entries: number;
  error: string | null;
}

export interface BehaviorIntelStatus {
  updating: boolean;
  lastCheckAt: string | null;
  autoUpdate: boolean;
  ready: boolean;
  sources: BehaviorIntelSource[];
}

export interface BehaviorReport {
  generatedAt: string;
  minutes: number;
  originCountry: string;
  analyzedEvents: number;
  publicIps: number;
  totals: { connections: number; blocked: number; countries: number; threatConnections: number; unknownConnections: number };
  countries: BehaviorCountry[];
  ips: BehaviorIp[];
  threats: BehaviorIp[];
  flows: BehaviorFlow[];
  intel: BehaviorIntelStatus;
  dataSource: 'memory' | 'database';
  truncated: boolean;
}
