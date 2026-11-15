export type FirewallVendor = 'sonicwall' | 'fortigate';

export type SyslogSeverity =
  | 'emergency'
  | 'alert'
  | 'critical'
  | 'error'
  | 'warning'
  | 'notice'
  | 'info'
  | 'debug';

export type SyslogAction = 'allow' | 'drop' | 'deny' | 'reset' | 'nat' | 'system';

export interface SyslogEvent {
  id: string;
  timestamp: string;
  firewallHost: string;
  serialNumber: string;
  priority: number;
  severity: SyslogSeverity;
  categoryCode: string;
  categoryName: string;
  messageId: string;
  action: SyslogAction;
  srcIp: string;
  srcPort: number | null;
  srcZone: string;
  dstIp: string;
  dstPort: number | null;
  dstZone: string;
  natSrcIp: string | null;
  natSrcPort: number | null;
  natDstIp: string | null;
  natDstPort: number | null;
  protocol: string;
  ruleRef: string | null;
  natRuleRef: string | null;
  bytesSent: number;
  bytesRcvd: number;
  appName: string | null;
  user: string | null;
  message: string;
  raw: string;
  source: 'upload' | 'udp' | 'paste' | 'sample';
  ingestedAt: string;
}

export type RuleHealthStatus =
  | 'active'
  | 'unused'
  | 'shadowed'
  | 'disabled'
  | 'overpermissive';

export interface FirewallRule {
  id: string;
  uuid?: string;
  name: string;
  priority: number;
  fromZone: string;
  toZone: string;
  source: string;
  destination: string;
  service: string;
  action: 'allow' | 'deny' | 'discard';
  enabled: boolean;
  applianceHits: number;
  syslogHits: number;
  lastHitAt: string | null;
  comment: string;
  status: RuleHealthStatus;
  findingReason: string;
  shadowedBy?: string;
  sourceOrigin: 'api' | 'exp' | 'json' | 'sample';
}

export type NatHealthStatus = 'active' | 'unused' | 'disabled' | 'orphaned';

export interface NatPolicy {
  id: string;
  uuid?: string;
  name: string;
  priority: number;
  inboundInterface: string;
  outboundInterface: string;
  origSource: string;
  transSource: string;
  origDestination: string;
  transDestination: string;
  origService: string;
  transService: string;
  enabled: boolean;
  applianceHits: number;
  syslogHits: number;
  lastHitAt: string | null;
  comment: string;
  status: NatHealthStatus;
  findingReason: string;
  sourceOrigin: 'api' | 'exp' | 'json' | 'sample';
}

export interface UdpListenerStatus {
  running: boolean;
  port: number;
  bindAddress: string;
  packetsReceived: number;
  lastPacketAt: string | null;
  lastError: string | null;
}

export interface ApplianceMetadata {
  model: string;
  serialNumber: string;
  firmware: string;
  romVersion?: string;
  safemodeVersion?: string;
  uptimeFormatted?: string;
  uptimeSeconds?: number;
  cpuPercent?: number | null;
  memoryPercent?: number | null;
  activeConnections?: number | null;
  maxConnections?: number | null;
  haRole?: string;
  host: string;
  lastSyncAt: string | null;
  dataSource: 'none' | 'api' | 'exp' | 'json' | 'sample';
}

export interface InterfaceTelemetry {
  name: string;
  zone: string;
  ip: string;
  linkStatus: 'up' | 'down';
  linkSpeedMbps: number;
  rxMbps: number;
  txMbps: number;
  rxBytes: number;
  txBytes: number;
  rxErrors: number;
  txErrors: number;
  utilizationPercent: number;
  role: 'wan-primary' | 'wan-failover' | 'internal';
}

export interface VpnTunnelStatus {
  name: string;
  type: 'ipsec' | 'sslvpn';
  peer: string;
  status: 'up' | 'down';
  rxBytes: number;
  txBytes: number;
  activeUsers?: number;
}

export interface SecurityServiceLicense {
  service: string;
  status: 'active' | 'expiring' | 'expired' | 'unlicensed';
  expiresAt: string | null;
}

export interface TelemetrySnapshot {
  interfaces: InterfaceTelemetry[];
  vpns: VpnTunnelStatus[];
  licenses: SecurityServiceLicense[];
}

export interface HourlyLogVolumePoint {
  hourLabel: string;
  total: number;
  allow: number;
  blocked: number;
}

export type AlertSeverity = 'critical' | 'warning';

export type AlertCategory =
  | 'bandwidth'
  | 'link-down'
  | 'ips'
  | 'malware'
  | 'critical-log'
  | 'suspicious-traffic';

export interface AlertSettings {
  bandwidthUtilizationLimitPercent: number;
  bandwidthMbpsLimit: number;
  alertOnIps: boolean;
  alertOnCriticalLogs: boolean;
  suspiciousBlockThreshold: number;
}

export interface OverviewAlert {
  id: string;
  severity: AlertSeverity;
  category: AlertCategory;
  title: string;
  description: string;
  metricValue: string;
  sourceIp?: string;
  interfaceName?: string;
  eventCount?: number;
  lastSeenAt?: string;
  syslogFilterQuery?: string;
  aiPrompt?: string;
}

export interface FirewallConnectionStored {
  host: string;
  port: number;
  protocol: 'https' | 'http';
  username: string;
  passwordEncrypted?: string;
  authMode?: 'basic' | 'token';
  vdom?: string;
  ignoreTlsErrors: boolean;
}

export interface FirewallConnectionPublic {
  host: string;
  port: number;
  protocol: 'https' | 'http';
  username: string;
  hasSavedPassword: boolean;
  authMode?: 'basic' | 'token';
  vdom?: string;
  ignoreTlsErrors: boolean;
}

export interface FirewallSiteSummary {
  id: string;
  vendor: FirewallVendor;
  name: string;
  location: string;
  notes: string;
  appliance: ApplianceMetadata;
  connection: FirewallConnectionPublic;
  totalSyslogs: number;
  rulesCount: number;
  natsCount: number;
  alertsCount: number;
  criticalAlertsCount: number;
  createdAt: string;
  updatedAt: string;
}

export interface AuthStatus {
  authenticated: boolean;
  needsSetup: boolean;
  username: string | null;
}

export interface AuditOverview {
  vendor: FirewallVendor;
  activeSite: {
    id: string;
    vendor: FirewallVendor;
    name: string;
    location: string;
    notes: string;
    connection: FirewallConnectionPublic;
  };
  sites: FirewallSiteSummary[];
  appliance: ApplianceMetadata;
  totalSyslogs: number;
  syslogBreakdown: {
    allow: number;
    blocked: number;
    system: number;
    criticalAndError: number;
    warning: number;
    infoAndNotice: number;
  };
  rulesSummary: {
    total: number;
    active: number;
    unused: number;
    shadowed: number;
    disabled: number;
    overpermissive: number;
  };
  natsSummary: {
    total: number;
    active: number;
    unused: number;
    disabled: number;
    orphaned: number;
  };
  topBlockedSources: Array<{ ip: string; count: number; zone: string }>;
  topTargetedPorts: Array<{ port: string; protocol: string; count: number; blocked: number }>;
  zoneTraffic: Array<{ pair: string; allow: number; blocked: number }>;
  hourlyLogVolume: HourlyLogVolumePoint[];
  telemetry: TelemetrySnapshot;
  alertSettings: AlertSettings;
  alerts: OverviewAlert[];
  udpStatus: UdpListenerStatus;
  retention: RetentionStatus;
}

export interface RetentionStatus {
  retentionDays: number;
  autoPurgeEnabled: boolean;
  lastPurgeAt: string | null;
  lastPurgedCount: number;
  oldestEventAt: string | null;
  newestEventAt: string | null;
  storeSizeBytes: number;
}

export interface AuditReportData {
  generatedAt: string;
  overview: AuditOverview;
  recommendations: Array<{
    severity: 'high' | 'medium' | 'low';
    title: string;
    detail: string;
    affectedCount: number;
  }>;
  criticalEvents: SyslogEvent[];
  rules: FirewallRule[];
  nats: NatPolicy[];
  cliDisableScript: string;
}

export type AiProviderType = 'gemini' | 'openrouter' | 'openai' | 'local';

export interface AiProviderSettings {
  provider: AiProviderType;
  model: string;
  baseUrl: string;
  apiKey: string;
}

export interface AiPublicConfig {
  provider: AiProviderType;
  model: string;
  baseUrl: string;
  hasCustomKey: boolean;
  hasServerGeminiKey: boolean;
  maskedKey: string;
}

export interface AiChatMessage {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  timestamp: string;
  provider?: AiProviderType;
  model?: string;
}

export interface FirewallSiteRecord {
  id: string;
  vendor: FirewallVendor;
  name: string;
  location: string;
  notes: string;
  connection: FirewallConnectionStored;
  appliance: ApplianceMetadata;
  retentionDays: number;
  lastPurgeAt: string | null;
  lastPurgedCount: number;
  syslogs: SyslogEvent[];
  rules: FirewallRule[];
  nats: NatPolicy[];
  telemetry: TelemetrySnapshot;
  alertSettings: AlertSettings;
  createdAt: string;
  updatedAt: string;
}

export interface DataStore {
  vendor: FirewallVendor;
  activeSiteId: string;
  sites: Record<string, FirewallSiteRecord>;
  aiSettings?: AiProviderSettings;
}
