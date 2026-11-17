export type FirewallVendor = 'sonicwall' | 'fortigate';

export type ActiveSection = 'overview' | 'syslogs' | 'rules' | 'nats' | 'reports' | 'ai' | 'connect';

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

export interface UdpUnmatchedSource {
  address: string;
  serialNumber: string;
  count: number;
  lastSeenAt: string;
}

export interface UdpListenerStatus {
  running: boolean;
  port: number;
  bindAddress: string;
  packetsReceived: number;
  lastPacketAt: string | null;
  lastError: string | null;
  /** Eventos descartados por não pertencerem a nenhum firewall cadastrado. */
  unmatchedEvents?: number;
  unmatchedSources?: UdpUnmatchedSource[];
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

export interface RetentionStatus {
  retentionDays: number;
  autoPurgeEnabled: boolean;
  lastPurgeAt: string | null;
  lastPurgedCount: number;
  oldestEventAt: string | null;
  newestEventAt: string | null;
  storeSizeBytes: number;
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
  | 'traffic-volume'
  | 'anomaly'
  | 'ips'
  | 'malware'
  | 'critical-log'
  | 'suspicious-traffic'
  | 'vpn'
  | 'license'
  | 'resource'
  | 'collector'
  | 'config-change'
  | 'auth';

export interface AlertSettings {
  bandwidthUtilizationLimitPercent: number;
  bandwidthMbpsLimit: number;
  hourlyLogVolumeLimit: number;
  syslogTrafficMbLimit: number;
  blockedTrafficRatioLimitPercent: number;
  anomalyDetectionEnabled: boolean;
  anomalySpikeMultiplier: number;
  portScanUniquePortsThreshold: number;
  alertOnIps: boolean;
  alertOnCriticalLogs: boolean;
  suspiciousBlockThreshold: number;
  /** Janela deslizante (minutos) usada para avaliar os alertas baseados em syslog. */
  alertWindowMinutes: number;
  cpuLimitPercent: number;
  memoryLimitPercent: number;
  /** Minutos sem receber syslog antes de alertar (0 desativa). */
  silenceMinutes: number;
  alertOnVpnDown: boolean;
  alertOnLicense: boolean;
  alertOnConfigChange: boolean;
  adminLoginFailureThreshold: number;
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
  /** Preenchidos pelo motor de alertas persistente. */
  key?: string;
  status?: AlertStatus;
  firstSeenAt?: string;
  acknowledgedBy?: string | null;
  acknowledgedAt?: string | null;
}

export type AlertStatus = 'open' | 'acknowledged' | 'resolved';

export interface AlertRecord extends OverviewAlert {
  key: string;
  status: AlertStatus;
  firstSeenAt: string;
  lastDetectedAt: string;
  resolvedAt: string | null;
  acknowledgedBy: string | null;
  acknowledgedAt: string | null;
  notifiedAt: string | null;
}

export interface NotificationPublicConfig {
  enabled: boolean;
  minSeverity: AlertSeverity;
  notifyOnResolve: boolean;
  hasWebhook: boolean;
  hasTelegram: boolean;
  telegramChatId: string;
}

export interface MetricSample {
  ts: string;
  cpuPercent: number | null;
  memoryPercent: number | null;
  activeConnections: number | null;
  wanRxMbps: number;
  wanTxMbps: number;
}

export interface ConfigChangeEntry {
  at: string;
  rulesAdded: number;
  rulesRemoved: number;
  rulesModified: number;
  natsAdded: number;
  natsRemoved: number;
  natsModified: number;
  details: string[];
}

export interface SyncStatus {
  autoSyncMinutes: number;
  lastAttemptAt: string | null;
  lastError: string | null;
  consecutiveFailures: number;
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
  sync?: SyncStatus;
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
  /** Quantidade de eventos recentes mantidos em memória para as análises da tela. */
  analysisWindowSize?: number;
  sync?: SyncStatus;
  configChanges?: ConfigChangeEntry[];
  hitsObservedSince?: string | null;
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

export interface IpConsumptionTimelinePoint {
  bucketLabel: string;
  bytesSent: number;
  bytesRcvd: number;
  mbps: number;
  events: number;
}

export interface IpConsumptionDestination {
  ip: string;
  port: number | null;
  protocol: string;
  totalBytes: number;
  bytesSent: number;
  bytesRcvd: number;
  events: number;
}

export interface IpConsumptionConsumer {
  ip: string;
  totalBytes: number;
  bytesSent: number;
  bytesRcvd: number;
  avgMbps: number;
  events: number;
}

export interface IpConsumptionReport {
  ip: string;
  windowMinutes: number;
  totalBytes: number;
  bytesSent: number;
  bytesRcvd: number;
  avgMbps: number;
  sentMbps: number;
  rcvdMbps: number;
  eventCount: number;
  allowCount: number;
  blockedCount: number;
  lastSeenAt: string | null;
  timeline: IpConsumptionTimelinePoint[];
  topDestinations: IpConsumptionDestination[];
  topServices: Array<{ service: string; totalBytes: number; events: number }>;
  topConsumers: IpConsumptionConsumer[];
}

export type AppLogLevel = 'info' | 'warn' | 'error';

export interface AppLogEntry {
  id: string;
  ts: string;
  level: AppLogLevel;
  vendor: FirewallVendor | 'system';
  scope: string;
  message: string;
  detail?: string;
}
