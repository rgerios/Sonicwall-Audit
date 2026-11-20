import type {
  AiProviderType,
  AlertRecord,
  AlertSeverity,
  AlertSettings,
  ApplianceMetadata,
  ConfigChangeEntry,
  FirewallRule,
  FirewallVendor,
  MetricSample,
  NatPolicy,
  SyslogEvent,
  TelemetrySnapshot,
} from '../shared/types.ts';

export * from '../shared/types.ts';

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

export interface AiProviderSettings {
  provider: AiProviderType;
  model: string;
  baseUrl: string;
  apiKey: string;
  /** Mascara IPs, MACs e e-mails antes de enviar à IA (padrão: ligado). */
  anonymize?: boolean;
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
  /** Estado persistente dos alertas (abertos, reconhecidos e histórico). */
  alertRecords: AlertRecord[];
  autoSyncMinutes: number;
  lastSyncAttemptAt: string | null;
  lastSyncError: string | null;
  consecutiveSyncFailures: number;
  configChanges: ConfigChangeEntry[];
  /** Início da janela em que os contadores de uso por syslog vêm sendo acumulados. */
  hitsObservedSince: string | null;
  /** Amostras de telemetria (modo JSON local; com PostgreSQL ficam na tabela metrics). */
  metrics?: MetricSample[];
  createdAt: string;
  updatedAt: string;
}

export interface NotificationSettings {
  enabled: boolean;
  minSeverity: AlertSeverity;
  notifyOnResolve: boolean;
  webhookUrlEncrypted: string;
  telegramBotTokenEncrypted: string;
  telegramChatId: string;
}

export interface UdpListenerConfig {
  enabled: boolean;
  port: number;
  bindAddress: string;
}

export interface DataStore {
  vendor: FirewallVendor;
  activeSiteId: string;
  sites: Record<string, FirewallSiteRecord>;
  aiSettings?: AiProviderSettings;
  notificationSettings?: NotificationSettings;
  udpListener?: UdpListenerConfig;
}
