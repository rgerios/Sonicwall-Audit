import type {
  AlertRecord,
  AlertSeverity,
  FirewallVendor,
  NotificationPublicConfig,
  NotificationSettings,
} from './types.ts';

export const DEFAULT_NOTIFICATION_SETTINGS: NotificationSettings = {
  enabled: false,
  minSeverity: 'critical',
  notifyOnResolve: false,
  webhookUrlEncrypted: '',
  telegramBotTokenEncrypted: '',
  telegramChatId: '',
};

export function normalizeNotificationSettings(
  raw?: Partial<NotificationSettings> | null
): NotificationSettings {
  return {
    enabled: raw?.enabled === true,
    minSeverity: raw?.minSeverity === 'warning' ? 'warning' : 'critical',
    notifyOnResolve: raw?.notifyOnResolve === true,
    webhookUrlEncrypted: typeof raw?.webhookUrlEncrypted === 'string' ? raw.webhookUrlEncrypted : '',
    telegramBotTokenEncrypted:
      typeof raw?.telegramBotTokenEncrypted === 'string' ? raw.telegramBotTokenEncrypted : '',
    telegramChatId: typeof raw?.telegramChatId === 'string' ? raw.telegramChatId : '',
  };
}

export function toPublicNotificationConfig(s: NotificationSettings): NotificationPublicConfig {
  return {
    enabled: s.enabled,
    minSeverity: s.minSeverity,
    notifyOnResolve: s.notifyOnResolve,
    hasWebhook: Boolean(s.webhookUrlEncrypted),
    hasTelegram: Boolean(s.telegramBotTokenEncrypted && s.telegramChatId),
    telegramChatId: s.telegramChatId,
  };
}

export function severityPasses(sev: AlertSeverity, min: AlertSeverity): boolean {
  return min === 'warning' ? true : sev === 'critical';
}

export interface NotificationMessage {
  kind: 'opened' | 'resolved' | 'test';
  vendor: FirewallVendor;
  siteName: string;
  alerts: AlertRecord[];
}

const MAX_ALERTS_IN_MESSAGE = 8;

function formatText(msg: NotificationMessage): string {
  const vendorLabel = msg.vendor === 'fortigate' ? 'FortiGate' : 'SonicWall';
  if (msg.kind === 'test') {
    return `✅ FW Audit: teste de notificação (${vendorLabel} · ${msg.siteName}). O canal está funcionando.`;
  }
  const header =
    msg.kind === 'resolved'
      ? `✅ FW Audit: ${msg.alerts.length} alerta(s) resolvido(s) — ${vendorLabel} · ${msg.siteName}`
      : `🚨 FW Audit: ${msg.alerts.length} novo(s) alerta(s) — ${vendorLabel} · ${msg.siteName}`;
  const lines = msg.alerts.slice(0, MAX_ALERTS_IN_MESSAGE).map((a) => {
    const sev = a.severity === 'critical' ? 'CRÍTICO' : 'ATENÇÃO';
    return msg.kind === 'resolved'
      ? `• ${a.title}`
      : `• [${sev}] ${a.title} (${a.metricValue})\n  ${a.description.slice(0, 300)}`;
  });
  if (msg.alerts.length > MAX_ALERTS_IN_MESSAGE) {
    lines.push(`… e mais ${msg.alerts.length - MAX_ALERTS_IN_MESSAGE} alerta(s).`);
  }
  return [header, ...lines].join('\n');
}

async function postJson(url: string, body: unknown): Promise<void> {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(10000),
  });
  if (!res.ok) {
    const detail = (await res.text().catch(() => '')).slice(0, 200);
    throw new Error(`HTTP ${res.status}${detail ? `: ${detail}` : ''}`);
  }
}

/**
 * Envia a mensagem para todos os canais configurados. Retorna a lista de erros por canal
 * (vazia quando tudo foi entregue). Segredos chegam já decifrados.
 */
export async function sendNotification(
  channels: { webhookUrl: string; telegramBotToken: string; telegramChatId: string },
  msg: NotificationMessage
): Promise<string[]> {
  const errors: string[] = [];
  const text = formatText(msg);

  if (channels.webhookUrl) {
    try {
      // "text" atende Slack/Teams/Mattermost; "content" atende Discord; o restante é
      // estruturado para integrações próprias (n8n, Zapier, scripts).
      await postJson(channels.webhookUrl, {
        text,
        content: text.slice(0, 1900),
        event: msg.kind,
        vendor: msg.vendor,
        site: msg.siteName,
        alerts: msg.alerts.map((a) => ({
          id: a.id,
          severity: a.severity,
          category: a.category,
          title: a.title,
          description: a.description,
          metricValue: a.metricValue,
          sourceIp: a.sourceIp ?? null,
          firstSeenAt: a.firstSeenAt,
          status: a.status,
        })),
      });
    } catch (err) {
      errors.push(`Webhook: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  if (channels.telegramBotToken && channels.telegramChatId) {
    try {
      await postJson(`https://api.telegram.org/bot${channels.telegramBotToken}/sendMessage`, {
        chat_id: channels.telegramChatId,
        text: text.slice(0, 4000),
        disable_web_page_preview: true,
      });
    } catch (err) {
      // Nunca propaga a URL (contém o token do bot)
      errors.push(`Telegram: ${err instanceof Error ? err.message.replace(channels.telegramBotToken, '***') : 'falha'}`);
    }
  }

  return errors;
}
