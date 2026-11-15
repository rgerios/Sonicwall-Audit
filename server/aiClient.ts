import { GoogleGenAI, type Content } from '@google/genai';
import type {
  AiChatMessage,
  AiProviderSettings,
  AiProviderType,
  AiPublicConfig,
  AuditOverview,
  FirewallRule,
  NatPolicy,
  SyslogEvent,
} from './types.ts';

export const DEFAULT_AI_SETTINGS: AiProviderSettings = {
  provider: 'gemini',
  model: 'gemini-4-hydrogen',
  baseUrl: '',
  apiKey: '',
};

export function maskSecret(secret: string): string {
  const trimmed = secret.trim();
  if (!trimmed) return '';
  if (trimmed.length <= 8) return '••••••••';
  return `${trimmed.slice(0, 4)}••••${trimmed.slice(-4)}`;
}

export function toPublicAiConfig(settings: AiProviderSettings): AiPublicConfig {
  return {
    provider: settings.provider,
    model: settings.model,
    baseUrl: settings.baseUrl,
    hasCustomKey: settings.apiKey.trim().length > 0,
    hasServerGeminiKey: Boolean(process.env.GEMINI_API_KEY && process.env.GEMINI_API_KEY.trim().length > 0),
    maskedKey: maskSecret(settings.apiKey),
  };
}

function buildLogContextSnapshot(
  overview: AuditOverview,
  syslogs: SyslogEvent[],
  rules: FirewallRule[],
  nats: NatPolicy[]
): string {
  const flaggedRules = rules
    .filter((r) => r.status !== 'active')
    .slice(0, 25)
    .map(
      (r) =>
        `- [${r.id}] "${r.name}" (${r.fromZone}->${r.toZone}, ${r.source} -> ${r.destination}, svc=${r.service}, action=${r.action}) | status=${r.status} | hits_sonicos=${r.applianceHits} | hits_syslog=${r.syslogHits} | motivo: ${r.findingReason}`
    );

  const flaggedNats = nats
    .filter((n) => n.status !== 'active')
    .slice(0, 25)
    .map(
      (n) =>
        `- [${n.id}] "${n.name}" (${n.inboundInterface}->${n.outboundInterface}, orig=${n.origSource}->${n.origDestination}:${n.origService} => trans=${n.transSource}->${n.transDestination}:${n.transService}) | status=${n.status} | hits_sonicos=${n.applianceHits} | hits_syslog=${n.syslogHits} | motivo: ${n.findingReason}`
    );

  // Prioritize critical/blocked events plus recent allowed samples
  const blockedOrCritical = syslogs
    .filter(
      (ev) =>
        ev.priority <= 4 ||
        ev.action === 'drop' ||
        ev.action === 'deny' ||
        ev.action === 'reset'
    )
    .slice(0, 30);

  const recentAllow = syslogs.filter((ev) => ev.action === 'allow').slice(0, 12);
  const sampleEvents = [...blockedOrCritical, ...recentAllow].map(
    (ev) =>
      `[${ev.timestamp}] sev=${ev.severity} acao=${ev.action} ${ev.srcIp}:${ev.srcPort ?? '-'}(${ev.srcZone}) -> ${ev.dstIp}:${ev.dstPort ?? '-'}(${ev.dstZone}) proto=${ev.protocol} rule=${ev.ruleRef ?? '-'} nat=${ev.natRuleRef ?? '-'} msg="${ev.message}"`
  );

  const topBlocked = overview.topBlockedSources
    .map((s) => `${s.ip} (${s.zone}): ${s.count} drops`)
    .join('; ');
  const topPorts = overview.topTargetedPorts
    .map((p) => `${p.protocol}/${p.port}: ${p.count} total (${p.blocked} bloqueios)`)
    .join('; ');

  const ap = overview.appliance;
  const telemetry = overview.telemetry;
  const healthParts: string[] = [];
  if (ap.uptimeFormatted) healthParts.push(`Uptime: ${ap.uptimeFormatted}`);
  if (ap.romVersion) healthParts.push(`ROM: ${ap.romVersion}`);
  if (ap.safemodeVersion) healthParts.push(`SafeMode: ${ap.safemodeVersion}`);
  if (ap.haRole) healthParts.push(`HA: ${ap.haRole}`);
  if (ap.cpuPercent !== undefined && ap.cpuPercent !== null) healthParts.push(`CPU: ${ap.cpuPercent}%`);
  if (ap.memoryPercent !== undefined && ap.memoryPercent !== null) healthParts.push(`RAM: ${ap.memoryPercent}%`);
  if (ap.activeConnections !== undefined && ap.activeConnections !== null) {
    healthParts.push(
      `Conexões Ativas: ${ap.activeConnections}${ap.maxConnections ? ` / ${ap.maxConnections}` : ''}`
    );
  }

  const ifaceLines = (telemetry?.interfaces || []).map(
    (i) =>
      `- ${i.name} (${i.zone}, ${i.ip}, ${i.role}): status=${i.linkStatus.toUpperCase()} | link=${i.linkSpeedMbps} Mbps | Rx=${i.rxMbps} Mbps | Tx=${i.txMbps} Mbps | uso=${i.utilizationPercent}% | erros_rx=${i.rxErrors} erros_tx=${i.txErrors}`
  );
  const vpnLines = (telemetry?.vpns || []).map(
    (v) =>
      `- ${v.name} (${v.type.toUpperCase()}, peer=${v.peer}): status=${v.status.toUpperCase()}${v.activeUsers !== undefined ? ` | usuários=${v.activeUsers}` : ''}`
  );
  const licenseLines = (telemetry?.licenses || []).map(
    (l) => `- ${l.service}: ${l.status}${l.expiresAt ? ` (expira ${l.expiresAt})` : ''}`
  );

  return [
    `=== CONTEXTO ATUAL DO AMBIENTE SONICWALL ===`,
    ...(overview.activeSite
      ? [
          `Localidade Gerenciada: ${overview.activeSite.name}${overview.activeSite.location ? ` (${overview.activeSite.location})` : ''}`,
        ]
      : []),
    `Appliance: ${ap.model} | Serial: ${ap.serialNumber} | Firmware: ${ap.firmware} | Host: ${ap.host}`,
    ...(healthParts.length > 0 ? [`Saúde e Hardware: ${healthParts.join(' | ')}`] : []),
    `Total de syslogs na janela (${overview.retention.retentionDays} dias): ${overview.totalSyslogs} (Permitidos: ${overview.syslogBreakdown.allow}, Bloqueados: ${overview.syslogBreakdown.blocked}, Sistema: ${overview.syslogBreakdown.system}, Críticos/Erro: ${overview.syslogBreakdown.criticalAndError})`,
    `Resumo Regras Firewall: total=${overview.rulesSummary.total}, ativas=${overview.rulesSummary.active}, sem_uso=${overview.rulesSummary.unused}, sombreadas=${overview.rulesSummary.shadowed}, desabilitadas=${overview.rulesSummary.disabled}, permissivas=${overview.rulesSummary.overpermissive}`,
    `Resumo Políticas NAT: total=${overview.natsSummary.total}, ativas=${overview.natsSummary.active}, sem_uso=${overview.natsSummary.unused}, órfãs=${overview.natsSummary.orphaned}, desabilitadas=${overview.natsSummary.disabled}`,
    `Top IPs Bloqueados: ${topBlocked || 'Nenhum'}`,
    `Top Portas Visadas: ${topPorts || 'Nenhuma'}`,
    ...(ifaceLines.length > 0 ? [``, `Interfaces e Consumo de Link:`, ...ifaceLines] : []),
    ...(vpnLines.length > 0 ? [``, `Túneis VPN e Acesso Remoto:`, ...vpnLines] : []),
    ...(licenseLines.length > 0 ? [``, `Licenças de Serviços de Segurança:`, ...licenseLines] : []),
    ``,
    `Regras de Firewall Irregulares / Sem Uso:`,
    flaggedRules.length > 0 ? flaggedRules.join('\n') : '(Nenhuma regra irregular carregada)',
    ``,
    `Políticas NAT Irregulares / Sem Uso:`,
    flaggedNats.length > 0 ? flaggedNats.join('\n') : '(Nenhuma política NAT irregular carregada)',
    ``,
    `Amostra de Eventos de Syslog (priorizando alertas e bloqueios):`,
    sampleEvents.length > 0 ? sampleEvents.join('\n') : '(Nenhum syslog carregado ainda)',
  ].join('\n');
}

function buildSystemInstruction(contextSnapshot: string): string {
  return [
    `Você é um Engenheiro Sênior de Segurança de Redes especialista em firewalls SonicWall (SonicOS 6.5 / 7), análise de syslogs, políticas NAT e ambientes Linux.`,
    `Seu objetivo é traduzir os logs técnicos, drops, alertas de IPS/AV, regras sem uso e NATs em explicações claras, humanas, objetivas e acionáveis em português brasileiro.`,
    `Diretrizes obrigatórias:`,
    `1. Baseie-se exclusivamente nos dados reais fornecidos no contexto abaixo e nas mensagens do usuário. Nunca invente IPs, portas ou regras que não apareçam nos dados.`,
    `2. Se não houver logs ou regras carregados, informe claramente e oriente o usuário a carregar a amostra TZ470 ou importar/conectar seu SonicWall.`,
    `3. Ao explicar um evento ou risco, destaque: (a) o que aconteceu em linguagem simples, (b) se é tráfego normal ou ameaça/erro real, (c) qual ação prática tomar (ex.: desabilitar regra antes de excluir, bloquear IP, revisar NAT órfão).`,
    `4. Seja direto, organizado com listas curtas e cite os identificadores exatos (IPs, portas, IDs de regra/NAT) quando presentes.`,
    ``,
    contextSnapshot,
  ].join('\n');
}

async function callGeminiProvider(
  settings: AiProviderSettings,
  systemInstruction: string,
  history: AiChatMessage[],
  userMessage: string
): Promise<{ reply: string; modelUsed: string }> {
  const apiKey = settings.apiKey.trim() || process.env.GEMINI_API_KEY?.trim() || '';
  if (!apiKey) {
    throw new Error(
      'Nenhuma chave Gemini configurada. Adicione sua chave no campo de configuração acima ou defina GEMINI_API_KEY no ambiente do servidor.'
    );
  }

  const validGeminiModels = new Set([
    'gemini-4-hydrogen',
    'gemini-3.1-flash-lite',
    'gemini-4-argon',
    'gemini-4-carbon',
  ]);
  const model = settings.model.trim() || 'gemini-4-hydrogen';
  const resolvedModel = validGeminiModels.has(model) ? model : model;

  const ai = new GoogleGenAI({
    apiKey,
    httpOptions: {
      headers: {
        'User-Agent': 'aistudio-build',
      },
    },
  });

  const formattedHistory: Content[] = history.slice(-16).map((msg) => ({
    role: msg.role === 'assistant' ? 'model' : 'user',
    parts: [{ text: msg.content }],
  }));

  const chat = ai.chats.create({
    model: resolvedModel,
    config: {
      systemInstruction,
    },
    history: formattedHistory,
  });

  const response = await chat.sendMessage({ message: userMessage });
  const text = response.text?.trim();
  if (!text) {
    throw new Error('O modelo Gemini retornou uma resposta vazia.');
  }

  return { reply: text, modelUsed: resolvedModel };
}

function getDefaultBaseUrl(provider: AiProviderType): string {
  switch (provider) {
    case 'openrouter':
      return 'https://openrouter.ai/api/v1';
    case 'openai':
      return 'https://api.openai.com/v1';
    case 'local':
      return 'http://127.0.0.1:11434/v1';
    default:
      return '';
  }
}

async function callOpenAiCompatibleProvider(
  settings: AiProviderSettings,
  systemInstruction: string,
  history: AiChatMessage[],
  userMessage: string
): Promise<{ reply: string; modelUsed: string }> {
  const rawBaseUrl = (settings.baseUrl.trim() || getDefaultBaseUrl(settings.provider)).replace(/\/+$/, '');
  if (!rawBaseUrl) {
    throw new Error('Informe a URL base do provedor de IA.');
  }

  const endpoint = rawBaseUrl.endsWith('/chat/completions')
    ? rawBaseUrl
    : `${rawBaseUrl}/chat/completions`;

  const apiKey = settings.apiKey.trim();
  if (settings.provider !== 'local' && !apiKey) {
    throw new Error(
      `Informe sua chave de API para ${settings.provider === 'openrouter' ? 'OpenRouter' : 'OpenAI (GPT)'}.`
    );
  }

  const model =
    settings.model.trim() ||
    (settings.provider === 'openrouter'
      ? 'openai/gpt-4o-mini'
      : settings.provider === 'openai'
        ? 'gpt-4o-mini'
        : 'llama3.1');

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };
  if (apiKey) {
    headers.Authorization = `Bearer ${apiKey}`;
  }
  if (settings.provider === 'openrouter') {
    headers['HTTP-Referer'] = process.env.APP_URL || 'http://localhost:3000';
    headers['X-Title'] = 'SonicAudit';
  }

  const messages = [
    { role: 'system', content: systemInstruction },
    ...history.slice(-16).map((m) => ({
      role: m.role,
      content: m.content,
    })),
    { role: 'user', content: userMessage },
  ];

  const response = await fetch(endpoint, {
    method: 'POST',
    headers,
    body: JSON.stringify({
      model,
      messages,
    }),
  });

  const rawBody = await response.text();
  let parsed: Record<string, unknown> = {};
  try {
    parsed = rawBody ? (JSON.parse(rawBody) as Record<string, unknown>) : {};
  } catch {
    // Non-JSON response
  }

  if (!response.ok) {
    const errObj = parsed.error as Record<string, unknown> | undefined;
    const detail =
      (typeof errObj?.message === 'string' && errObj.message) ||
      (typeof parsed.message === 'string' && parsed.message) ||
      rawBody.slice(0, 200) ||
      `HTTP ${response.status}`;
    throw new Error(`Erro no provedor (${settings.provider}): ${detail}`);
  }

  const choices = Array.isArray(parsed.choices) ? parsed.choices : [];
  const first = (choices[0] && typeof choices[0] === 'object' ? choices[0] : {}) as Record<
    string,
    unknown
  >;
  const messageObj = (
    first.message && typeof first.message === 'object' ? first.message : {}
  ) as Record<string, unknown>;
  const reply = typeof messageObj.content === 'string' ? messageObj.content.trim() : '';

  if (!reply) {
    throw new Error('O provedor de IA não retornou texto na resposta.');
  }

  return { reply, modelUsed: model };
}

export async function runAiLogAnalysis(params: {
  settings: AiProviderSettings;
  overview: AuditOverview;
  syslogs: SyslogEvent[];
  rules: FirewallRule[];
  nats: NatPolicy[];
  history: AiChatMessage[];
  message: string;
}): Promise<{ reply: string; modelUsed: string; provider: AiProviderType }> {
  const contextSnapshot = buildLogContextSnapshot(
    params.overview,
    params.syslogs,
    params.rules,
    params.nats
  );
  const systemInstruction = buildSystemInstruction(contextSnapshot);

  if (params.settings.provider === 'gemini') {
    const result = await callGeminiProvider(
      params.settings,
      systemInstruction,
      params.history,
      params.message
    );
    return { ...result, provider: 'gemini' };
  }

  const result = await callOpenAiCompatibleProvider(
    params.settings,
    systemInstruction,
    params.history,
    params.message
  );
  return { ...result, provider: params.settings.provider };
}
