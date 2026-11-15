import { useEffect, useRef, useState } from 'react';
import {
  Bot,
  Check,
  KeyRound,
  RotateCcw,
  Send,
  Settings2,
  Trash2,
} from 'lucide-react';
import type {
  AiChatMessage,
  AiProviderType,
  AiPublicConfig,
  AuditOverview,
  FirewallVendor,
} from '../types.ts';
import { vendorApiUrl } from '../utils/vendorApi.ts';
import { VENDOR_THEMES } from '../utils/vendorTheme.ts';

interface AiAnalystViewProps {
  vendor: FirewallVendor;
  overview: AuditOverview | null;
  pendingPrompt: string | null;
  onConsumePendingPrompt: () => void;
}

const PROVIDER_DEFAULTS: Record<
  AiProviderType,
  { label: string; defaultModel: string; defaultBaseUrl: string; placeholderModel: string }
> = {
  gemini: {
    label: 'Google Gemini',
    defaultModel: 'gemini-4-hydrogen',
    defaultBaseUrl: '',
    placeholderModel: 'gemini-4-hydrogen',
  },
  openrouter: {
    label: 'OpenRouter',
    defaultModel: 'openai/gpt-4o-mini',
    defaultBaseUrl: 'https://openrouter.ai/api/v1',
    placeholderModel: 'anthropic/claude-3.5-sonnet',
  },
  openai: {
    label: 'OpenAI (GPT)',
    defaultModel: 'gpt-4o-mini',
    defaultBaseUrl: 'https://api.openai.com/v1',
    placeholderModel: 'gpt-4o-mini',
  },
  local: {
    label: 'LLM Local (Ollama / LM Studio)',
    defaultModel: 'llama3.1',
    defaultBaseUrl: 'http://127.0.0.1:11434/v1',
    placeholderModel: 'llama3.1 ou qwen2.5:14b',
  },
};

export function AiAnalystView({
  vendor,
  overview,
  pendingPrompt,
  onConsumePendingPrompt,
}: AiAnalystViewProps) {
  const theme = VENDOR_THEMES[vendor];
  const [config, setConfig] = useState<AiPublicConfig | null>(null);
  const [provider, setProvider] = useState<AiProviderType>('gemini');
  const [model, setModel] = useState('gemini-4-hydrogen');
  const [baseUrl, setBaseUrl] = useState('');
  const [apiKeyInput, setApiKeyInput] = useState('');
  const [savingConfig, setSavingConfig] = useState(false);
  const [configStatus, setConfigStatus] = useState<{ type: 'ok' | 'err'; text: string } | null>(
    null
  );

  const [messages, setMessages] = useState<AiChatMessage[]>([]);
  const [input, setInput] = useState('');
  const [sending, setSending] = useState(false);
  const [chatError, setChatError] = useState<string | null>(null);

  const threadEndRef = useRef<HTMLDivElement | null>(null);

  const quickPrompts = [
    `Explique em linguagem simples os principais bloqueios e alertas críticos dos logs ${theme.label}.`,
    vendor === 'fortigate'
      ? 'Quais políticas FortiOS, VIPs e IP Pools sem uso devo desabilitar primeiro e por quê?'
      : 'Quais regras de firewall e políticas NAT sem uso devo desabilitar primeiro e por quê?',
    'Há sinais de ataque, varredura de portas (scan) ou força bruta nos syslogs atuais?',
    'Gere um resumo executivo curto em linguagem não técnica para apresentar à diretoria.',
  ];

  useEffect(() => {
    setMessages([]);
    setChatError(null);
  }, [vendor]);

  useEffect(() => {
    const loadConfig = async () => {
      const res = await fetch(vendorApiUrl(vendor, '/ai/config'));
      if (res.ok) {
        const data = (await res.json()) as AiPublicConfig;
        setConfig(data);
        setProvider(data.provider);
        setModel(data.model || PROVIDER_DEFAULTS[data.provider].defaultModel);
        setBaseUrl(data.baseUrl || PROVIDER_DEFAULTS[data.provider].defaultBaseUrl);
      }
    };
    void loadConfig();
  }, [vendor]);

  useEffect(() => {
    threadEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, sending]);

  useEffect(() => {
    if (pendingPrompt) {
      setInput(pendingPrompt);
      onConsumePendingPrompt();
    }
  }, [pendingPrompt, onConsumePendingPrompt]);

  const handleSelectProvider = (next: AiProviderType) => {
    setProvider(next);
    setModel(PROVIDER_DEFAULTS[next].defaultModel);
    setBaseUrl(PROVIDER_DEFAULTS[next].defaultBaseUrl);
    setConfigStatus(null);
  };

  const handleSaveConfig = async (e: React.FormEvent) => {
    e.preventDefault();
    setSavingConfig(true);
    setConfigStatus(null);
    try {
      const res = await fetch(vendorApiUrl(vendor, '/ai/config'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          provider,
          model,
          baseUrl,
          apiKey: apiKeyInput.trim() || undefined,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setConfigStatus({ type: 'err', text: data.error || 'Erro ao salvar configuração.' });
      } else {
        setConfig(data as AiPublicConfig);
        setApiKeyInput('');
        setConfigStatus({
          type: 'ok',
          text: `Provedor ${PROVIDER_DEFAULTS[provider].label} (${data.model}) salvo no servidor.`,
        });
      }
    } catch {
      setConfigStatus({ type: 'err', text: 'Falha de rede ao salvar configuração.' });
    } finally {
      setSavingConfig(false);
    }
  };

  const handleClearKey = async () => {
    setSavingConfig(true);
    try {
      const res = await fetch(vendorApiUrl(vendor, '/ai/config'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          provider,
          model,
          baseUrl,
          clearKey: true,
        }),
      });
      if (res.ok) {
        const data = (await res.json()) as AiPublicConfig;
        setConfig(data);
        setConfigStatus({ type: 'ok', text: 'Chave customizada removida do servidor.' });
      }
    } finally {
      setSavingConfig(false);
    }
  };

  const sendMessage = async (textToSend?: string) => {
    const content = (textToSend ?? input).trim();
    if (!content || sending) return;

    const userMsg: AiChatMessage = {
      id: crypto.randomUUID(),
      role: 'user',
      content,
      timestamp: new Date().toISOString(),
    };

    const historySnapshot = [...messages];
    setMessages((prev) => [...prev, userMsg]);
    if (!textToSend) setInput('');
    setSending(true);
    setChatError(null);

    try {
      const res = await fetch(vendorApiUrl(vendor, '/ai/chat'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: content,
          history: historySnapshot,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setChatError(data.error || 'Erro ao obter análise da IA.');
      } else {
        const assistantMsg: AiChatMessage = {
          id: crypto.randomUUID(),
          role: 'assistant',
          content: data.reply,
          timestamp: data.timestamp || new Date().toISOString(),
          provider: data.provider,
          model: data.modelUsed,
        };
        setMessages((prev) => [...prev, assistantMsg]);
      }
    } catch {
      setChatError('Erro de comunicação com o servidor ao consultar a IA.');
    } finally {
      setSending(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      void sendMessage();
    }
  };

  return (
    <div className="grid grid-cols-1 xl:grid-cols-3 gap-6 items-start">
      <div className="xl:col-span-2 bg-white border border-[var(--fw-border)] rounded-lg flex flex-col h-[calc(100vh-148px)] min-h-[560px] overflow-hidden">
        <div className="px-5 py-3.5 border-b border-[var(--fw-border)] bg-[var(--fw-surface)] flex flex-wrap items-center justify-between gap-3 shrink-0">
          <div className="flex items-center gap-2.5 min-w-0">
            <Bot className="w-4 h-4 text-[var(--fw-accent)] shrink-0" />
            <div className="min-w-0">
              <h2 className="text-sm font-semibold text-[var(--fw-heading)] truncate">
                Analista de Logs {theme.label}
              </h2>
              <p className="text-[11px] text-[var(--fw-text-muted)] truncate font-mono">
                {PROVIDER_DEFAULTS[config?.provider || provider].label} ·{' '}
                {config?.model || model} · Contexto:{' '}
                {(overview?.totalSyslogs ?? 0).toLocaleString('pt-BR')} logs /{' '}
                {overview?.rulesSummary.total ?? 0} regras / {overview?.natsSummary.total ?? 0} NATs
              </p>
            </div>
          </div>

          {messages.length > 0 && (
            <button
              type="button"
              onClick={() => {
                setMessages([]);
                setChatError(null);
              }}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-[var(--fw-text-body)] bg-white border border-[var(--fw-border-strong)] rounded-md hover:bg-[var(--fw-bg)] whitespace-nowrap"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              Nova Conversa
            </button>
          )}
        </div>

        <div className="flex-1 overflow-y-auto p-5 space-y-4 bg-[var(--fw-bg)]/60">
          {messages.length === 0 ? (
            <div className="max-w-2xl mx-auto py-8 space-y-5">
              <div>
                <h3 className="text-base font-semibold text-[var(--fw-heading)]">
                  Interpretação em linguagem humana dos seus logs e regras ({theme.label})
                </h3>
                <p className="text-xs text-[var(--fw-text-muted)] mt-1.5 leading-relaxed">
                  Pergunte sobre qualquer IP, porta, bloqueio de IPS/Antivírus, regra sem uso ou
                  política NAT/VIP. O assistente lê automaticamente os dados carregados no FW Audit e
                  mantém o contexto da conversa.
                </p>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                {quickPrompts.map((prompt) => (
                  <button
                    key={prompt}
                    type="button"
                    onClick={() => void sendMessage(prompt)}
                    disabled={sending}
                    className="text-left p-3.5 bg-white border border-[var(--fw-border)] rounded-md hover:border-[var(--fw-border-strong)] hover:bg-[var(--fw-surface)]/70 transition-colors text-xs text-[var(--fw-text-body)] leading-snug"
                  >
                    {prompt}
                  </button>
                ))}
              </div>
            </div>
          ) : (
            messages.map((msg) => (
              <div
                key={msg.id}
                className={`flex flex-col ${
                  msg.role === 'user' ? 'items-end' : 'items-start'
                }`}
              >
                <div
                  className={`max-w-[85%] rounded-lg px-4 py-3 text-xs leading-relaxed border ${
                    msg.role === 'user'
                      ? 'bg-[var(--fw-surface-alt)] border-[var(--fw-border-strong)] text-[var(--fw-heading)]'
                      : 'bg-white border-[var(--fw-border)] text-[var(--fw-text)]'
                  }`}
                >
                  <p className="whitespace-pre-wrap">{msg.content}</p>
                </div>
                <span className="text-[11px] text-[var(--fw-text-subtle)] mt-1 font-mono tabular-nums">
                  {msg.role === 'user' ? 'Você' : msg.model || 'Assistente'} ·{' '}
                  {new Date(msg.timestamp).toLocaleTimeString('pt-BR', {
                    hour: '2-digit',
                    minute: '2-digit',
                  })}
                </span>
              </div>
            ))
          )}

          {sending && (
            <div className="flex items-start">
              <div className="bg-white border border-[var(--fw-border)] rounded-lg px-4 py-3 text-xs text-[var(--fw-text-muted)]">
                Analisando logs e políticas do {theme.label}...
              </div>
            </div>
          )}

          {chatError && (
            <div className="p-3 rounded-md border border-red-200 bg-red-50 text-xs text-red-800">
              {chatError}
            </div>
          )}

          <div ref={threadEndRef} />
        </div>

        <form
          onSubmit={(e) => {
            e.preventDefault();
            void sendMessage();
          }}
          className="p-4 border-t border-[var(--fw-border)] bg-white shrink-0 space-y-2"
        >
          <div className="flex items-end gap-2">
            <textarea
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
              rows={2}
              placeholder="Pergunte sobre um IP, drop, alerta IPS ou cole uma linha de syslog... (Enter envia)"
              className="flex-1 px-3 py-2 text-xs border border-[var(--fw-border-strong)] rounded-md bg-[var(--fw-bg-input)] focus:outline-none focus:ring-2 focus:ring-[var(--fw-accent-mid)] resize-none"
            />
            <button
              type="submit"
              disabled={sending || !input.trim()}
              className="inline-flex items-center gap-1.5 px-4 py-2.5 text-xs font-medium text-white bg-[var(--fw-accent)] rounded-md hover:bg-[var(--fw-accent-hover)] disabled:opacity-40 whitespace-nowrap shrink-0"
            >
              <Send className="w-3.5 h-3.5" />
              Enviar
            </button>
          </div>
        </form>
      </div>

      <form
        onSubmit={handleSaveConfig}
        className="bg-white border border-[var(--fw-border)] rounded-lg p-5 space-y-4"
      >
        <div className="pb-3 border-b border-[var(--fw-border-soft)] flex items-center gap-2">
          <Settings2 className="w-4 h-4 text-[var(--fw-accent)]" />
          <div>
            <h3 className="text-sm font-semibold text-[var(--fw-heading)]">
              Provedor de IA e Chave de API
            </h3>
            <p className="text-[11px] text-[var(--fw-text-muted)]">
              Compartilhado entre SonicWall e FortiGate no servidor Linux
            </p>
          </div>
        </div>

        <div className="space-y-1.5">
          <label className="block text-xs font-medium text-[var(--fw-text-body)]">Provedor</label>
          <div className="grid grid-cols-2 gap-1.5 p-1 bg-[var(--fw-surface-alt)] rounded-md">
            {(Object.keys(PROVIDER_DEFAULTS) as AiProviderType[]).map((key) => (
              <button
                key={key}
                type="button"
                onClick={() => handleSelectProvider(key)}
                className={`px-2.5 py-1.5 text-xs font-medium rounded transition-colors truncate ${
                  provider === key
                    ? 'bg-white text-[var(--fw-heading)] shadow-xs'
                    : 'text-[var(--fw-text-body)] hover:text-[var(--fw-heading)]'
                }`}
              >
                {key === 'local'
                  ? 'Local (Ollama)'
                  : key === 'gemini'
                    ? 'Gemini'
                    : key === 'openrouter'
                      ? 'OpenRouter'
                      : 'OpenAI GPT'}
              </button>
            ))}
          </div>
        </div>

        <div>
          <label className="block text-xs font-medium text-[var(--fw-text-body)] mb-1">
            Modelo
          </label>
          {provider === 'gemini' ? (
            <select
              value={model}
              onChange={(e) => setModel(e.target.value)}
              className="w-full px-3 py-2 text-xs font-mono border border-[var(--fw-border-strong)] rounded-md bg-white focus:outline-none focus:ring-2 focus:ring-[var(--fw-accent-mid)]"
            >
              <option value="gemini-4-hydrogen">gemini-4-hydrogen (Análise Geral)</option>
              <option value="gemini-3.1-flash-lite">gemini-3.1-flash-lite (Triagem Rápida)</option>
            </select>
          ) : (
            <input
              type="text"
              value={model}
              onChange={(e) => setModel(e.target.value)}
              placeholder={PROVIDER_DEFAULTS[provider].placeholderModel}
              className="w-full px-3 py-2 text-xs font-mono border border-[var(--fw-border-strong)] rounded-md bg-[var(--fw-bg-input)] focus:outline-none focus:ring-2 focus:ring-[var(--fw-accent-mid)]"
            />
          )}
        </div>

        {provider !== 'gemini' && (
          <div>
            <label className="block text-xs font-medium text-[var(--fw-text-body)] mb-1">
              Endpoint Base (OpenAI-compatível)
            </label>
            <input
              type="text"
              value={baseUrl}
              onChange={(e) => setBaseUrl(e.target.value)}
              placeholder={PROVIDER_DEFAULTS[provider].defaultBaseUrl}
              className="w-full px-3 py-2 text-xs font-mono border border-[var(--fw-border-strong)] rounded-md bg-[var(--fw-bg-input)] focus:outline-none focus:ring-2 focus:ring-[var(--fw-accent-mid)]"
            />
            {provider === 'local' && (
              <p className="text-[11px] text-[var(--fw-text-muted)] mt-1">
                Ollama: <span className="font-mono">http://127.0.0.1:11434/v1</span> · LM Studio:{' '}
                <span className="font-mono">http://127.0.0.1:1234/v1</span>
              </p>
            )}
          </div>
        )}

        <div>
          <label className="block text-xs font-medium text-[var(--fw-text-body)] mb-1">
            Chave de API {provider === 'local' ? '(Opcional para servidor local)' : ''}
          </label>
          <div className="relative">
            <KeyRound className="w-3.5 h-3.5 text-[var(--fw-text-subtle)] absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="password"
              value={apiKeyInput}
              onChange={(e) => setApiKeyInput(e.target.value)}
              placeholder={
                config?.hasCustomKey
                  ? `Salva (${config.maskedKey}) — digite para substituir`
                  : provider === 'gemini' && config?.hasServerGeminiKey
                    ? 'Usando GEMINI_API_KEY do servidor (opcional)'
                    : provider === 'local'
                      ? 'Opcional (vazio para Ollama)'
                      : 'Cole sua chave de API aqui'
              }
              className="w-full pl-9 pr-3 py-2 text-xs font-mono border border-[var(--fw-border-strong)] rounded-md bg-[var(--fw-bg-input)] focus:outline-none focus:ring-2 focus:ring-[var(--fw-accent-mid)]"
            />
          </div>

          <div className="mt-2 flex items-center justify-between text-[11px] text-[var(--fw-text-muted)]">
            <span>
              {config?.hasCustomKey
                ? `Chave salva: ${config.maskedKey}`
                : provider === 'gemini' && config?.hasServerGeminiKey
                  ? 'Chave padrão do servidor ativa'
                  : provider === 'local'
                    ? 'Sem chave exigida localmente'
                    : 'Nenhuma chave configurada'}
            </span>
            {config?.hasCustomKey && (
              <button
                type="button"
                onClick={() => void handleClearKey()}
                className="inline-flex items-center gap-1 text-red-700 hover:underline"
              >
                <Trash2 className="w-3 h-3" /> Remover
              </button>
            )}
          </div>
        </div>

        {configStatus && (
          <div
            className={`p-3 rounded-md border text-xs flex items-start gap-2 ${
              configStatus.type === 'ok'
                ? 'bg-[var(--fw-surface)] border-[var(--fw-border-strong)] text-[var(--fw-heading)]'
                : 'bg-red-50 border-red-200 text-red-800'
            }`}
          >
            {configStatus.type === 'ok' && <Check className="w-3.5 h-3.5 shrink-0 mt-0.5" />}
            <span>{configStatus.text}</span>
          </div>
        )}

        <button
          type="submit"
          disabled={savingConfig}
          className="w-full py-2 px-4 text-xs font-medium text-white bg-[var(--fw-accent)] rounded-md hover:bg-[var(--fw-accent-hover)] disabled:opacity-50"
        >
          {savingConfig ? 'Salvando...' : 'Salvar Configuração de IA'}
        </button>
      </form>
    </div>
  );
}
