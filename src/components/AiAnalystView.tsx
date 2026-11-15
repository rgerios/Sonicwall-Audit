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
} from '../types.ts';

interface AiAnalystViewProps {
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

const QUICK_PROMPTS = [
  'Explique em linguagem simples os principais bloqueios e alertas críticos dos logs.',
  'Quais regras de firewall e políticas NAT sem uso devo desabilitar primeiro e por quê?',
  'Há sinais de ataque, varredura de portas (scan) ou força bruta nos syslogs atuais?',
  'Gere um resumo executivo curto em linguagem não técnica para apresentar à diretoria.',
];

export function AiAnalystView({
  overview,
  pendingPrompt,
  onConsumePendingPrompt,
}: AiAnalystViewProps) {
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

  useEffect(() => {
    const loadConfig = async () => {
      const res = await fetch('/api/ai/config');
      if (res.ok) {
        const data = (await res.json()) as AiPublicConfig;
        setConfig(data);
        setProvider(data.provider);
        setModel(data.model || PROVIDER_DEFAULTS[data.provider].defaultModel);
        setBaseUrl(data.baseUrl || PROVIDER_DEFAULTS[data.provider].defaultBaseUrl);
      }
    };
    void loadConfig();
  }, []);

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
      const res = await fetch('/api/ai/config', {
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
      const res = await fetch('/api/ai/config', {
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
      const res = await fetch('/api/ai/chat', {
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
      <div className="xl:col-span-2 bg-white border border-[#D4E4D8] rounded-lg flex flex-col h-[calc(100vh-148px)] min-h-[560px] overflow-hidden">
        <div className="px-5 py-3.5 border-b border-[#D4E4D8] bg-[#EDF5EF] flex flex-wrap items-center justify-between gap-3 shrink-0">
          <div className="flex items-center gap-2.5 min-w-0">
            <Bot className="w-4 h-4 text-[#1E4D3B] shrink-0" />
            <div className="min-w-0">
              <h2 className="text-sm font-semibold text-[#123325] truncate">
                Analista de Logs SonicWall
              </h2>
              <p className="text-[11px] text-[#4B6B5C] truncate font-mono">
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
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-[#1D3B2E] bg-white border border-[#BFD5C5] rounded-md hover:bg-[#F4F8F5] whitespace-nowrap"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              Nova Conversa
            </button>
          )}
        </div>

        <div className="flex-1 overflow-y-auto p-5 space-y-4 bg-[#F4F8F5]/50">
          {messages.length === 0 ? (
            <div className="max-w-2xl mx-auto py-8 space-y-5">
              <div>
                <h3 className="text-base font-semibold text-[#123325]">
                  Interpretação em linguagem humana dos seus logs e regras
                </h3>
                <p className="text-xs text-[#456354] mt-1.5 leading-relaxed">
                  Pergunte sobre qualquer IP, porta, bloqueio de IPS/Antivírus, regra sem uso ou
                  política NAT. O assistente lê automaticamente os dados carregados no SonicAudit e
                  mantém o contexto da conversa.
                </p>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                {QUICK_PROMPTS.map((prompt) => (
                  <button
                    key={prompt}
                    type="button"
                    onClick={() => void sendMessage(prompt)}
                    disabled={sending}
                    className="text-left p-3.5 bg-white border border-[#D4E4D8] rounded-md hover:border-[#9EC2AA] hover:bg-[#EDF5EF]/60 transition-colors text-xs text-[#1D3B2E] leading-snug"
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
                      ? 'bg-[#E3EFE7] border-[#BFD5C5] text-[#123325]'
                      : 'bg-white border-[#D4E4D8] text-[#162820]'
                  }`}
                >
                  <p className="whitespace-pre-wrap">{msg.content}</p>
                </div>
                <span className="text-[11px] text-[#5C7A6B] mt-1 font-mono tabular-nums">
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
              <div className="bg-white border border-[#D4E4D8] rounded-lg px-4 py-3 text-xs text-[#4B6B5C]">
                Analisando logs e políticas do SonicWall...
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
          className="p-4 border-t border-[#D4E4D8] bg-white shrink-0 space-y-2"
        >
          <div className="flex items-end gap-2">
            <textarea
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
              rows={2}
              placeholder="Pergunte sobre um IP, drop, alerta IPS ou cole uma linha de syslog... (Enter envia)"
              className="flex-1 px-3 py-2 text-xs border border-[#BFD5C5] rounded-md focus:outline-none focus:ring-2 focus:ring-[#2A6B52] resize-none"
            />
            <button
              type="submit"
              disabled={sending || !input.trim()}
              className="inline-flex items-center gap-1.5 px-4 py-2.5 text-xs font-medium text-white bg-[#1E4D3B] rounded-md hover:bg-[#163A2C] disabled:opacity-40 whitespace-nowrap shrink-0"
            >
              <Send className="w-3.5 h-3.5" />
              Enviar
            </button>
          </div>
        </form>
      </div>

      <form
        onSubmit={handleSaveConfig}
        className="bg-white border border-[#D4E4D8] rounded-lg p-5 space-y-4"
      >
        <div className="pb-3 border-b border-[#E6F0E8] flex items-center gap-2">
          <Settings2 className="w-4 h-4 text-[#1E4D3B]" />
          <div>
            <h3 className="text-sm font-semibold text-[#123325]">Provedor de IA e Chave de API</h3>
            <p className="text-[11px] text-[#4B6B5C]">
              Armazenado apenas no backend Linux (data/store.json)
            </p>
          </div>
        </div>

        <div className="space-y-1.5">
          <label className="block text-xs font-medium text-[#1D3B2E]">Provedor</label>
          <div className="grid grid-cols-2 gap-1.5 p-1 bg-[#E5EFE8] rounded-md">
            {(Object.keys(PROVIDER_DEFAULTS) as AiProviderType[]).map((key) => (
              <button
                key={key}
                type="button"
                onClick={() => handleSelectProvider(key)}
                className={`px-2.5 py-1.5 text-xs font-medium rounded transition-colors truncate ${
                  provider === key
                    ? 'bg-white text-[#123325] shadow-xs'
                    : 'text-[#456354] hover:text-[#123325]'
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
          <label className="block text-xs font-medium text-[#1D3B2E] mb-1">Modelo</label>
          {provider === 'gemini' ? (
            <select
              value={model}
              onChange={(e) => setModel(e.target.value)}
              className="w-full px-3 py-2 text-xs font-mono border border-[#BFD5C5] rounded-md bg-white focus:outline-none focus:ring-2 focus:ring-[#2A6B52]"
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
              className="w-full px-3 py-2 text-xs font-mono border border-[#BFD5C5] rounded-md focus:outline-none focus:ring-2 focus:ring-[#2A6B52]"
            />
          )}
        </div>

        {provider !== 'gemini' && (
          <div>
            <label className="block text-xs font-medium text-[#1D3B2E] mb-1">
              Endpoint Base (OpenAI-compatível)
            </label>
            <input
              type="text"
              value={baseUrl}
              onChange={(e) => setBaseUrl(e.target.value)}
              placeholder={PROVIDER_DEFAULTS[provider].defaultBaseUrl}
              className="w-full px-3 py-2 text-xs font-mono border border-[#BFD5C5] rounded-md focus:outline-none focus:ring-2 focus:ring-[#2A6B52]"
            />
            {provider === 'local' && (
              <p className="text-[11px] text-[#4B6B5C] mt-1">
                Ollama: <span className="font-mono">http://127.0.0.1:11434/v1</span> · LM Studio:{' '}
                <span className="font-mono">http://127.0.0.1:1234/v1</span>
              </p>
            )}
          </div>
        )}

        <div>
          <label className="block text-xs font-medium text-[#1D3B2E] mb-1">
            Chave de API {provider === 'local' ? '(Opcional para servidor local)' : ''}
          </label>
          <div className="relative">
            <KeyRound className="w-3.5 h-3.5 text-[#6D8B7B] absolute left-3 top-1/2 -translate-y-1/2" />
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
              className="w-full pl-9 pr-3 py-2 text-xs font-mono border border-[#BFD5C5] rounded-md focus:outline-none focus:ring-2 focus:ring-[#2A6B52]"
            />
          </div>

          <div className="mt-2 flex items-center justify-between text-[11px] text-[#4B6B5C]">
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
                ? 'bg-[#E7F2EA] border-[#B6D4BE] text-[#143D2C]'
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
          className="w-full py-2 px-4 text-xs font-medium text-white bg-[#1E4D3B] rounded-md hover:bg-[#163A2C] disabled:opacity-50"
        >
          {savingConfig ? 'Salvando...' : 'Salvar Configuração de IA'}
        </button>
      </form>
    </div>
  );
}
