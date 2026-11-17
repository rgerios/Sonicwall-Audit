import { useEffect, useState } from 'react';
import {
  Building2,
  Check,
  CheckCircle2,
  Copy,
  FileUp,
  HardDrive,
  Lock,
  Pencil,
  Play,
  Plus,
  Radio,
  RefreshCw,
  Send,
  ShieldCheck,
  Square,
  Trash2,
} from 'lucide-react';
import type {
  AuditOverview,
  FirewallSiteSummary,
  FirewallVendor,
  RetentionStatus,
  UdpListenerStatus,
} from '../types.ts';
import { vendorApiUrl } from '../utils/vendorApi.ts';
import { VENDOR_THEMES } from '../utils/vendorTheme.ts';

interface ConnectLinuxViewProps {
  vendor: FirewallVendor;
  overview: AuditOverview | null;
  onDataChanged: () => void;
  onOverviewUpdated: (next: AuditOverview) => void;
}

function getRsyslogSnippet(vendor: FirewallVendor, udpPort: number): string {
  if (vendor === 'fortigate') {
    return `# /etc/rsyslog.d/31-fortigate.conf
# Encaminha logs FortiOS para o container/serviço FW Audit FortiGate (porta UDP ${udpPort})
module(load="imudp")
input(type="imudp" port="514")

if ($msg contains 'devname=' or $msg contains 'logid=') then {
  action(type="omfile" file="/var/log/fortigate.log")
  action(type="omfwd" target="127.0.0.1" port="${udpPort}" protocol="udp")
  stop
}`;
  }
  return `# /etc/rsyslog.d/30-sonicwall.conf
# Encaminha logs SonicWall para o container/serviço FW Audit SonicWall (porta UDP ${udpPort})
module(load="imudp")
input(type="imudp" port="514")

if ($fromhost-ip == '192.168.10.1' or $msg contains 'id=firewall') then {
  action(type="omfile" file="/var/log/sonicwall.log")
  action(type="omfwd" target="127.0.0.1" port="${udpPort}" protocol="udp")
  stop
}`;
}

function getComposeSnippet(vendor: FirewallVendor): string {
  if (vendor === 'fortigate') {
    return `# Serviço isolado no docker-compose.yml (Ubuntu Server)
backend-fortigate:
  build:
    context: .
    dockerfile: Dockerfile.backend
  environment:
    FW_VENDOR: fortigate
    PORT: 3001
    SYSLOG_UDP_PORT: 5515
    SYSLOG_AUTOSTART: "true"
    DATABASE_URL: postgres://fwaudit:SENHA@db:5432/fwaudit
  ports:
    - "5515:5515/udp"`;
  }
  return `# Serviço isolado no docker-compose.yml (Ubuntu Server)
backend-sonicwall:
  build:
    context: .
    dockerfile: Dockerfile.backend
  environment:
    FW_VENDOR: sonicwall
    PORT: 3000
    SYSLOG_UDP_PORT: 5514
    SYSLOG_AUTOSTART: "true"
    DATABASE_URL: postgres://fwaudit:SENHA@db:5432/fwaudit
  ports:
    - "5514:5514/udp"`;
}

function getCurlIngestSnippet(vendor: FirewallVendor): string {
  const logPath = vendor === 'fortigate' ? '/var/log/fortigate.log' : '/var/log/sonicwall.log';
  return `# Enviar arquivo de syslog histórico do Linux para o ambiente ${vendor}:
curl -X POST http://localhost:8080/api/${vendor}/syslogs/ingest \\
  -b cookies.txt \\
  -H "Content-Type: text/plain" \\
  --data-binary @${logPath}`;
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

export function ConnectLinuxView({
  vendor,
  overview,
  onDataChanged,
  onOverviewUpdated,
}: ConnectLinuxViewProps) {
  const theme = VENDOR_THEMES[vendor];
  const isForti = vendor === 'fortigate';
  const defaultHost = isForti ? '192.168.10.2' : '192.168.10.1';
  const activeSite = overview?.activeSite;
  const sites = overview?.sites ?? [];

  // Multi-locality creation / editing state
  const [showSiteForm, setShowSiteForm] = useState(false);
  const [editingSiteId, setEditingSiteId] = useState<string | null>(null);
  const [siteName, setSiteName] = useState('');
  const [siteLocation, setSiteLocation] = useState('');
  const [siteNotes, setSiteNotes] = useState('');
  const [siteHost, setSiteHost] = useState('');
  const [sitePort, setSitePort] = useState('443');
  const [siteProtocol, setSiteProtocol] = useState<'https' | 'http'>('https');
  const [siteUsername, setSiteUsername] = useState(isForti ? 'api-readonly' : 'admin');
  const [siteVdom, setSiteVdom] = useState('root');
  const [sitePassword, setSitePassword] = useState('');
  const [siteSavePass, setSiteSavePass] = useState(true);
  const [siteIgnoreTls, setSiteIgnoreTls] = useState(true);
  const [siteAutoSync, setSiteAutoSync] = useState('5');
  const [siteBusy, setSiteBusy] = useState(false);
  const [syncingSiteId, setSyncingSiteId] = useState<string | null>(null);
  const [siteFeedback, setSiteFeedback] = useState<{ type: 'ok' | 'err'; text: string } | null>(null);

  // Active site API connection form
  const [host, setHost] = useState(defaultHost);
  const [port, setPort] = useState('443');
  const [protocol, setProtocol] = useState<'https' | 'http'>('https');
  const [username, setUsername] = useState(isForti ? 'api-readonly' : 'admin');
  const [vdom, setVdom] = useState('root');
  const [password, setPassword] = useState('');
  const [savePassword, setSavePassword] = useState(true);
  const [ignoreTlsErrors, setIgnoreTlsErrors] = useState(true);
  const [apiLoading, setApiLoading] = useState(false);
  const [apiFeedback, setApiFeedback] = useState<{ type: 'ok' | 'err'; text: string } | null>(null);

  const [udpPort, setUdpPort] = useState(String(theme.defaultUdpPort));
  const [udpStatus, setUdpStatus] = useState<UdpListenerStatus | null>(null);
  const [udpBusy, setUdpBusy] = useState(false);
  const [udpFeedback, setUdpFeedback] = useState<{ type: 'ok' | 'err'; text: string } | null>(null);

  const [retention, setRetention] = useState<RetentionStatus | null>(null);
  const [retentionInput, setRetentionInput] = useState('10');
  const [retentionBusy, setRetentionBusy] = useState(false);
  const [retentionFeedback, setRetentionFeedback] = useState<{
    type: 'ok' | 'err';
    text: string;
  } | null>(null);

  const [configBusy, setConfigBusy] = useState(false);
  const [configFeedback, setConfigFeedback] = useState<{ type: 'ok' | 'err'; text: string } | null>(
    null
  );

  const [copiedBlock, setCopiedBlock] = useState<string | null>(null);

  useEffect(() => {
    setShowSiteForm(false);
    setEditingSiteId(null);
    setSiteFeedback(null);
    setApiFeedback(null);
    setUdpFeedback(null);
    setRetentionFeedback(null);
    setConfigFeedback(null);
    setUdpPort(String(theme.defaultUdpPort));
  }, [vendor, theme.defaultUdpPort]);

  useEffect(() => {
    if (activeSite) {
      setHost(activeSite.connection.host || defaultHost);
      setPort(String(activeSite.connection.port || 443));
      setProtocol(activeSite.connection.protocol === 'http' ? 'http' : 'https');
      setUsername(activeSite.connection.username || (isForti ? 'api-readonly' : 'admin'));
      setVdom(activeSite.connection.vdom || 'root');
      setIgnoreTlsErrors(activeSite.connection.ignoreTlsErrors !== false);
      setPassword('');
    }
  }, [
    activeSite?.id,
    activeSite?.connection.host,
    activeSite?.connection.port,
    activeSite?.connection.protocol,
    activeSite?.connection.username,
    activeSite?.connection.vdom,
    activeSite?.connection.ignoreTlsErrors,
    defaultHost,
    isForti,
  ]);

  const loadStatuses = async () => {
    const [udpRes, retRes] = await Promise.all([
      fetch(vendorApiUrl(vendor, '/syslog-server/status')),
      fetch(vendorApiUrl(vendor, '/retention')),
    ]);
    if (udpRes.ok) {
      const status = (await udpRes.json()) as UdpListenerStatus;
      setUdpStatus(status);
      setUdpPort(String(status.port || theme.defaultUdpPort));
    }
    if (retRes.ok) {
      const ret = (await retRes.json()) as RetentionStatus;
      setRetention(ret);
      setRetentionInput(String(ret.retentionDays));
    }
  };

  useEffect(() => {
    void loadStatuses();
  }, [vendor, activeSite?.id]);

  const openNewSiteForm = () => {
    setEditingSiteId(null);
    setSiteName('');
    setSiteLocation('');
    setSiteNotes('');
    setSiteHost('');
    setSitePort('443');
    setSiteProtocol('https');
    setSiteUsername(isForti ? 'api-readonly' : 'admin');
    setSiteVdom('root');
    setSitePassword('');
    setSiteSavePass(true);
    setSiteIgnoreTls(true);
    setSiteAutoSync('5');
    setSiteFeedback(null);
    setShowSiteForm(true);
  };

  const openEditSiteForm = (site: FirewallSiteSummary) => {
    setEditingSiteId(site.id);
    setSiteName(site.name);
    setSiteLocation(site.location);
    setSiteNotes(site.notes);
    setSiteHost(site.connection.host);
    setSitePort(String(site.connection.port || 443));
    setSiteProtocol(site.connection.protocol === 'http' ? 'http' : 'https');
    setSiteUsername(site.connection.username || (isForti ? 'api-readonly' : 'admin'));
    setSiteVdom(site.connection.vdom || 'root');
    setSitePassword('');
    setSiteSavePass(site.connection.hasSavedPassword);
    setSiteIgnoreTls(site.connection.ignoreTlsErrors);
    setSiteAutoSync(String(site.sync?.autoSyncMinutes ?? 5));
    setSiteFeedback(null);
    setShowSiteForm(true);
  };

  const handleSaveSite = async (e: React.FormEvent) => {
    e.preventDefault();
    setSiteBusy(true);
    setSiteFeedback(null);
    try {
      const payload = {
        name: siteName.trim(),
        location: siteLocation.trim(),
        notes: siteNotes.trim(),
        select: true,
        connection: {
          host: siteHost.trim(),
          port: Number(sitePort) || 443,
          protocol: siteProtocol,
          username: siteUsername.trim() || (isForti ? 'api-readonly' : 'admin'),
          vdom: isForti ? siteVdom.trim() || 'root' : undefined,
          password: sitePassword,
          savePassword: siteSavePass,
          ignoreTlsErrors: siteIgnoreTls,
        },
        autoSyncMinutes: Math.min(1440, Math.max(0, Math.round(Number(siteAutoSync) || 0))),
      };

      const url = editingSiteId
        ? vendorApiUrl(vendor, `/sites/${editingSiteId}`)
        : vendorApiUrl(vendor, '/sites');
      const method = editingSiteId ? 'PUT' : 'POST';
      const res = await fetch(url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      if (!res.ok) {
        setSiteFeedback({ type: 'err', text: data.error || 'Erro ao salvar localidade.' });
      } else {
        if (data.overview) onOverviewUpdated(data.overview);
        setShowSiteForm(false);
        setEditingSiteId(null);
        setSiteFeedback({
          type: 'ok',
          text: editingSiteId
            ? 'Localidade atualizada com persistência no banco.'
            : `Localidade "${payload.name}" criada e selecionada no ambiente ${theme.label}.`,
        });
        onDataChanged();
      }
    } finally {
      setSiteBusy(false);
    }
  };

  const handleSelectSite = async (siteId: string) => {
    setSiteFeedback(null);
    const res = await fetch(vendorApiUrl(vendor, `/sites/${siteId}/select`), { method: 'POST' });
    const data = await res.json();
    if (res.ok) {
      if (data.overview) onOverviewUpdated(data.overview);
      onDataChanged();
    }
  };

  const handleQuickSyncSite = async (siteId: string) => {
    setSyncingSiteId(siteId);
    setSiteFeedback(null);
    try {
      const res = await fetch(vendorApiUrl(vendor, `/sites/${siteId}/sync`), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      const data = await res.json();
      if (!res.ok) {
        setSiteFeedback({ type: 'err', text: data.error || 'Falha ao sincronizar firewall.' });
      } else {
        if (data.overview) onOverviewUpdated(data.overview);
        setSiteFeedback({
          type: 'ok',
          text: `Localidade sincronizada via API ${isForti ? 'FortiOS' : 'SonicOS'} (${data.rulesCount} regras, ${data.natsCount} NATs).`,
        });
        onDataChanged();
      }
    } finally {
      setSyncingSiteId(null);
    }
  };

  const handleDeleteSite = async (site: FirewallSiteSummary) => {
    setSiteFeedback(null);
    const res = await fetch(vendorApiUrl(vendor, `/sites/${site.id}`), { method: 'DELETE' });
    const data = await res.json();
    if (!res.ok) {
      setSiteFeedback({ type: 'err', text: data.error || 'Não foi possível excluir localidade.' });
    } else {
      if (data.overview) onOverviewUpdated(data.overview);
      setSiteFeedback({ type: 'ok', text: `Localidade "${site.name}" removida.` });
      onDataChanged();
    }
  };

  const handleFirewallApiAudit = async (e: React.FormEvent) => {
    e.preventDefault();
    setApiLoading(true);
    setApiFeedback(null);
    try {
      const res = await fetch(vendorApiUrl(vendor, '/firewall/audit'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          siteId: activeSite?.id,
          host,
          port: Number(port),
          protocol,
          username,
          vdom: isForti ? vdom.trim() || 'root' : undefined,
          password,
          savePassword,
          ignoreTlsErrors,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setApiFeedback({
          type: 'err',
          text: data.error || `Falha na conexão com o ${theme.label}.`,
        });
      } else {
        if (data.overview) onOverviewUpdated(data.overview);
        setPassword('');
        setApiFeedback({
          type: 'ok',
          text: `Sincronizado com sucesso (${theme.label}): ${data.rulesCount} regras e ${data.natsCount} políticas NAT/VIP.`,
        });
        onDataChanged();
      }
    } catch {
      setApiFeedback({
        type: 'err',
        text: 'Erro de rede ao tentar acessar o backend local.',
      });
    } finally {
      setApiLoading(false);
    }
  };

  const handleToggleUdp = async () => {
    setUdpBusy(true);
    setUdpFeedback(null);
    try {
      const endpoint = udpStatus?.running ? '/syslog-server/stop' : '/syslog-server/start';
      const res = await fetch(vendorApiUrl(vendor, endpoint), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ port: Number(udpPort) || theme.defaultUdpPort }),
      });
      const data = await res.json();
      if (!res.ok) {
        setUdpFeedback({ type: 'err', text: data.error || 'Erro ao alterar receptor UDP.' });
      } else {
        setUdpStatus(data);
        setUdpFeedback({
          type: 'ok',
          text: data.running
            ? `Receptor UDP ${theme.label} ativo na porta ${data.port}. Syslogs recebidos são roteados por Serial/IP para cada localidade.`
            : `Receptor UDP ${theme.label} encerrado.`,
        });
        onDataChanged();
      }
    } finally {
      setUdpBusy(false);
    }
  };

  const handleSendTestUdp = async () => {
    setUdpBusy(true);
    setUdpFeedback(null);
    try {
      const res = await fetch(vendorApiUrl(vendor, '/syslog-server/test-packet'), {
        method: 'POST',
      });
      const data = await res.json();
      if (!res.ok) {
        setUdpFeedback({ type: 'err', text: data.error || 'Falha no envio de pacote teste.' });
      } else {
        setUdpStatus(data.status);
        setUdpFeedback({
          type: 'ok',
          text: `Pacote UDP ${theme.label} recebido e processado na porta ${data.status?.port || theme.defaultUdpPort}.`,
        });
        onDataChanged();
        await loadStatuses();
      }
    } finally {
      setUdpBusy(false);
    }
  };

  const handleSaveRetention = async () => {
    setRetentionBusy(true);
    setRetentionFeedback(null);
    try {
      const days = Number.parseInt(retentionInput, 10);
      const res = await fetch(vendorApiUrl(vendor, '/retention'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ retentionDays: days }),
      });
      const data = await res.json();
      if (!res.ok) {
        setRetentionFeedback({ type: 'err', text: data.error || 'Valor inválido.' });
      } else {
        setRetention(data.retention);
        setRetentionFeedback({
          type: 'ok',
          text: `Retenção definida para ${data.retention.retentionDays} dia(s). ${data.purged} log(s) expirado(s) removido(s).`,
        });
        onDataChanged();
      }
    } finally {
      setRetentionBusy(false);
    }
  };

  const handleRunPurgeNow = async () => {
    setRetentionBusy(true);
    setRetentionFeedback(null);
    try {
      const res = await fetch(vendorApiUrl(vendor, '/retention/purge'), { method: 'POST' });
      const data = await res.json();
      if (res.ok) {
        setRetention(data.retention);
        setRetentionFeedback({
          type: 'ok',
          text: `Limpeza concluída: ${data.purged} syslog(s) com mais de ${data.retention.retentionDays} dias removidos.`,
        });
        onDataChanged();
      }
    } finally {
      setRetentionBusy(false);
    }
  };

  const handleConfigUpload = async (file: File | undefined) => {
    if (!file) return;
    setConfigBusy(true);
    setConfigFeedback(null);
    try {
      const content = await file.text();
      const res = await fetch(vendorApiUrl(vendor, '/config/import'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content, filename: file.name }),
      });
      const data = await res.json();
      if (!res.ok) {
        setConfigFeedback({ type: 'err', text: data.error || 'Arquivo inválido.' });
      } else {
        setConfigFeedback({
          type: 'ok',
          text: `Importado de ${file.name}: ${data.rulesCount} regras e ${data.natsCount} NATs.`,
        });
        onDataChanged();
        await loadStatuses();
      }
    } catch {
      setConfigFeedback({ type: 'err', text: 'Erro ao ler o arquivo selecionado.' });
    } finally {
      setConfigBusy(false);
    }
  };

  const handleSyslogUpload = async (file: File | undefined) => {
    if (!file) return;
    setConfigBusy(true);
    setConfigFeedback(null);
    try {
      const content = await file.text();
      const res = await fetch(vendorApiUrl(vendor, '/syslogs/ingest'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content, source: 'upload' }),
      });
      const data = await res.json();
      if (!res.ok) {
        setConfigFeedback({ type: 'err', text: data.error || 'Falha ao ler arquivo de log.' });
      } else {
        setConfigFeedback({
          type: 'ok',
          text: `${data.added.toLocaleString('pt-BR')} eventos de syslog importados de ${file.name}.`,
        });
        onDataChanged();
        await loadStatuses();
      }
    } finally {
      setConfigBusy(false);
    }
  };

  const handleClearAll = async () => {
    await fetch(vendorApiUrl(vendor, '/data/clear'), { method: 'POST' });
    setConfigFeedback({ type: 'ok', text: 'Os dados desta localidade foram limpos.' });
    onDataChanged();
    await loadStatuses();
  };

  const copyText = async (id: string, text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedBlock(id);
      setTimeout(() => setCopiedBlock(null), 1600);
    } catch {
      // Clipboard blocked
    }
  };

  const rsyslogSnippet = getRsyslogSnippet(vendor, Number(udpPort) || theme.defaultUdpPort);
  const composeSnippet = getComposeSnippet(vendor);
  const curlSnippet = getCurlIngestSnippet(vendor);

  return (
    <div className="space-y-6">
      <div className="bg-white border border-[var(--fw-border)] rounded-lg p-6 space-y-4">
        <div className="pb-3 border-b border-[var(--fw-border-soft)] flex flex-wrap items-center justify-between gap-4">
          <div>
            <h2 className="text-sm font-semibold text-[var(--fw-heading)] inline-flex items-center gap-2">
              <Building2 className="w-4 h-4 text-[var(--fw-accent)]" />
              Localidades {theme.label} Persistentes ({sites.length})
            </h2>
            <p className="text-xs text-[var(--fw-text-muted)] mt-1">
              Cada localidade armazena separadamente suas credenciais criptografadas, regras, NATs,
              telemetria e syslogs no PostgreSQL com isolamento por vendor ({vendor}).
            </p>
          </div>
          <button
            type="button"
            onClick={openNewSiteForm}
            className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium text-white bg-[var(--fw-accent)] rounded-md hover:bg-[var(--fw-accent-hover)] whitespace-nowrap"
          >
            <Plus className="w-3.5 h-3.5" />
            Nova Localidade {theme.label}
          </button>
        </div>

        {showSiteForm && (
          <form
            onSubmit={(e) => void handleSaveSite(e)}
            className="p-4 bg-[var(--fw-bg)] border border-[var(--fw-border-strong)] rounded-md space-y-4"
          >
            <div className="flex items-center justify-between border-b border-[var(--fw-border)] pb-2">
              <span className="text-xs font-semibold text-[var(--fw-heading)]">
                {editingSiteId
                  ? `Editar Localidade ${theme.label}`
                  : `Cadastrar Nova Localidade ${theme.label}`}
              </span>
              <button
                type="button"
                onClick={() => setShowSiteForm(false)}
                className="text-xs text-[var(--fw-text-muted)] hover:underline"
              >
                Cancelar
              </button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
              <div>
                <label className="block font-medium text-[var(--fw-text-body)] mb-1">
                  Nome da Localidade
                </label>
                <input
                  type="text"
                  value={siteName}
                  onChange={(e) => setSiteName(e.target.value)}
                  required
                  placeholder={isForti ? 'Ex: Matriz FortiGate 100F' : 'Ex: Filial Campinas'}
                  className="w-full px-3 py-2 border border-[var(--fw-border-strong)] rounded bg-white"
                />
              </div>
              <div>
                <label className="block font-medium text-[var(--fw-text-body)] mb-1">
                  Cidade / Unidade
                </label>
                <input
                  type="text"
                  value={siteLocation}
                  onChange={(e) => setSiteLocation(e.target.value)}
                  placeholder="Ex: Campinas / SP"
                  className="w-full px-3 py-2 border border-[var(--fw-border-strong)] rounded bg-white"
                />
              </div>
              <div>
                <label className="block font-medium text-[var(--fw-text-body)] mb-1">
                  Observações
                </label>
                <input
                  type="text"
                  value={siteNotes}
                  onChange={(e) => setSiteNotes(e.target.value)}
                  placeholder="Ex: Link Vivo + Backup Claro"
                  className="w-full px-3 py-2 border border-[var(--fw-border-strong)] rounded bg-white"
                />
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-5 gap-3 text-xs">
              <div className="md:col-span-2">
                <label className="block font-medium text-[var(--fw-text-body)] mb-1">
                  IP / Hostname {isForti ? 'FortiOS' : 'SonicOS'}
                </label>
                <input
                  type="text"
                  value={siteHost}
                  onChange={(e) => setSiteHost(e.target.value)}
                  placeholder={defaultHost}
                  className="w-full px-3 py-2 font-mono border border-[var(--fw-border-strong)] rounded bg-white"
                />
              </div>
              <div>
                <label className="block font-medium text-[var(--fw-text-body)] mb-1">
                  Proto / Porta
                </label>
                <div className="flex gap-1">
                  <select
                    value={siteProtocol}
                    onChange={(e) => setSiteProtocol(e.target.value === 'http' ? 'http' : 'https')}
                    className="px-2 py-2 font-mono border border-[var(--fw-border-strong)] rounded bg-white"
                  >
                    <option value="https">HTTPS</option>
                    <option value="http">HTTP</option>
                  </select>
                  <input
                    type="number"
                    value={sitePort}
                    onChange={(e) => setSitePort(e.target.value)}
                    className="w-full px-2 py-2 font-mono border border-[var(--fw-border-strong)] rounded bg-white"
                  />
                </div>
              </div>
              {isForti ? (
                <div>
                  <label className="block font-medium text-[var(--fw-text-body)] mb-1">VDOM</label>
                  <input
                    type="text"
                    value={siteVdom}
                    onChange={(e) => setSiteVdom(e.target.value)}
                    placeholder="root"
                    className="w-full px-3 py-2 font-mono border border-[var(--fw-border-strong)] rounded bg-white"
                  />
                </div>
              ) : (
                <div>
                  <label className="block font-medium text-[var(--fw-text-body)] mb-1">
                    Usuário API
                  </label>
                  <input
                    type="text"
                    value={siteUsername}
                    onChange={(e) => setSiteUsername(e.target.value)}
                    className="w-full px-3 py-2 font-mono border border-[var(--fw-border-strong)] rounded bg-white"
                  />
                </div>
              )}
              <div>
                <label className="block font-medium text-[var(--fw-text-body)] mb-1">
                  {isForti ? 'Bearer API Token' : 'Senha API'}
                </label>
                <input
                  type="password"
                  value={sitePassword}
                  onChange={(e) => setSitePassword(e.target.value)}
                  placeholder={editingSiteId ? '(Manter atual)' : '••••••••'}
                  className="w-full px-3 py-2 font-mono border border-[var(--fw-border-strong)] rounded bg-white"
                />
              </div>
            </div>

            <div className="flex flex-wrap items-center justify-between gap-4 text-xs pt-1">
              <div className="flex flex-wrap items-center gap-4">
                <label className="inline-flex items-center gap-2 text-[var(--fw-text-body)] cursor-pointer">
                  <input
                    type="checkbox"
                    checked={siteSavePass}
                    onChange={(e) => setSiteSavePass(e.target.checked)}
                    className="rounded border-[var(--fw-border-strong)] accent-[var(--fw-accent)]"
                  />
                  Salvar {isForti ? 'token' : 'senha'} criptografado(a) (AES-256) para re-sincronização rápida
                </label>
                <label className="inline-flex items-center gap-2 text-[var(--fw-text-muted)] cursor-pointer">
                  <input
                    type="checkbox"
                    checked={siteIgnoreTls}
                    onChange={(e) => setSiteIgnoreTls(e.target.checked)}
                    className="rounded border-[var(--fw-border-strong)] accent-[var(--fw-accent)]"
                  />
                  Ignorar TLS autoassinado
                </label>
                <label className="inline-flex items-center gap-2 text-[var(--fw-text-muted)]">
                  Sincronizar a cada
                  <input
                    type="number"
                    min={0}
                    max={1440}
                    value={siteAutoSync}
                    onChange={(e) => setSiteAutoSync(e.target.value)}
                    className="w-16 px-2 py-1 border border-[var(--fw-border-strong)] rounded font-mono text-right tabular-nums text-[var(--fw-heading)] bg-[var(--fw-bg-input)]"
                  />
                  min (0 = só manual; exige {isForti ? 'token' : 'senha'} salvo)
                </label>
              </div>
              <button
                type="submit"
                disabled={siteBusy}
                className="px-4 py-2 text-xs font-medium text-white bg-[var(--fw-accent)] rounded-md hover:bg-[var(--fw-accent-hover)] disabled:opacity-50"
              >
                {siteBusy ? 'Salvando...' : editingSiteId ? 'Salvar Alterações' : 'Criar Localidade'}
              </button>
            </div>
          </form>
        )}

        {siteFeedback && (
          <div
            className={`p-3 rounded-md border text-xs ${
              siteFeedback.type === 'ok'
                ? 'bg-[var(--fw-surface)] border-[var(--fw-border-strong)] text-[var(--fw-heading)]'
                : 'bg-red-50 border-red-200 text-red-800'
            }`}
          >
            {siteFeedback.text}
          </div>
        )}

        <div className="overflow-x-auto border border-[var(--fw-border)] rounded-md">
          <table className="w-full text-xs">
            <thead>
              <tr className="bg-[var(--fw-surface)] text-[var(--fw-text-body)] border-b border-[var(--fw-border)]">
                <th className="py-2.5 px-3 text-left font-medium">Localidade</th>
                <th className="py-2.5 px-3 text-left font-medium">Appliance / Serial</th>
                <th className="py-2.5 px-3 text-left font-medium">
                  Endpoint {isForti ? 'FortiOS' : 'SonicOS'}
                </th>
                <th className="py-2.5 px-3 text-right font-medium">Syslogs</th>
                <th className="py-2.5 px-3 text-right font-medium">Regras / NATs</th>
                <th className="py-2.5 px-3 text-right font-medium">Alertas</th>
                <th className="py-2.5 px-3 text-right font-medium">Ações</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--fw-border-soft)]">
              {sites.map((site) => {
                const isActive = site.id === activeSite?.id;
                const canQuickSync = Boolean(site.connection.host && site.connection.hasSavedPassword);
                return (
                  <tr key={site.id} className={isActive ? 'bg-[var(--fw-bg)]' : 'bg-white'}>
                    <td className="py-2.5 px-3">
                      <div className="flex items-center gap-2">
                        <span className="font-semibold text-[var(--fw-heading)]">{site.name}</span>
                        {isActive && (
                          <span className="inline-flex items-center gap-1 text-[11px] font-medium text-emerald-800">
                            <CheckCircle2 className="w-3.5 h-3.5" /> Ativa
                          </span>
                        )}
                      </div>
                      <p className="text-[11px] text-[var(--fw-text-subtle)]">
                        {site.location || 'Sem unidade informada'}
                        {site.notes ? ` · ${site.notes}` : ''}
                      </p>
                    </td>
                    <td className="py-2.5 px-3">
                      <p className="text-[var(--fw-heading)] font-medium truncate max-w-[190px]">
                        {site.appliance.model}
                      </p>
                      <p className="text-[11px] font-mono text-[var(--fw-text-subtle)]">
                        S/N: {site.appliance.serialNumber}
                      </p>
                    </td>
                    <td className="py-2.5 px-3">
                      <p className="font-mono text-[var(--fw-heading)]">
                        {site.connection.host
                          ? `${site.connection.protocol}://${site.connection.host}:${site.connection.port}${
                              isForti && site.connection.vdom ? ` (${site.connection.vdom})` : ''
                            }`
                          : 'Não configurado'}
                      </p>
                      <p className="text-[11px] text-[var(--fw-text-subtle)] inline-flex items-center gap-1">
                        <Lock className="w-3 h-3" />
                        {site.connection.hasSavedPassword
                          ? isForti
                            ? 'Token salvo (AES-256)'
                            : 'Senha salva (AES-256)'
                          : isForti
                            ? 'Sem token salvo'
                            : 'Sem senha salva'}
                      </p>
                    </td>
                    <td className="py-2.5 px-3 text-right font-mono tabular-nums text-[var(--fw-heading)]">
                      {site.totalSyslogs.toLocaleString('pt-BR')}
                    </td>
                    <td className="py-2.5 px-3 text-right font-mono tabular-nums text-[var(--fw-text-muted)]">
                      {site.rulesCount} / {site.natsCount}
                    </td>
                    <td className="py-2.5 px-3 text-right font-mono tabular-nums">
                      <span
                        className={
                          site.criticalAlertsCount > 0
                            ? 'text-red-700 font-semibold'
                            : site.alertsCount > 0
                              ? 'text-amber-800 font-semibold'
                              : 'text-[var(--fw-text-subtle)]'
                        }
                      >
                        {site.alertsCount}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-right">
                      <div className="inline-flex items-center gap-1.5">
                        {!isActive && (
                          <button
                            type="button"
                            onClick={() => void handleSelectSite(site.id)}
                            className="px-2.5 py-1 text-[11px] font-medium text-[var(--fw-accent)] bg-white border border-[var(--fw-border-strong)] rounded hover:bg-[var(--fw-surface)]"
                          >
                            Selecionar
                          </button>
                        )}
                        {canQuickSync && (
                          <button
                            type="button"
                            disabled={syncingSiteId === site.id}
                            onClick={() => void handleQuickSyncSite(site.id)}
                            title={`Sincronizar via API ${isForti ? 'FortiOS' : 'SonicOS'}`}
                            className="inline-flex items-center gap-1 px-2.5 py-1 text-[11px] font-medium text-white bg-[var(--fw-accent)] rounded hover:bg-[var(--fw-accent-hover)] disabled:opacity-50"
                          >
                            <RefreshCw
                              className={`w-3 h-3 ${syncingSiteId === site.id ? 'animate-spin' : ''}`}
                            />
                            Sincronizar
                          </button>
                        )}
                        <button
                          type="button"
                          onClick={() => openEditSiteForm(site)}
                          title="Editar localidade"
                          aria-label={`Editar ${site.name}`}
                          className="p-1.5 text-[var(--fw-text-muted)] hover:text-[var(--fw-heading)] hover:bg-[var(--fw-surface)] rounded"
                        >
                          <Pencil className="w-3.5 h-3.5" />
                        </button>
                        {sites.length > 1 && (
                          <button
                            type="button"
                            onClick={() => void handleDeleteSite(site)}
                            title="Excluir localidade"
                            aria-label={`Excluir ${site.name}`}
                            className="p-1.5 text-red-700 hover:bg-red-50 rounded"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <form
          onSubmit={handleFirewallApiAudit}
          className="bg-white border border-[var(--fw-border)] rounded-lg p-6 space-y-4"
        >
          <div className="pb-3 border-b border-[var(--fw-border-soft)]">
            <h2 className="text-sm font-semibold text-[var(--fw-heading)]">
              Conexão Direta — API REST {isForti ? 'FortiOS v2' : 'SonicOS'} (
              {activeSite?.name || 'Localidade Ativa'})
            </h2>
            <p className="text-xs text-[var(--fw-text-muted)] mt-1">
              {isForti
                ? 'Consulta políticas de firewall, hit counts, VIPs, IP Pools, interfaces, VPNs IPSec e licenças FortiGuard via REST API.'
                : 'Consulta diretamente regras, NATs, uptime, links e licenças do SonicWall desta localidade e mantém os dados salvos no banco.'}
            </p>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div className="sm:col-span-2">
              <label className="block text-xs font-medium text-[var(--fw-text-body)] mb-1">
                IP ou Hostname do {theme.label}
              </label>
              <input
                type="text"
                value={host}
                onChange={(e) => setHost(e.target.value)}
                required
                placeholder={defaultHost}
                className="w-full px-3 py-2 text-xs font-mono border border-[var(--fw-border-strong)] rounded-md bg-[var(--fw-bg-input)] focus:outline-none focus:ring-2 focus:ring-[var(--fw-accent-mid)]"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-[var(--fw-text-body)] mb-1">
                Porta / Proto
              </label>
              <div className="flex gap-1.5">
                <select
                  value={protocol}
                  onChange={(e) => setProtocol(e.target.value === 'http' ? 'http' : 'https')}
                  className="px-2 py-2 text-xs font-mono border border-[var(--fw-border-strong)] rounded-md bg-white"
                >
                  <option value="https">HTTPS</option>
                  <option value="http">HTTP</option>
                </select>
                <input
                  type="number"
                  value={port}
                  onChange={(e) => setPort(e.target.value)}
                  className="w-full px-2.5 py-2 text-xs font-mono border border-[var(--fw-border-strong)] rounded-md bg-[var(--fw-bg-input)]"
                />
              </div>
            </div>
          </div>

          {isForti ? (
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <div>
                <label className="block text-xs font-medium text-[var(--fw-text-body)] mb-1">
                  VDOM FortiOS
                </label>
                <input
                  type="text"
                  value={vdom}
                  onChange={(e) => setVdom(e.target.value)}
                  placeholder="root"
                  className="w-full px-3 py-2 text-xs font-mono border border-[var(--fw-border-strong)] rounded-md bg-[var(--fw-bg-input)] focus:outline-none focus:ring-2 focus:ring-[var(--fw-accent-mid)]"
                />
              </div>
              <div className="sm:col-span-2">
                <label className="block text-xs font-medium text-[var(--fw-text-body)] mb-1">
                  API Token (REST API Admin Read-Only)
                </label>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required={!activeSite?.connection.hasSavedPassword}
                  placeholder={
                    activeSite?.connection.hasSavedPassword
                      ? 'Token salvo (vazio = reutilizar)'
                      : 'Cole o Bearer token gerado no FortiGate'
                  }
                  className="w-full px-3 py-2 text-xs font-mono border border-[var(--fw-border-strong)] rounded-md bg-[var(--fw-bg-input)] focus:outline-none focus:ring-2 focus:ring-[var(--fw-accent-mid)]"
                />
              </div>
            </div>
          ) : (
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label className="block text-xs font-medium text-[var(--fw-text-body)] mb-1">
                  Usuário Admin / Read-Only
                </label>
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  required
                  className="w-full px-3 py-2 text-xs font-mono border border-[var(--fw-border-strong)] rounded-md bg-[var(--fw-bg-input)] focus:outline-none focus:ring-2 focus:ring-[var(--fw-accent-mid)]"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-[var(--fw-text-body)] mb-1">
                  Senha
                </label>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required={!activeSite?.connection.hasSavedPassword}
                  placeholder={
                    activeSite?.connection.hasSavedPassword
                      ? 'Senha salva (vazio = reutilizar)'
                      : '••••••••'
                  }
                  className="w-full px-3 py-2 text-xs border border-[var(--fw-border-strong)] rounded-md bg-[var(--fw-bg-input)] focus:outline-none focus:ring-2 focus:ring-[var(--fw-accent-mid)]"
                />
              </div>
            </div>
          )}

          <div className="space-y-2">
            <label className="flex items-center gap-2 text-xs text-[var(--fw-text-body)] cursor-pointer">
              <input
                type="checkbox"
                checked={savePassword}
                onChange={(e) => setSavePassword(e.target.checked)}
                className="rounded border-[var(--fw-border-strong)] accent-[var(--fw-accent)]"
              />
              Salvar credenciais criptografadas (AES-256) nesta localidade
            </label>
            <label className="flex items-center gap-2 text-xs text-[var(--fw-text-muted)] cursor-pointer">
              <input
                type="checkbox"
                checked={ignoreTlsErrors}
                onChange={(e) => setIgnoreTlsErrors(e.target.checked)}
                className="rounded border-[var(--fw-border-strong)] accent-[var(--fw-accent)]"
              />
              Ignorar erro de certificado TLS autoassinado (comum em interfaces locais)
            </label>
          </div>

          {apiFeedback && (
            <div
              className={`p-3 rounded-md border text-xs ${
                apiFeedback.type === 'ok'
                  ? 'bg-[var(--fw-surface)] border-[var(--fw-border-strong)] text-[var(--fw-heading)]'
                  : 'bg-red-50 border-red-200 text-red-800'
              }`}
            >
              {apiFeedback.text}
            </div>
          )}

          <div className="pt-1 flex items-center justify-between gap-3">
            <span className="text-[11px] text-[var(--fw-text-muted)]">
              {isForti
                ? 'Habilite em: System → Administrators → Create New → REST API Admin'
                : 'Habilite em: Manage → System Setup → Appliance → SonicOS API'}
            </span>
            <button
              type="submit"
              disabled={apiLoading}
              className="inline-flex items-center gap-2 px-4 py-2 text-xs font-medium text-white bg-[var(--fw-accent)] rounded-md hover:bg-[var(--fw-accent-hover)] disabled:opacity-50 whitespace-nowrap shrink-0"
            >
              <ShieldCheck className="w-3.5 h-3.5" />
              {apiLoading ? 'Auditando...' : 'Conectar e Auditar'}
            </button>
          </div>
        </form>

        <div className="space-y-6">
          <div className="bg-white border border-[var(--fw-border)] rounded-lg p-6 space-y-4">
            <div className="pb-3 border-b border-[var(--fw-border-soft)] flex items-center justify-between">
              <div>
                <h2 className="text-sm font-semibold text-[var(--fw-heading)]">
                  Receptor UDP Syslog {theme.label} (Socket Linux)
                </h2>
                <p className="text-xs text-[var(--fw-text-muted)] mt-1">
                  Porta padrão {theme.defaultUdpPort}/udp · Roteia eventos por Serial/IP
                </p>
              </div>
              {udpStatus?.running ? (
                <span className="inline-flex items-center gap-1.5 text-xs font-mono text-[var(--fw-accent)] font-medium">
                  <Radio className="w-3.5 h-3.5" /> Escutando :{udpStatus.port}
                </span>
              ) : (
                <span className="text-xs font-mono text-[var(--fw-text-subtle)]">Inativo</span>
              )}
            </div>

            <div className="flex flex-wrap items-end gap-3">
              <div>
                <label className="block text-xs font-medium text-[var(--fw-text-body)] mb-1">
                  Porta UDP
                </label>
                <input
                  type="number"
                  value={udpPort}
                  disabled={udpStatus?.running}
                  onChange={(e) => setUdpPort(e.target.value)}
                  className="w-28 px-3 py-2 text-xs font-mono border border-[var(--fw-border-strong)] rounded-md bg-[var(--fw-bg-input)] disabled:bg-[var(--fw-surface)]"
                />
              </div>

              <button
                type="button"
                disabled={udpBusy}
                onClick={() => void handleToggleUdp()}
                className={`inline-flex items-center gap-1.5 px-4 py-2 text-xs font-medium rounded-md whitespace-nowrap ${
                  udpStatus?.running
                    ? 'text-red-700 bg-red-50 border border-red-200 hover:bg-red-100'
                    : 'text-white bg-[var(--fw-accent)] hover:bg-[var(--fw-accent-hover)]'
                }`}
              >
                {udpStatus?.running ? (
                  <>
                    <Square className="w-3.5 h-3.5" /> Parar Socket
                  </>
                ) : (
                  <>
                    <Play className="w-3.5 h-3.5" /> Iniciar Socket UDP
                  </>
                )}
              </button>

              {udpStatus?.running && (
                <button
                  type="button"
                  disabled={udpBusy}
                  onClick={() => void handleSendTestUdp()}
                  className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-[var(--fw-text-body)] bg-white border border-[var(--fw-border-strong)] rounded-md hover:bg-[var(--fw-surface)] whitespace-nowrap"
                >
                  <Send className="w-3.5 h-3.5" /> Testar Pacote {theme.label}
                </button>
              )}
            </div>

            {udpStatus && (
              <p className="text-xs text-[var(--fw-text-muted)] font-mono tabular-nums">
                Pacotes recebidos nesta sessão: {udpStatus.packetsReceived.toLocaleString('pt-BR')}
                {udpStatus.lastPacketAt ? ` · Último: ${udpStatus.lastPacketAt}` : ''}
              </p>
            )}

            {udpStatus && (udpStatus.unmatchedEvents ?? 0) > 0 && (
              <div className="p-3 rounded-md border border-amber-300 bg-amber-50 text-xs text-amber-900 space-y-1">
                <p className="font-semibold">
                  {(udpStatus.unmatchedEvents ?? 0).toLocaleString('pt-BR')} evento(s) descartado(s):
                  a origem não corresponde a nenhum firewall cadastrado.
                </p>
                <p>
                  Cadastre a localidade com o mesmo IP de origem (ou sincronize via API para
                  registrar o número de série) para que os logs sejam aceitos:
                </p>
                <ul className="font-mono tabular-nums">
                  {(udpStatus.unmatchedSources ?? []).map((src) => (
                    <li key={`${src.address}|${src.serialNumber}`}>
                      {src.address}
                      {src.serialNumber && src.serialNumber !== '-' ? ` · SN ${src.serialNumber}` : ''} —{' '}
                      {src.count.toLocaleString('pt-BR')} evento(s)
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {udpFeedback && (
              <div
                className={`p-3 rounded-md border text-xs ${
                  udpFeedback.type === 'ok'
                    ? 'bg-[var(--fw-surface)] border-[var(--fw-border-strong)] text-[var(--fw-heading)]'
                    : 'bg-red-50 border-red-200 text-red-800'
                }`}
              >
                {udpFeedback.text}
              </div>
            )}
          </div>

          <div className="bg-white border border-[var(--fw-border)] rounded-lg p-6 space-y-4">
            <div className="pb-3 border-b border-[var(--fw-border-soft)] flex items-center justify-between">
              <div>
                <h2 className="text-sm font-semibold text-[var(--fw-heading)]">
                  Importação Offline ({activeSite?.name || 'Localidade Ativa'})
                </h2>
                <p className="text-xs text-[var(--fw-text-muted)] mt-1">
                  {isForti
                    ? 'Importe arquivos de syslog FortiOS (.log / .txt) para esta localidade'
                    : 'Importe arquivos .exp, .json ou .log para esta localidade'}
                </p>
              </div>
              <button
                type="button"
                onClick={() => void handleClearAll()}
                className="inline-flex items-center gap-1 text-xs text-red-700 hover:underline"
              >
                <Trash2 className="w-3.5 h-3.5" /> Limpar Localidade
              </button>
            </div>

            <div className="flex flex-wrap gap-3">
              {!isForti && (
                <label className="inline-flex items-center gap-2 px-4 py-2 text-xs font-medium text-[var(--fw-text-body)] bg-[var(--fw-bg)] border border-[var(--fw-border-strong)] rounded-md hover:bg-[var(--fw-surface)] cursor-pointer">
                  <FileUp className="w-3.5 h-3.5" />
                  {configBusy ? 'Processando...' : 'Importar Config (.exp / .json)'}
                  <input
                    type="file"
                    accept=".exp,.json,.txt"
                    className="hidden"
                    onChange={(e) => void handleConfigUpload(e.target.files?.[0])}
                  />
                </label>
              )}

              <label className="inline-flex items-center gap-2 px-4 py-2 text-xs font-medium text-[var(--fw-text-body)] bg-[var(--fw-bg)] border border-[var(--fw-border-strong)] rounded-md hover:bg-[var(--fw-surface)] cursor-pointer">
                <FileUp className="w-3.5 h-3.5" />
                {configBusy ? 'Processando...' : 'Importar Arquivo Syslog (.log)'}
                <input
                  type="file"
                  accept=".log,.txt,.syslog"
                  className="hidden"
                  onChange={(e) => void handleSyslogUpload(e.target.files?.[0])}
                />
              </label>
            </div>

            {configFeedback && (
              <div
                className={`p-3 rounded-md border text-xs ${
                  configFeedback.type === 'ok'
                    ? 'bg-[var(--fw-surface)] border-[var(--fw-border-strong)] text-[var(--fw-heading)]'
                    : 'bg-red-50 border-red-200 text-red-800'
                }`}
              >
                {configFeedback.text}
              </div>
            )}
          </div>
        </div>
      </div>

      <div className="bg-white border border-[var(--fw-border)] rounded-lg p-6 space-y-4">
        <div className="pb-3 border-b border-[var(--fw-border-soft)] flex flex-wrap items-center justify-between gap-4">
          <div>
            <h2 className="text-sm font-semibold text-[var(--fw-heading)] inline-flex items-center gap-2">
              <HardDrive className="w-4 h-4 text-[var(--fw-accent)]" />
              Retenção Automática de Syslogs e Proteção de Disco
            </h2>
            <p className="text-xs text-[var(--fw-text-muted)] mt-1">
              Syslogs mais antigos que o prazo configurado são expirados automaticamente no
              carregamento, na ingestão e a cada 1 hora em segundo plano.
            </p>
          </div>
          {retention && (
            <span className="font-mono text-xs text-[var(--fw-heading)] tabular-nums">
              Uso em armazenamento: {formatBytes(retention.storeSizeBytes)}
            </span>
          )}
        </div>

        <div className="flex flex-wrap items-end gap-4">
          <div>
            <label className="block text-xs font-medium text-[var(--fw-text-body)] mb-1">
              Expirar syslogs após (dias)
            </label>
            <input
              type="number"
              min={1}
              max={365}
              value={retentionInput}
              onChange={(e) => setRetentionInput(e.target.value)}
              className="w-28 px-3 py-2 text-xs font-mono border border-[var(--fw-border-strong)] rounded-md bg-[var(--fw-bg-input)]"
            />
          </div>

          <button
            type="button"
            disabled={retentionBusy}
            onClick={() => void handleSaveRetention()}
            className="px-4 py-2 text-xs font-medium text-white bg-[var(--fw-accent)] rounded-md hover:bg-[var(--fw-accent-hover)] disabled:opacity-50"
          >
            Salvar Retenção
          </button>

          <button
            type="button"
            disabled={retentionBusy}
            onClick={() => void handleRunPurgeNow()}
            className="px-4 py-2 text-xs font-medium text-[var(--fw-text-body)] bg-[var(--fw-bg)] border border-[var(--fw-border-strong)] rounded-md hover:bg-[var(--fw-surface)] disabled:opacity-50"
          >
            Executar Limpeza Agora
          </button>

          {retention && (
            <p className="text-xs text-[var(--fw-text-muted)] tabular-nums">
              {retention.lastPurgeAt
                ? `Última limpeza: ${new Date(retention.lastPurgeAt).toLocaleString('pt-BR')} (${retention.lastPurgedCount} removidos)`
                : 'Nenhuma limpeza manual executada ainda nesta sessão'}
            </p>
          )}
        </div>

        {retentionFeedback && (
          <div
            className={`p-3 rounded-md border text-xs ${
              retentionFeedback.type === 'ok'
                ? 'bg-[var(--fw-surface)] border-[var(--fw-border-strong)] text-[var(--fw-heading)]'
                : 'bg-red-50 border-red-200 text-red-800'
            }`}
          >
            {retentionFeedback.text}
          </div>
        )}
      </div>

      <div className="bg-white border border-[var(--fw-border)] rounded-lg p-6 space-y-5">
        <div className="pb-3 border-b border-[var(--fw-border-soft)]">
          <h2 className="text-sm font-semibold text-[var(--fw-heading)]">
            Implantação Containerizada no Ubuntu Server ({theme.label})
          </h2>
          <p className="text-xs text-[var(--fw-text-muted)] mt-1">
            Portas UDP dedicadas por fabricante (5514 SonicWall / 5515 FortiGate) com isolamento
            por container e banco PostgreSQL compartilhado.
          </p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-[var(--fw-heading)]">
                1. Configuração rsyslog (porta 514 → {Number(udpPort) || theme.defaultUdpPort})
              </span>
              <button
                type="button"
                onClick={() => void copyText('rsyslog', rsyslogSnippet)}
                className="inline-flex items-center gap-1 text-xs text-[var(--fw-accent)] hover:underline"
              >
                {copiedBlock === 'rsyslog' ? (
                  <Check className="w-3 h-3" />
                ) : (
                  <Copy className="w-3 h-3" />
                )}
                {copiedBlock === 'rsyslog' ? 'Copiado' : 'Copiar'}
              </button>
            </div>
            <pre className="p-4 bg-[var(--fw-terminal-bg)] text-[var(--fw-terminal-text)] rounded-md font-mono text-[11px] overflow-x-auto leading-5">
              {rsyslogSnippet}
            </pre>
          </div>

          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-[var(--fw-heading)]">
                2. Serviço Docker Compose ({vendor})
              </span>
              <button
                type="button"
                onClick={() => void copyText('compose', composeSnippet)}
                className="inline-flex items-center gap-1 text-xs text-[var(--fw-accent)] hover:underline"
              >
                {copiedBlock === 'compose' ? (
                  <Check className="w-3 h-3" />
                ) : (
                  <Copy className="w-3 h-3" />
                )}
                {copiedBlock === 'compose' ? 'Copiado' : 'Copiar'}
              </button>
            </div>
            <pre className="p-4 bg-[var(--fw-terminal-bg)] text-[var(--fw-terminal-text)] rounded-md font-mono text-[11px] overflow-x-auto leading-5">
              {composeSnippet}
            </pre>
          </div>
        </div>

        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-[var(--fw-heading)]">
              3. Ingestão automática via CLI / Cron no Linux
            </span>
            <button
              type="button"
              onClick={() => void copyText('curl', curlSnippet)}
              className="inline-flex items-center gap-1 text-xs text-[var(--fw-accent)] hover:underline"
            >
              {copiedBlock === 'curl' ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
              {copiedBlock === 'curl' ? 'Copiado' : 'Copiar'}
            </button>
          </div>
          <pre className="p-4 bg-[var(--fw-terminal-bg)] text-[var(--fw-terminal-text)] rounded-md font-mono text-[11px] overflow-x-auto leading-5">
            {curlSnippet}
          </pre>
        </div>
      </div>
    </div>
  );
}
