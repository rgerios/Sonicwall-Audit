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
import type { AuditOverview, FirewallSiteSummary, RetentionStatus, UdpListenerStatus } from '../types.ts';

interface ConnectLinuxViewProps {
  overview: AuditOverview | null;
  onDataChanged: () => void;
  onOverviewUpdated: (next: AuditOverview) => void;
}

const RSYSLOG_SNIPPET = `# /etc/rsyslog.d/30-sonicwall.conf
# Encaminha logs do SonicWall para o SonicAudit e mantém rotação segura no Linux
module(load="imudp")
input(type="imudp" port="514")

if ($fromhost-ip == '192.168.10.1' or $msg contains 'id=firewall') then {
  action(type="omfile" file="/var/log/sonicwall.log")
  action(type="omfwd" target="127.0.0.1" port="5514" protocol="udp")
  stop
}`;

const SYSTEMD_SNIPPET = `# /etc/systemd/system/sonicaudit.service
[Unit]
Description=SonicAudit — Analisador SonicWall Syslog, NAT e Firewall
After=network-online.target

[Service]
Type=simple
User=sonicaudit
WorkingDirectory=/opt/sonicaudit
Environment=NODE_ENV=production
Environment=PORT=3000
ExecStart=/usr/bin/node /opt/sonicaudit/server.ts
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target`;

const CURL_INGEST_SNIPPET = `# Enviar arquivo de syslog histórico do Linux diretamente para a API local:
curl -X POST http://localhost:3000/api/syslogs/ingest \\
  -H "Content-Type: text/plain" \\
  --data-binary @/var/log/sonicwall.log`;

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

export function ConnectLinuxView({
  overview,
  onDataChanged,
  onOverviewUpdated,
}: ConnectLinuxViewProps) {
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
  const [siteUsername, setSiteUsername] = useState('admin');
  const [sitePassword, setSitePassword] = useState('');
  const [siteSavePass, setSiteSavePass] = useState(true);
  const [siteIgnoreTls, setSiteIgnoreTls] = useState(true);
  const [siteBusy, setSiteBusy] = useState(false);
  const [syncingSiteId, setSyncingSiteId] = useState<string | null>(null);
  const [siteFeedback, setSiteFeedback] = useState<{ type: 'ok' | 'err'; text: string } | null>(null);

  // Active site SonicOS API connection form
  const [host, setHost] = useState('192.168.10.1');
  const [port, setPort] = useState('443');
  const [protocol, setProtocol] = useState<'https' | 'http'>('https');
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('');
  const [savePassword, setSavePassword] = useState(true);
  const [ignoreTlsErrors, setIgnoreTlsErrors] = useState(true);
  const [apiLoading, setApiLoading] = useState(false);
  const [apiFeedback, setApiFeedback] = useState<{ type: 'ok' | 'err'; text: string } | null>(null);

  const [udpPort, setUdpPort] = useState('5514');
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
    if (activeSite) {
      setHost(activeSite.connection.host || '192.168.10.1');
      setPort(String(activeSite.connection.port || 443));
      setProtocol(activeSite.connection.protocol === 'http' ? 'http' : 'https');
      setUsername(activeSite.connection.username || 'admin');
      setIgnoreTlsErrors(activeSite.connection.ignoreTlsErrors !== false);
      setPassword('');
    }
  }, [
    activeSite?.id,
    activeSite?.connection.host,
    activeSite?.connection.port,
    activeSite?.connection.protocol,
    activeSite?.connection.username,
    activeSite?.connection.ignoreTlsErrors,
  ]);

  const loadStatuses = async () => {
    const [udpRes, retRes] = await Promise.all([
      fetch('/api/syslog-server/status'),
      fetch('/api/retention'),
    ]);
    if (udpRes.ok) {
      const status = (await udpRes.json()) as UdpListenerStatus;
      setUdpStatus(status);
      setUdpPort(String(status.port));
    }
    if (retRes.ok) {
      const ret = (await retRes.json()) as RetentionStatus;
      setRetention(ret);
      setRetentionInput(String(ret.retentionDays));
    }
  };

  useEffect(() => {
    void loadStatuses();
  }, [activeSite?.id]);

  const openNewSiteForm = () => {
    setEditingSiteId(null);
    setSiteName('');
    setSiteLocation('');
    setSiteNotes('');
    setSiteHost('');
    setSitePort('443');
    setSiteProtocol('https');
    setSiteUsername('admin');
    setSitePassword('');
    setSiteSavePass(true);
    setSiteIgnoreTls(true);
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
    setSiteUsername(site.connection.username || 'admin');
    setSitePassword('');
    setSiteSavePass(site.connection.hasSavedPassword);
    setSiteIgnoreTls(site.connection.ignoreTlsErrors);
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
          username: siteUsername.trim() || 'admin',
          password: sitePassword,
          savePassword: siteSavePass,
          ignoreTlsErrors: siteIgnoreTls,
        },
      };

      const url = editingSiteId ? `/api/sites/${editingSiteId}` : '/api/sites';
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
            ? 'Localidade atualizada com persistência no servidor.'
            : `Localidade "${payload.name}" criada e selecionada.`,
        });
        onDataChanged();
      }
    } finally {
      setSiteBusy(false);
    }
  };

  const handleSelectSite = async (siteId: string) => {
    setSiteFeedback(null);
    const res = await fetch(`/api/sites/${siteId}/select`, { method: 'POST' });
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
      const res = await fetch(`/api/sites/${siteId}/sync`, {
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
          text: `Localidade sincronizada via API SonicOS (${data.rulesCount} regras, ${data.natsCount} NATs).`,
        });
        onDataChanged();
      }
    } finally {
      setSyncingSiteId(null);
    }
  };

  const handleDeleteSite = async (site: FirewallSiteSummary) => {
    setSiteFeedback(null);
    const res = await fetch(`/api/sites/${site.id}`, { method: 'DELETE' });
    const data = await res.json();
    if (!res.ok) {
      setSiteFeedback({ type: 'err', text: data.error || 'Não foi possível excluir localidade.' });
    } else {
      if (data.overview) onOverviewUpdated(data.overview);
      setSiteFeedback({ type: 'ok', text: `Localidade "${site.name}" removida.` });
      onDataChanged();
    }
  };

  const handleSonicOsAudit = async (e: React.FormEvent) => {
    e.preventDefault();
    setApiLoading(true);
    setApiFeedback(null);
    try {
      const res = await fetch('/api/sonicwall/audit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          siteId: activeSite?.id,
          host,
          port: Number(port),
          protocol,
          username,
          password,
          savePassword,
          ignoreTlsErrors,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setApiFeedback({ type: 'err', text: data.error || 'Falha na conexão com o SonicWall.' });
      } else {
        if (data.overview) onOverviewUpdated(data.overview);
        setPassword('');
        setApiFeedback({
          type: 'ok',
          text: `Sincronizado com sucesso e salvo na localidade ativa: ${data.rulesCount} regras e ${data.natsCount} políticas NAT.`,
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
      const endpoint = udpStatus?.running ? '/api/syslog-server/stop' : '/api/syslog-server/start';
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ port: Number(udpPort) || 5514 }),
      });
      const data = await res.json();
      if (!res.ok) {
        setUdpFeedback({ type: 'err', text: data.error || 'Erro ao alterar receptor UDP.' });
      } else {
        setUdpStatus(data);
        setUdpFeedback({
          type: 'ok',
          text: data.running
            ? `Receptor UDP ativo na porta ${data.port}. Syslogs recebidos são roteados pelo Serial/IP para cada localidade.`
            : 'Receptor UDP encerrado.',
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
      const res = await fetch('/api/syslog-server/test-packet', { method: 'POST' });
      const data = await res.json();
      if (!res.ok) {
        setUdpFeedback({ type: 'err', text: data.error || 'Falha no envio de pacote teste.' });
      } else {
        setUdpStatus(data.status);
        setUdpFeedback({
          type: 'ok',
          text: 'Pacote UDP SonicWall recebido e processado pelo socket local.',
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
      const res = await fetch('/api/retention', {
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
      const res = await fetch('/api/retention/purge', { method: 'POST' });
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
      const res = await fetch('/api/config/import', {
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
      const res = await fetch('/api/syslogs/ingest', {
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
    await fetch('/api/data/clear', { method: 'POST' });
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

  return (
    <div className="space-y-6">
      <div className="bg-white border border-[#D4E4D8] rounded-lg p-6 space-y-4">
        <div className="pb-3 border-b border-[#E6F0E8] flex flex-wrap items-center justify-between gap-4">
          <div>
            <h2 className="text-sm font-semibold text-[#123325] inline-flex items-center gap-2">
              <Building2 className="w-4 h-4 text-[#1E4D3B]" />
              Localidades e Firewalls Persistentes ({sites.length})
            </h2>
            <p className="text-xs text-[#4B6B5C] mt-1">
              Cada localidade armazena separadamente suas credenciais criptografadas, regras, NATs,
              telemetria e syslogs em disco no Linux.
            </p>
          </div>
          <button
            type="button"
            onClick={openNewSiteForm}
            className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium text-white bg-[#1E4D3B] rounded-md hover:bg-[#163A2C] whitespace-nowrap"
          >
            <Plus className="w-3.5 h-3.5" />
            Nova Localidade
          </button>
        </div>

        {showSiteForm && (
          <form
            onSubmit={(e) => void handleSaveSite(e)}
            className="p-4 bg-[#F4F8F5] border border-[#BFD5C5] rounded-md space-y-4"
          >
            <div className="flex items-center justify-between border-b border-[#DCE9E0] pb-2">
              <span className="text-xs font-semibold text-[#123325]">
                {editingSiteId ? 'Editar Localidade / Firewall' : 'Cadastrar Nova Localidade'}
              </span>
              <button
                type="button"
                onClick={() => setShowSiteForm(false)}
                className="text-xs text-[#4B6B5C] hover:underline"
              >
                Cancelar
              </button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
              <div>
                <label className="block font-medium text-[#1D3B2E] mb-1">Nome da Localidade</label>
                <input
                  type="text"
                  value={siteName}
                  onChange={(e) => setSiteName(e.target.value)}
                  required
                  placeholder="Ex: Filial Campinas"
                  className="w-full px-3 py-2 border border-[#BFD5C5] rounded bg-white"
                />
              </div>
              <div>
                <label className="block font-medium text-[#1D3B2E] mb-1">Cidade / Unidade</label>
                <input
                  type="text"
                  value={siteLocation}
                  onChange={(e) => setSiteLocation(e.target.value)}
                  placeholder="Ex: Campinas / SP"
                  className="w-full px-3 py-2 border border-[#BFD5C5] rounded bg-white"
                />
              </div>
              <div>
                <label className="block font-medium text-[#1D3B2E] mb-1">Observações</label>
                <input
                  type="text"
                  value={siteNotes}
                  onChange={(e) => setSiteNotes(e.target.value)}
                  placeholder="Ex: Link Vivo + Backup Claro"
                  className="w-full px-3 py-2 border border-[#BFD5C5] rounded bg-white"
                />
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-5 gap-3 text-xs">
              <div className="md:col-span-2">
                <label className="block font-medium text-[#1D3B2E] mb-1">IP / Hostname SonicOS</label>
                <input
                  type="text"
                  value={siteHost}
                  onChange={(e) => setSiteHost(e.target.value)}
                  placeholder="10.20.0.1"
                  className="w-full px-3 py-2 font-mono border border-[#BFD5C5] rounded bg-white"
                />
              </div>
              <div>
                <label className="block font-medium text-[#1D3B2E] mb-1">Proto / Porta</label>
                <div className="flex gap-1">
                  <select
                    value={siteProtocol}
                    onChange={(e) => setSiteProtocol(e.target.value === 'http' ? 'http' : 'https')}
                    className="px-2 py-2 font-mono border border-[#BFD5C5] rounded bg-white"
                  >
                    <option value="https">HTTPS</option>
                    <option value="http">HTTP</option>
                  </select>
                  <input
                    type="number"
                    value={sitePort}
                    onChange={(e) => setSitePort(e.target.value)}
                    className="w-full px-2 py-2 font-mono border border-[#BFD5C5] rounded bg-white"
                  />
                </div>
              </div>
              <div>
                <label className="block font-medium text-[#1D3B2E] mb-1">Usuário API</label>
                <input
                  type="text"
                  value={siteUsername}
                  onChange={(e) => setSiteUsername(e.target.value)}
                  className="w-full px-3 py-2 font-mono border border-[#BFD5C5] rounded bg-white"
                />
              </div>
              <div>
                <label className="block font-medium text-[#1D3B2E] mb-1">Senha API</label>
                <input
                  type="password"
                  value={sitePassword}
                  onChange={(e) => setSitePassword(e.target.value)}
                  placeholder={editingSiteId ? '(Manter atual)' : '••••••••'}
                  className="w-full px-3 py-2 border border-[#BFD5C5] rounded bg-white"
                />
              </div>
            </div>

            <div className="flex flex-wrap items-center justify-between gap-4 text-xs pt-1">
              <div className="flex flex-wrap items-center gap-4">
                <label className="inline-flex items-center gap-2 text-[#1D3B2E] cursor-pointer">
                  <input
                    type="checkbox"
                    checked={siteSavePass}
                    onChange={(e) => setSiteSavePass(e.target.checked)}
                    className="rounded border-[#9EC2AA] accent-[#1E4D3B]"
                  />
                  Salvar senha criptografada (AES-256) para re-sincronização rápida
                </label>
                <label className="inline-flex items-center gap-2 text-[#456354] cursor-pointer">
                  <input
                    type="checkbox"
                    checked={siteIgnoreTls}
                    onChange={(e) => setSiteIgnoreTls(e.target.checked)}
                    className="rounded border-[#9EC2AA] accent-[#1E4D3B]"
                  />
                  Ignorar TLS autoassinado
                </label>
              </div>
              <button
                type="submit"
                disabled={siteBusy}
                className="px-4 py-2 text-xs font-medium text-white bg-[#1E4D3B] rounded-md hover:bg-[#163A2C] disabled:opacity-50"
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
                ? 'bg-[#E7F2EA] border-[#B6D4BE] text-[#143D2C]'
                : 'bg-red-50 border-red-200 text-red-800'
            }`}
          >
            {siteFeedback.text}
          </div>
        )}

        <div className="overflow-x-auto border border-[#D4E4D8] rounded-md">
          <table className="w-full text-xs">
            <thead>
              <tr className="bg-[#EDF5EF] text-[#244838] border-b border-[#D4E4D8]">
                <th className="py-2.5 px-3 text-left font-medium">Localidade</th>
                <th className="py-2.5 px-3 text-left font-medium">Appliance / Serial</th>
                <th className="py-2.5 px-3 text-left font-medium">Endpoint SonicOS</th>
                <th className="py-2.5 px-3 text-right font-medium">Syslogs</th>
                <th className="py-2.5 px-3 text-right font-medium">Regras / NATs</th>
                <th className="py-2.5 px-3 text-right font-medium">Alertas</th>
                <th className="py-2.5 px-3 text-right font-medium">Ações</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#E6F0E8]">
              {sites.map((site) => {
                const isActive = site.id === activeSite?.id;
                const canQuickSync = Boolean(site.connection.host && site.connection.hasSavedPassword);
                return (
                  <tr key={site.id} className={isActive ? 'bg-[#F4F8F5]' : 'bg-white'}>
                    <td className="py-2.5 px-3">
                      <div className="flex items-center gap-2">
                        <span className="font-semibold text-[#123325]">{site.name}</span>
                        {isActive && (
                          <span className="inline-flex items-center gap-1 text-[11px] font-medium text-emerald-800">
                            <CheckCircle2 className="w-3.5 h-3.5" /> Ativa
                          </span>
                        )}
                      </div>
                      <p className="text-[11px] text-[#5C7A6B]">
                        {site.location || 'Sem unidade informada'}
                        {site.notes ? ` · ${site.notes}` : ''}
                      </p>
                    </td>
                    <td className="py-2.5 px-3">
                      <p className="text-[#123325] font-medium truncate max-w-[190px]">
                        {site.appliance.model}
                      </p>
                      <p className="text-[11px] font-mono text-[#5C7A6B]">
                        S/N: {site.appliance.serialNumber}
                      </p>
                    </td>
                    <td className="py-2.5 px-3">
                      <p className="font-mono text-[#123325]">
                        {site.connection.host
                          ? `${site.connection.protocol}://${site.connection.host}:${site.connection.port}`
                          : 'Não configurado'}
                      </p>
                      <p className="text-[11px] text-[#5C7A6B] inline-flex items-center gap-1">
                        <Lock className="w-3 h-3" />
                        {site.connection.hasSavedPassword ? 'Senha salva (AES-256)' : 'Sem senha salva'}
                      </p>
                    </td>
                    <td className="py-2.5 px-3 text-right font-mono tabular-nums text-[#123325]">
                      {site.totalSyslogs.toLocaleString('pt-BR')}
                    </td>
                    <td className="py-2.5 px-3 text-right font-mono tabular-nums text-[#456354]">
                      {site.rulesCount} / {site.natsCount}
                    </td>
                    <td className="py-2.5 px-3 text-right font-mono tabular-nums">
                      <span
                        className={
                          site.criticalAlertsCount > 0
                            ? 'text-red-700 font-semibold'
                            : site.alertsCount > 0
                              ? 'text-amber-800 font-semibold'
                              : 'text-[#5C7A6B]'
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
                            className="px-2.5 py-1 text-[11px] font-medium text-[#1E4D3B] bg-white border border-[#BFD5C5] rounded hover:bg-[#EDF5EF]"
                          >
                            Selecionar
                          </button>
                        )}
                        {canQuickSync && (
                          <button
                            type="button"
                            disabled={syncingSiteId === site.id}
                            onClick={() => void handleQuickSyncSite(site.id)}
                            title="Sincronizar via API SonicOS usando senha salva"
                            className="inline-flex items-center gap-1 px-2.5 py-1 text-[11px] font-medium text-white bg-[#1E4D3B] rounded hover:bg-[#163A2C] disabled:opacity-50"
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
                          className="p-1.5 text-[#4B6B5C] hover:text-[#123325] hover:bg-[#EDF5EF] rounded"
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
          onSubmit={handleSonicOsAudit}
          className="bg-white border border-[#D4E4D8] rounded-lg p-6 space-y-4"
        >
          <div className="pb-3 border-b border-[#E6F0E8]">
            <h2 className="text-sm font-semibold text-[#123325]">
              Conexão Direta — API REST SonicOS ({activeSite?.name || 'Localidade Ativa'})
            </h2>
            <p className="text-xs text-[#4B6B5C] mt-1">
              Consulta diretamente regras, NATs, uptime, links e licenças do SonicWall desta
              localidade e mantém os dados salvos no servidor.
            </p>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div className="sm:col-span-2">
              <label className="block text-xs font-medium text-[#1D3B2E] mb-1">
                IP ou Hostname do SonicWall
              </label>
              <input
                type="text"
                value={host}
                onChange={(e) => setHost(e.target.value)}
                required
                placeholder="192.168.10.1"
                className="w-full px-3 py-2 text-xs font-mono border border-[#BFD5C5] rounded-md focus:outline-none focus:ring-2 focus:ring-[#2A6B52]"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-[#1D3B2E] mb-1">Porta / Proto</label>
              <div className="flex gap-1.5">
                <select
                  value={protocol}
                  onChange={(e) => setProtocol(e.target.value === 'http' ? 'http' : 'https')}
                  className="px-2 py-2 text-xs font-mono border border-[#BFD5C5] rounded-md bg-white"
                >
                  <option value="https">HTTPS</option>
                  <option value="http">HTTP</option>
                </select>
                <input
                  type="number"
                  value={port}
                  onChange={(e) => setPort(e.target.value)}
                  className="w-full px-2.5 py-2 text-xs font-mono border border-[#BFD5C5] rounded-md"
                />
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-medium text-[#1D3B2E] mb-1">
                Usuário Admin / Read-Only
              </label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
                className="w-full px-3 py-2 text-xs font-mono border border-[#BFD5C5] rounded-md focus:outline-none focus:ring-2 focus:ring-[#2A6B52]"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-[#1D3B2E] mb-1">Senha</label>
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
                className="w-full px-3 py-2 text-xs border border-[#BFD5C5] rounded-md focus:outline-none focus:ring-2 focus:ring-[#2A6B52]"
              />
            </div>
          </div>

          <div className="space-y-2">
            <label className="flex items-center gap-2 text-xs text-[#1D3B2E] cursor-pointer">
              <input
                type="checkbox"
                checked={savePassword}
                onChange={(e) => setSavePassword(e.target.checked)}
                className="rounded border-[#9EC2AA] accent-[#1E4D3B]"
              />
              Salvar credenciais criptografadas (AES-256) nesta localidade
            </label>
            <label className="flex items-center gap-2 text-xs text-[#456354] cursor-pointer">
              <input
                type="checkbox"
                checked={ignoreTlsErrors}
                onChange={(e) => setIgnoreTlsErrors(e.target.checked)}
                className="rounded border-[#9EC2AA] accent-[#1E4D3B]"
              />
              Ignorar erro de certificado TLS autoassinado (comum em interfaces locais SonicOS)
            </label>
          </div>

          {apiFeedback && (
            <div
              className={`p-3 rounded-md border text-xs ${
                apiFeedback.type === 'ok'
                  ? 'bg-[#E7F2EA] border-[#B6D4BE] text-[#143D2C]'
                  : 'bg-red-50 border-red-200 text-red-800'
              }`}
            >
              {apiFeedback.text}
            </div>
          )}

          <div className="pt-1 flex items-center justify-between gap-3">
            <span className="text-[11px] text-[#4B6B5C]">
              Habilite em: Manage → System Setup → Appliance → SonicOS API
            </span>
            <button
              type="submit"
              disabled={apiLoading}
              className="inline-flex items-center gap-2 px-4 py-2 text-xs font-medium text-white bg-[#1E4D3B] rounded-md hover:bg-[#163A2C] disabled:opacity-50 whitespace-nowrap shrink-0"
            >
              <ShieldCheck className="w-3.5 h-3.5" />
              {apiLoading ? 'Auditando...' : 'Conectar e Auditar'}
            </button>
          </div>
        </form>

        <div className="space-y-6">
          <div className="bg-white border border-[#D4E4D8] rounded-lg p-6 space-y-4">
            <div className="pb-3 border-b border-[#E6F0E8] flex items-center justify-between">
              <div>
                <h2 className="text-sm font-semibold text-[#123325]">
                  Receptor UDP Syslog (Socket Linux)
                </h2>
                <p className="text-xs text-[#4B6B5C] mt-1">
                  Recebe pacotes UDP de múltiplas localidades e roteia por Serial/IP
                </p>
              </div>
              {udpStatus?.running ? (
                <span className="inline-flex items-center gap-1.5 text-xs font-mono text-[#1E4D3B] font-medium">
                  <Radio className="w-3.5 h-3.5" /> Escutando :{udpStatus.port}
                </span>
              ) : (
                <span className="text-xs font-mono text-[#4B6B5C]">Inativo</span>
              )}
            </div>

            <div className="flex flex-wrap items-end gap-3">
              <div>
                <label className="block text-xs font-medium text-[#1D3B2E] mb-1">Porta UDP</label>
                <input
                  type="number"
                  value={udpPort}
                  disabled={udpStatus?.running}
                  onChange={(e) => setUdpPort(e.target.value)}
                  className="w-28 px-3 py-2 text-xs font-mono border border-[#BFD5C5] rounded-md disabled:bg-[#EDF5EF]"
                />
              </div>

              <button
                type="button"
                disabled={udpBusy}
                onClick={() => void handleToggleUdp()}
                className={`inline-flex items-center gap-1.5 px-4 py-2 text-xs font-medium rounded-md whitespace-nowrap ${
                  udpStatus?.running
                    ? 'text-red-700 bg-red-50 border border-red-200 hover:bg-red-100'
                    : 'text-white bg-[#1E4D3B] hover:bg-[#163A2C]'
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
                  className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-[#1D3B2E] bg-white border border-[#BFD5C5] rounded-md hover:bg-[#EDF5EF] whitespace-nowrap"
                >
                  <Send className="w-3.5 h-3.5" /> Testar Pacote Local
                </button>
              )}
            </div>

            {udpStatus && (
              <p className="text-xs text-[#4B6B5C] font-mono tabular-nums">
                Pacotes recebidos nesta sessão: {udpStatus.packetsReceived.toLocaleString('pt-BR')}
                {udpStatus.lastPacketAt ? ` · Último: ${udpStatus.lastPacketAt}` : ''}
              </p>
            )}

            {udpFeedback && (
              <div
                className={`p-3 rounded-md border text-xs ${
                  udpFeedback.type === 'ok'
                    ? 'bg-[#E7F2EA] border-[#B6D4BE] text-[#143D2C]'
                    : 'bg-red-50 border-red-200 text-red-800'
                }`}
              >
                {udpFeedback.text}
              </div>
            )}
          </div>

          <div className="bg-white border border-[#D4E4D8] rounded-lg p-6 space-y-4">
            <div className="pb-3 border-b border-[#E6F0E8] flex items-center justify-between">
              <div>
                <h2 className="text-sm font-semibold text-[#123325]">
                  Importação Offline ({activeSite?.name || 'Localidade Ativa'})
                </h2>
                <p className="text-xs text-[#4B6B5C] mt-1">
                  Importe arquivos .exp, .json ou .log para esta localidade
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
              <label className="inline-flex items-center gap-2 px-4 py-2 text-xs font-medium text-[#1D3B2E] bg-[#F4F8F5] border border-[#BFD5C5] rounded-md hover:bg-[#E7F2EA] cursor-pointer">
                <FileUp className="w-3.5 h-3.5" />
                {configBusy ? 'Processando...' : 'Importar Config (.exp / .json)'}
                <input
                  type="file"
                  accept=".exp,.json,.txt"
                  className="hidden"
                  onChange={(e) => void handleConfigUpload(e.target.files?.[0])}
                />
              </label>

              <label className="inline-flex items-center gap-2 px-4 py-2 text-xs font-medium text-[#1D3B2E] bg-[#F4F8F5] border border-[#BFD5C5] rounded-md hover:bg-[#E7F2EA] cursor-pointer">
                <FileUp className="w-3.5 h-3.5" />
                Importar Arquivo Syslog (.log)
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
                    ? 'bg-[#E7F2EA] border-[#B6D4BE] text-[#143D2C]'
                    : 'bg-red-50 border-red-200 text-red-800'
                }`}
              >
                {configFeedback.text}
              </div>
            )}
          </div>
        </div>
      </div>

      <div className="bg-white border border-[#D4E4D8] rounded-lg p-6 space-y-4">
        <div className="pb-3 border-b border-[#E6F0E8] flex flex-wrap items-center justify-between gap-4">
          <div>
            <h2 className="text-sm font-semibold text-[#123325] inline-flex items-center gap-2">
              <HardDrive className="w-4 h-4 text-[#1E4D3B]" />
              Retenção Automática de Syslogs e Proteção de Disco
            </h2>
            <p className="text-xs text-[#4B6B5C] mt-1">
              Syslogs mais antigos que o prazo configurado são expirados automaticamente no
              carregamento, na ingestão e a cada 1 hora em segundo plano.
            </p>
          </div>
          {retention && (
            <span className="font-mono text-xs text-[#123325] tabular-nums">
              Uso em disco (data/store.json): {formatBytes(retention.storeSizeBytes)}
            </span>
          )}
        </div>

        <div className="flex flex-wrap items-end gap-4">
          <div>
            <label className="block text-xs font-medium text-[#1D3B2E] mb-1">
              Expirar syslogs após (dias)
            </label>
            <input
              type="number"
              min={1}
              max={365}
              value={retentionInput}
              onChange={(e) => setRetentionInput(e.target.value)}
              className="w-28 px-3 py-2 text-xs font-mono border border-[#BFD5C5] rounded-md"
            />
          </div>

          <button
            type="button"
            disabled={retentionBusy}
            onClick={() => void handleSaveRetention()}
            className="px-4 py-2 text-xs font-medium text-white bg-[#1E4D3B] rounded-md hover:bg-[#163A2C] disabled:opacity-50"
          >
            Salvar Retenção
          </button>

          <button
            type="button"
            disabled={retentionBusy}
            onClick={() => void handleRunPurgeNow()}
            className="px-4 py-2 text-xs font-medium text-[#1D3B2E] bg-[#F4F8F5] border border-[#BFD5C5] rounded-md hover:bg-[#E7F2EA] disabled:opacity-50"
          >
            Executar Limpeza Agora
          </button>

          {retention && (
            <p className="text-xs text-[#4B6B5C] tabular-nums">
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
                ? 'bg-[#E7F2EA] border-[#B6D4BE] text-[#143D2C]'
                : 'bg-red-50 border-red-200 text-red-800'
            }`}
          >
            {retentionFeedback.text}
          </div>
        )}
      </div>

      <div className="bg-white border border-[#D4E4D8] rounded-lg p-6 space-y-5">
        <div className="pb-3 border-b border-[#E6F0E8]">
          <h2 className="text-sm font-semibold text-[#123325]">
            Implantação em Produção no Linux (Ubuntu / Debian / RHEL)
          </h2>
          <p className="text-xs text-[#4B6B5C] mt-1">
            Use as configurações abaixo para receber syslogs na porta padrão 514 via rsyslog sem
            precisar rodar o Node.js como root e manter o serviço ativo via systemd.
          </p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-[#123325]">
                1. Configuração rsyslog (porta 514 → 5514)
              </span>
              <button
                type="button"
                onClick={() => void copyText('rsyslog', RSYSLOG_SNIPPET)}
                className="inline-flex items-center gap-1 text-xs text-[#1E4D3B] hover:underline"
              >
                {copiedBlock === 'rsyslog' ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                {copiedBlock === 'rsyslog' ? 'Copiado' : 'Copiar'}
              </button>
            </div>
            <pre className="p-4 bg-[#0E221A] text-[#E6F2EB] rounded-md font-mono text-[11px] overflow-x-auto leading-5">
              {RSYSLOG_SNIPPET}
            </pre>
          </div>

          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-[#123325]">
                2. Serviço systemd (execução contínua)
              </span>
              <button
                type="button"
                onClick={() => void copyText('systemd', SYSTEMD_SNIPPET)}
                className="inline-flex items-center gap-1 text-xs text-[#1E4D3B] hover:underline"
              >
                {copiedBlock === 'systemd' ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                {copiedBlock === 'systemd' ? 'Copiado' : 'Copiar'}
              </button>
            </div>
            <pre className="p-4 bg-[#0E221A] text-[#E6F2EB] rounded-md font-mono text-[11px] overflow-x-auto leading-5">
              {SYSTEMD_SNIPPET}
            </pre>
          </div>
        </div>

        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-[#123325]">
              3. Ingestão automática via CLI / Cron no Linux
            </span>
            <button
              type="button"
              onClick={() => void copyText('curl', CURL_INGEST_SNIPPET)}
              className="inline-flex items-center gap-1 text-xs text-[#1E4D3B] hover:underline"
            >
              {copiedBlock === 'curl' ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
              {copiedBlock === 'curl' ? 'Copiado' : 'Copiar'}
            </button>
          </div>
          <pre className="p-4 bg-[#0E221A] text-[#E6F2EB] rounded-md font-mono text-[11px] overflow-x-auto leading-5">
            {CURL_INGEST_SNIPPET}
          </pre>
        </div>
      </div>
    </div>
  );
}
