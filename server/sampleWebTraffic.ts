/**
 * Tráfego web de demonstração (somente amostras): destinos com FQDN para o radar de destinos
 * ter o que mostrar sem um firewall real. Os nomes vêm no próprio log (dstname/hostname).
 */
interface SampleDestination {
  host: string;
  ip: string;
  count: number;
  app?: string;
}

const SAMPLE_DESTINATIONS: SampleDestination[] = [
  { host: 'edge.microsoft.com', ip: '13.107.42.16', count: 22, app: 'Microsoft Edge' },
  { host: 'mobile.events.data.microsoft.com', ip: '20.189.173.5', count: 16 },
  { host: 'v10.events.data.microsoft.com', ip: '20.189.173.7', count: 9 },
  { host: 'settings-win.data.microsoft.com', ip: '40.127.240.158', count: 7 },
  { host: 'windowsupdate.microsoft.com', ip: '40.77.226.250', count: 30, app: 'Windows Update' },
  { host: 'outlook.office365.com', ip: '52.96.164.18', count: 34, app: 'Microsoft 365' },
  { host: 'crl3.digicert.com', ip: '192.229.211.108', count: 18 },
  { host: 'ocsp.digicert.com', ip: '192.229.211.109', count: 11 },
  { host: 'cloud-ecs.gravityzone.bitdefender.com', ip: '34.107.221.82', count: 14 },
  { host: 'lc-bootstrap.bitdefender.com', ip: '34.107.221.90', count: 8 },
  { host: 'us-lurker.bitdefender.net', ip: '34.107.221.99', count: 7 },
  { host: 'www.google.com', ip: '142.250.219.14', count: 40 },
  { host: 'www.gstatic.com', ip: '142.250.219.35', count: 26 },
  { host: 'pki.goog', ip: '142.250.79.99', count: 15 },
  { host: 'g.whatsapp.net', ip: '157.240.222.60', count: 17, app: 'WhatsApp' },
  { host: 'mmg.whatsapp.net', ip: '157.240.222.61', count: 6, app: 'WhatsApp' },
  { host: 'zoom.us', ip: '170.114.52.2', count: 12, app: 'Zoom' },
  { host: 'grafana.com', ip: '34.120.177.193', count: 5 },
  { host: 'relay.anydesk.com', ip: '139.162.58.5', count: 9, app: 'AnyDesk' },
  { host: 'api.ipify.org', ip: '104.26.12.205', count: 10 },
  { host: 'cdn.cloudflare.com', ip: '172.64.155.12', count: 13 },
  { host: 'github.com', ip: '140.82.112.4', count: 8 },
];

const SOURCES = ['10.20.1.12', '10.20.1.19', '10.20.1.33', '10.20.1.45', '10.20.1.60', '10.20.1.71', '10.20.2.15'];
const pad = (n: number) => String(n).padStart(2, '0');

function when(index: number, total: number): Date {
  // Distribui ao longo das últimas ~50 minutos
  return new Date(Date.now() - Math.floor((index / total) * 50 * 60 * 1000) - 5000);
}

export function sonicWallSampleWebLines(): string[] {
  const lines: string[] = [];
  let i = 0;
  const total = SAMPLE_DESTINATIONS.reduce((s, d) => s + d.count, 0);
  for (const d of SAMPLE_DESTINATIONS) {
    for (let k = 0; k < d.count; k += 1) {
      const t = when(i, total);
      const ts = `${t.getFullYear()}-${pad(t.getMonth() + 1)}-${pad(t.getDate())} ${pad(t.getHours())}:${pad(t.getMinutes())}:${pad(t.getSeconds())}`;
      const src = SOURCES[(i + k) % SOURCES.length];
      lines.push(
        `<134>id=firewall sn=2CB8ED549A10 time="${ts}" fw=192.168.10.1 pri=6 c=1024 m=537 msg="Connection Closed" src=${src}:${40000 + ((i * 37) % 20000)}:X0 dst=${d.ip}:443:X1 proto=tcp/https sent=${900 + ((i * 131) % 4000)} rcvd=${6000 + ((i * 977) % 90000)} fw_action="allow" rule="R-01" dstname="${d.host}"${d.app ? ` appName="${d.app}"` : ''}`
      );
      i += 1;
    }
  }
  return lines;
}

export function fortiGateSampleWebLines(): string[] {
  const lines: string[] = [];
  let i = 0;
  const total = SAMPLE_DESTINATIONS.reduce((s, d) => s + d.count, 0);
  for (const d of SAMPLE_DESTINATIONS) {
    for (let k = 0; k < d.count; k += 1) {
      const t = when(i, total);
      const date = `${t.getFullYear()}-${pad(t.getMonth() + 1)}-${pad(t.getDate())}`;
      const time = `${pad(t.getHours())}:${pad(t.getMinutes())}:${pad(t.getSeconds())}`;
      const src = SOURCES[(i + k) % SOURCES.length].replace('10.20.', '10.40.');
      lines.push(
        `date=${date} time=${time} devname="FGT-100F-FILIAL" devid="FG100FTK22088190" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip=${src} srcport=${40000 + ((i * 37) % 20000)} srcintf="internal" dstip=${d.ip} dstport=443 dstintf="wan1" proto=6 action="accept" policyid=1 policyname="LAN-to-WAN-HTTPS" service="HTTPS" hostname="${d.host}" sentbyte=${900 + ((i * 131) % 4000)} rcvdbyte=${6000 + ((i * 977) % 90000)}${d.app ? ` app="${d.app}"` : ''}`
      );
      i += 1;
    }
  }
  return lines;
}
