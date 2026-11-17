import dgram from 'node:dgram';
import { parseFortiGateSyslog } from './fortigateParsers.ts';
import { parseSonicWallSyslog } from './parsers.ts';
import type { FirewallVendor, SyslogEvent, UdpListenerStatus } from './types.ts';

export class SyslogUdpReceiver {
  private socket: dgram.Socket | null = null;
  private vendor: FirewallVendor;
  private status: UdpListenerStatus;
  private onEventsCallback: (events: SyslogEvent[], remoteAddress: string) => void;

  constructor(
    onEvents: (events: SyslogEvent[], remoteAddress: string) => void,
    vendor: FirewallVendor = 'sonicwall'
  ) {
    this.onEventsCallback = onEvents;
    this.vendor = vendor;
    this.status = {
      running: false,
      port: vendor === 'fortigate' ? 5515 : 5514,
      bindAddress: '0.0.0.0',
      packetsReceived: 0,
      lastPacketAt: null,
      lastError: null,
    };
  }

  getStatus(): UdpListenerStatus {
    return { ...this.status };
  }

  async start(port?: number, bindAddress = '0.0.0.0'): Promise<UdpListenerStatus> {
    const resolvedPort = port ?? (this.vendor === 'fortigate' ? 5515 : 5514);
    if (this.socket) {
      await this.stop();
    }

    return new Promise((resolve, reject) => {
      // Buffer de recepção maior para absorver rajadas sem perda no kernel
      const sock = dgram.createSocket({ type: 'udp4', recvBufferSize: 8 * 1024 * 1024 });

      sock.on('error', (err) => {
        this.status.lastError = err.message;
        if (!this.status.running) {
          sock.close();
          reject(err);
        }
      });

      sock.on('message', (msg, rinfo) => {
        const text = msg.toString('utf8');
        const parsed =
          this.vendor === 'fortigate'
            ? parseFortiGateSyslog(text, 'udp')
            : parseSonicWallSyslog(text, 'udp');
        if (parsed.length > 0) {
          this.status.packetsReceived += parsed.length;
          this.status.lastPacketAt = new Date().toISOString();
          this.onEventsCallback(parsed, rinfo.address);
        }
      });

      sock.bind(resolvedPort, bindAddress, () => {
        this.socket = sock;
        this.status = {
          running: true,
          port: resolvedPort,
          bindAddress,
          packetsReceived: this.status.packetsReceived,
          lastPacketAt: this.status.lastPacketAt,
          lastError: null,
        };
        resolve(this.getStatus());
      });
    });
  }

  async stop(): Promise<UdpListenerStatus> {
    if (!this.socket) {
      this.status.running = false;
      return this.getStatus();
    }

    return new Promise((resolve) => {
      const sock = this.socket;
      this.socket = null;
      if (!sock) {
        this.status.running = false;
        resolve(this.getStatus());
        return;
      }
      sock.close(() => {
        this.status.running = false;
        resolve(this.getStatus());
      });
    });
  }

  async sendTestPacket(): Promise<void> {
    if (!this.status.running) {
      throw new Error('Inicie o receptor UDP antes de enviar um pacote de teste.');
    }
    const client = dgram.createSocket('udp4');
    const now = new Date();
    const iso = now.toISOString();
    const datePart = iso.slice(0, 10);
    const timePart = iso.slice(11, 19);

    const sampleLine =
      this.vendor === 'fortigate'
        ? `date=${datePart} time=${timePart} devname="FGT-100F-FILIAL" devid="FG100FTK22088190" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip=10.40.10.22 srcport=52110 srcintf="internal" dstip=172.16.80.10 dstport=443 dstintf="wan1" proto=6 action="accept" policyid=1 policyname="LAN-to-WAN-HTTPS" service="HTTPS" sentbyte=3200 rcvdbyte=18400`
        : `<134>id=firewall sn=2CB8ED549A10 time="${datePart} ${timePart}" fw=192.168.1.1 pri=6 c=1024 m=537 msg="Connection Closed" n=14820 src=10.20.4.45:51422:X0 dst=172.16.50.10:443:X1 proto=tcp/https sent=2480 rcvd=9420 fw_action="allow" rule="R-01"`;
    const buf = Buffer.from(sampleLine, 'utf8');

    return new Promise((resolve, reject) => {
      client.send(buf, this.status.port, '127.0.0.1', (err) => {
        client.close();
        if (err) reject(err);
        else resolve();
      });
    });
  }
}
