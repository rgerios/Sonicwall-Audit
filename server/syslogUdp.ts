import dgram from 'node:dgram';
import { parseSonicWallSyslog } from './parsers.ts';
import type { SyslogEvent, UdpListenerStatus } from './types.ts';

export class SyslogUdpReceiver {
  private socket: dgram.Socket | null = null;
  private status: UdpListenerStatus = {
    running: false,
    port: 5514,
    bindAddress: '0.0.0.0',
    packetsReceived: 0,
    lastPacketAt: null,
    lastError: null,
  };
  private onEventsCallback: (events: SyslogEvent[]) => void;

  constructor(onEvents: (events: SyslogEvent[]) => void) {
    this.onEventsCallback = onEvents;
  }

  getStatus(): UdpListenerStatus {
    return { ...this.status };
  }

  async start(port = 5514, bindAddress = '0.0.0.0'): Promise<UdpListenerStatus> {
    if (this.socket) {
      await this.stop();
    }

    return new Promise((resolve, reject) => {
      const sock = dgram.createSocket('udp4');

      sock.on('error', (err) => {
        this.status.lastError = err.message;
        if (!this.status.running) {
          sock.close();
          reject(err);
        }
      });

      sock.on('message', (msg) => {
        const text = msg.toString('utf8');
        const parsed = parseSonicWallSyslog(text, 'udp');
        if (parsed.length > 0) {
          this.status.packetsReceived += parsed.length;
          this.status.lastPacketAt = new Date().toISOString();
          this.onEventsCallback(parsed);
        }
      });

      sock.bind(port, bindAddress, () => {
        this.socket = sock;
        this.status = {
          running: true,
          port,
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
    const now = new Date().toISOString().replace('T', ' ').slice(0, 19);
    const sampleLine = `<134>id=firewall sn=2CB8ED549A10 time="${now}" fw=192.168.1.1 pri=6 c=1024 m=537 msg="Connection Closed" n=14820 src=10.20.4.45:51422:X0 dst=172.16.50.10:443:X1 proto=tcp/https sent=2480 rcvd=9420 fw_action="allow" rule="R-01"`;
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
