import crypto from 'node:crypto';
import type {
  FirewallRule,
  NatPolicy,
  SyslogAction,
  SyslogEvent,
  SyslogSeverity,
} from './types.ts';

function parseFortiKvPairs(line: string): Record<string, string> {
  const result: Record<string, string> = {};
  const regex = /([a-zA-Z0-9_.\-]+)=("([^"]*)"|([^\s]*))/g;
  let match: RegExpExecArray | null = regex.exec(line);
  while (match !== null) {
    const key = match[1].toLowerCase();
    const val = match[3] !== undefined ? match[3] : match[4] || '';
    result[key] = val;
    match = regex.exec(line);
  }
  return result;
}

function mapFortiLevelToSeverity(levelRaw: string): { severity: SyslogSeverity; priority: number } {
  const l = levelRaw.toLowerCase();
  if (l === 'emergency' || l === 'emerg') return { severity: 'emergency', priority: 0 };
  if (l === 'alert') return { severity: 'alert', priority: 1 };
  if (l === 'critical' || l === 'crit') return { severity: 'critical', priority: 2 };
  if (l === 'error' || l === 'err') return { severity: 'error', priority: 3 };
  if (l === 'warning' || l === 'warn') return { severity: 'warning', priority: 4 };
  if (l === 'notice') return { severity: 'notice', priority: 5 };
  if (l === 'information' || l === 'info') return { severity: 'info', priority: 6 };
  if (l === 'debug') return { severity: 'debug', priority: 7 };
  return { severity: 'info', priority: 6 };
}

function mapIanaProto(protoRaw: string): string {
  const clean = protoRaw.trim().toLowerCase();
  if (clean === '6' || clean === 'tcp') return 'TCP';
  if (clean === '17' || clean === 'udp') return 'UDP';
  if (clean === '1' || clean === 'icmp') return 'ICMP';
  if (clean === '47') return 'GRE';
  if (clean === '50') return 'ESP';
  return clean ? clean.toUpperCase() : 'IP';
}

function inferFortiAction(kv: Record<string, string>): SyslogAction {
  const action = (kv.action || '').toLowerCase();
  const utmAction = (kv.utmaction || '').toLowerCase();
  const type = (kv.type || '').toLowerCase();
  const subtype = (kv.subtype || '').toLowerCase();

  if (type === 'utm' || subtype === 'ips' || subtype === 'virus') {
    if (action.includes('drop') || action.includes('block') || utmAction.includes('block')) {
      return 'drop';
    }
    if (action.includes('reset')) return 'reset';
    if (action.includes('deny')) return 'deny';
  }

  if (action === 'deny' || action === 'policy_violation') return 'deny';
  if (action === 'drop' || action === 'dropped' || action === 'blocked' || action === 'block') {
    return 'drop';
  }
  if (action === 'server-rst' || action === 'client-rst' || action === 'reset') return 'reset';
  if (action === 'accept' || action === 'close' || action === 'start' || action === 'timeout') {
    return 'allow';
  }
  if (type === 'event') return 'system';
  if (kv.transip) return 'nat';
  return 'allow';
}

function toIntOrNull(val: string | undefined): number | null {
  if (!val) return null;
  const n = Number(val);
  return Number.isFinite(n) && n > 0 ? Math.trunc(n) : null;
}

export function parseFortiGateSyslog(
  rawText: string,
  source: SyslogEvent['source']
): SyslogEvent[] {
  const lines = rawText
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean);

  const events: SyslogEvent[] = [];
  const ingestedAt = new Date().toISOString();

  for (const line of lines) {
    const kv = parseFortiKvPairs(line);
    if (!kv.devid && !kv.devname && !kv.srcip && !kv.type && !kv.logid) {
      continue;
    }

    const { severity, priority } = mapFortiLevelToSeverity(kv.level || 'notice');
    const action = inferFortiAction(kv);
    const type = (kv.type || 'traffic').toLowerCase();
    const subtype = (kv.subtype || 'forward').toLowerCase();

    let categoryCode = '1024';
    let categoryName = 'Tráfego FortiGate';
    if (subtype === 'ips' || kv.attack) {
      categoryCode = '512';
      categoryName = 'IPS / Detecção de Intrusão';
    } else if (subtype === 'virus' || kv.virus) {
      categoryCode = '2048';
      categoryName = 'FortiGuard AntiVirus';
    } else if (type === 'event') {
      categoryCode = '256';
      categoryName = `Evento (${subtype})`;
    }

    const datePart = kv.date || new Date().toISOString().slice(0, 10);
    const timePart = kv.time || new Date().toISOString().slice(11, 19);
    const timestamp = `${datePart} ${timePart}`;

    const protoLabel = mapIanaProto(kv.proto || '');
    const serviceLabel = kv.service ? `${protoLabel}/${kv.service}` : protoLabel;

    const attackMsg = kv.attack ? `IPS: ${kv.attack}` : '';
    const virusMsg = kv.virus ? `AV: ${kv.virus}` : '';
    const msg =
      kv.msg ||
      attackMsg ||
      virusMsg ||
      `FortiOS ${type}/${subtype} (${kv.action || 'allow'})${kv.policyname ? ` · Policy ${kv.policyname}` : ''}`;

    const ruleRef =
      kv.policyname ||
      (kv.policyid && kv.policyid !== '0' ? `Policy-${kv.policyid}` : null);

    events.push({
      id: crypto.randomUUID(),
      timestamp,
      firewallHost: kv.devname || kv.devid || 'FortiGate',
      serialNumber: kv.devid || '-',
      priority,
      severity,
      categoryCode,
      categoryName,
      messageId: kv.logid || '-',
      action,
      srcIp: kv.srcip || '-',
      srcPort: toIntOrNull(kv.srcport),
      srcZone: kv.srcintf || '-',
      dstIp: kv.dstip || '-',
      dstPort: toIntOrNull(kv.dstport),
      dstZone: kv.dstintf || '-',
      natSrcIp: kv.transip || null,
      natSrcPort: toIntOrNull(kv.transport),
      natDstIp: kv.trandisp === 'dnat' ? kv.transip || null : null,
      natDstPort: kv.trandisp === 'dnat' ? toIntOrNull(kv.transport) : null,
      protocol: serviceLabel,
      ruleRef,
      natRuleRef: kv.transip ? `NAT-${kv.policyid || 'VIP'}` : null,
      bytesSent: Number(kv.sentbyte || 0) || 0,
      bytesRcvd: Number(kv.rcvdbyte || 0) || 0,
      appName: kv.app || kv.service || null,
      user: kv.user || null,
      message: msg,
      raw: line,
      source,
      ingestedAt,
    });
  }

  return events;
}

export function generateFortiOsCli(
  rules: FirewallRule[],
  nats: NatPolicy[],
  mode: 'disable' | 'delete'
): string {
  const lines: string[] = [
    `# Script FortiOS CLI gerado por FW Audit em ${new Date().toISOString()}`,
    `# Modo: ${mode === 'disable' ? 'DESABILITAÇÃO SEGURA (recomendado para quarentena)' : 'REMOÇÃO DEFINITIVA'}`,
    `# Execute via SSH no FortiGate (ou revise no FortiManager antes do commit).`,
    ``,
  ];

  const numericPolicies = rules.filter((r) => !r.id.startsWith('FG-'));
  const policyList = numericPolicies.length > 0 ? rules : rules;

  if (policyList.length > 0) {
    lines.push(`config firewall policy`);
    for (const r of policyList) {
      const policyId = r.id.replace(/^FG-POL-/i, '').replace(/[^0-9]/g, '') || r.id;
      lines.push(`    # ${r.name} (${r.fromZone} -> ${r.toZone}) | ${r.findingReason}`);
      if (mode === 'disable') {
        lines.push(`    edit ${policyId}`);
        lines.push(`        set status disable`);
        lines.push(`        set comments "Quarentena FW Audit (${new Date().toISOString().slice(0, 10)})"`);
        lines.push(`    next`);
      } else {
        lines.push(`    delete ${policyId}`);
      }
    }
    lines.push(`end`);
    lines.push(``);
  }

  if (nats.length > 0) {
    lines.push(`# Objetos VIP / IP Pool / Central SNAT identificados sem uso`);
    const vips = nats.filter((n) => n.id.startsWith('VIP-'));
    const pools = nats.filter((n) => n.id.startsWith('POOL-'));
    const snats = nats.filter((n) => !n.id.startsWith('VIP-') && !n.id.startsWith('POOL-'));

    if (vips.length > 0) {
      lines.push(`config firewall vip`);
      for (const n of vips) {
        lines.push(`    # ${n.name} (${n.origDestination} -> ${n.transDestination}) | ${n.findingReason}`);
        if (mode === 'delete') {
          lines.push(`    delete "${n.name}"`);
        } else {
          lines.push(`    edit "${n.name}"`);
          lines.push(`        set comment "Revisar quarentena FW Audit (${new Date().toISOString().slice(0, 10)})"`);
          lines.push(`    next`);
        }
      }
      lines.push(`end`);
      lines.push(``);
    }

    if (pools.length > 0) {
      lines.push(`config firewall ippool`);
      for (const n of pools) {
        lines.push(`    # ${n.name} (${n.transSource}) | ${n.findingReason}`);
        if (mode === 'delete') {
          lines.push(`    delete "${n.name}"`);
        } else {
          lines.push(`    edit "${n.name}"`);
          lines.push(`        set comments "Revisar quarentena FW Audit (${new Date().toISOString().slice(0, 10)})"`);
          lines.push(`    next`);
        }
      }
      lines.push(`end`);
      lines.push(``);
    }

    if (snats.length > 0) {
      lines.push(`config firewall central-snat-map`);
      for (const n of snats) {
        const snatId = n.id.replace(/^SNAT-/i, '') || n.id;
        lines.push(`    # ${n.name} | ${n.findingReason}`);
        if (mode === 'disable') {
          lines.push(`    edit ${snatId}`);
          lines.push(`        set status disable`);
          lines.push(`    next`);
        } else {
          lines.push(`    delete ${snatId}`);
        }
      }
      lines.push(`end`);
    }
  }

  return lines.join('\n');
}
