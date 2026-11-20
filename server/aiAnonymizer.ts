/**
 * Anonimização reversível para consultas à IA externa.
 *
 * Substitui IPv4, MAC e e-mails por tokens estáveis (o mesmo valor sempre vira o mesmo token
 * dentro de uma consulta) antes de enviar ao provedor, e restaura os valores originais na
 * resposta. O modelo ainda consegue correlacionar ("IP-PRIV-001 falhou 40x contra IP-PUB-003"),
 * mas o endereçamento real da rede não sai do servidor.
 */
const IPV4 = /(?<![\d.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\d.]*\d)/g;
const MAC = /\b[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}\b/g;
const EMAIL = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;
const TOKEN = /\b(?:IP-PRIV|IP-PUB|MAC|MAIL)-\d{3,}\b/g;

function isPrivateIpv4(ip: string): boolean {
  const [a, b] = ip.split('.').map(Number);
  return a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254);
}

export interface Anonymizer {
  mask(text: string): string;
  unmask(text: string): string;
  /** Quantidade de valores distintos substituídos até agora. */
  size(): number;
}

export function createAnonymizer(): Anonymizer {
  const forward = new Map<string, string>();
  const reverse = new Map<string, string>();
  const counters = { 'IP-PRIV': 0, 'IP-PUB': 0, MAC: 0, MAIL: 0 };

  const tokenFor = (value: string, kind: keyof typeof counters): string => {
    const key = `${kind}:${value.toLowerCase()}`;
    const existing = forward.get(key);
    if (existing) return existing;
    counters[kind] += 1;
    const token = `${kind}-${String(counters[kind]).padStart(3, '0')}`;
    forward.set(key, token);
    reverse.set(token, value);
    return token;
  };

  return {
    mask(text: string): string {
      return text
        .replace(EMAIL, (m) => tokenFor(m, 'MAIL'))
        .replace(MAC, (m) => tokenFor(m, 'MAC'))
        .replace(IPV4, (m) => tokenFor(m, isPrivateIpv4(m) ? 'IP-PRIV' : 'IP-PUB'));
    },
    unmask(text: string): string {
      return text.replace(TOKEN, (t) => reverse.get(t) ?? t);
    },
    size: () => reverse.size,
  };
}
