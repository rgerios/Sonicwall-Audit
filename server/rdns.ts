import dns from 'node:dns';
import { ipScope } from '../shared/destinations.ts';

/**
 * Resolvedor de DNS reverso (PTR) com cache e fila, para rotular IPs de destino com FQDN.
 * Nunca bloqueia a resposta da API: consulta só IPs públicos, em segundo plano, com
 * concorrência e tempo limite pequenos. Desative com DESTINATIONS_RDNS=false.
 */
export interface ReverseResolver {
  enabled: boolean;
  /** string = FQDN; null = sem PTR (negativo); undefined = ainda não consultado. */
  lookupCached(ip: string): string | null | undefined;
  schedule(ips: string[]): void;
  stats(): { resolved: number; pending: number };
}

interface ResolverOptions {
  enabled?: boolean;
  ttlMs?: number;
  negativeTtlMs?: number;
  timeoutMs?: number;
  concurrency?: number;
  maxEntries?: number;
  reverse?: (ip: string) => Promise<string[]>;
}

export function createReverseResolver(options: ResolverOptions = {}): ReverseResolver {
  const enabled = options.enabled ?? process.env.DESTINATIONS_RDNS !== 'false';
  const ttl = options.ttlMs ?? 6 * 60 * 60 * 1000;
  const negativeTtl = options.negativeTtlMs ?? 30 * 60 * 1000;
  const timeoutMs = options.timeoutMs ?? 1500;
  const concurrency = options.concurrency ?? 6;
  const maxEntries = options.maxEntries ?? 5000;
  const reverse = options.reverse ?? ((ip: string) => dns.promises.reverse(ip));

  const cache = new Map<string, { host: string | null; expires: number }>();
  const queued = new Set<string>();
  const queue: string[] = [];
  let active = 0;

  const withTimeout = <T,>(promise: Promise<T>): Promise<T> =>
    Promise.race([
      promise,
      new Promise<T>((_, reject) => setTimeout(() => reject(new Error('timeout')), timeoutMs).unref?.()),
    ]);

  function store(ip: string, host: string | null) {
    if (cache.size >= maxEntries) {
      const oldest = cache.keys().next().value;
      if (oldest !== undefined) cache.delete(oldest);
    }
    cache.set(ip, { host, expires: Date.now() + (host ? ttl : negativeTtl) });
  }

  async function pump() {
    while (active < concurrency && queue.length > 0) {
      const ip = queue.shift()!;
      active += 1;
      void (async () => {
        try {
          const names = await withTimeout(reverse(ip));
          const first = names?.[0]?.toLowerCase().replace(/\.$/, '') ?? '';
          store(ip, first && first.includes('.') ? first : null);
        } catch {
          store(ip, null);
        } finally {
          queued.delete(ip);
          active -= 1;
          void pump();
        }
      })();
    }
  }

  return {
    enabled,
    lookupCached(ip) {
      const hit = cache.get(ip);
      if (!hit) return undefined;
      if (hit.expires < Date.now()) {
        cache.delete(ip);
        return undefined;
      }
      return hit.host;
    },
    schedule(ips) {
      if (!enabled) return;
      for (const ip of ips) {
        if (queued.has(ip) || ipScope(ip) !== 'public') continue;
        const hit = cache.get(ip);
        if (hit && hit.expires >= Date.now()) continue;
        queued.add(ip);
        queue.push(ip);
      }
      void pump();
    },
    stats() {
      let resolved = 0;
      for (const v of cache.values()) if (v.host) resolved += 1;
      return { resolved, pending: queued.size };
    },
  };
}

let shared: ReverseResolver | null = null;
export function getSharedResolver(): ReverseResolver {
  shared ??= createReverseResolver();
  return shared;
}
