import type { FirewallVendor } from '../types.ts';

export function getVendorApiBase(vendor: FirewallVendor): string {
  return vendor === 'fortigate' ? '/api/fortigate' : '/api/sonicwall';
}

// O firewall selecionado é guardado por aba do navegador e enviado em cada requisição
// (?site=). Assim, duas abas ou dois usuários podem olhar firewalls diferentes sem que a
// seleção de um mude a tela do outro.
const selectedSiteIds: Partial<Record<FirewallVendor, string>> = {};

function storageKey(vendor: FirewallVendor): string {
  return `fwaudit_selected_site_${vendor}`;
}

export function getSelectedSiteId(vendor: FirewallVendor): string | null {
  const cached = selectedSiteIds[vendor];
  if (cached) return cached;
  try {
    const stored = sessionStorage.getItem(storageKey(vendor));
    if (stored) {
      selectedSiteIds[vendor] = stored;
      return stored;
    }
  } catch {
    // sessionStorage indisponível (modo privado restrito)
  }
  return null;
}

export function setSelectedSiteId(vendor: FirewallVendor, siteId: string | null): void {
  try {
    if (siteId) {
      selectedSiteIds[vendor] = siteId;
      sessionStorage.setItem(storageKey(vendor), siteId);
    } else {
      delete selectedSiteIds[vendor];
      sessionStorage.removeItem(storageKey(vendor));
    }
  } catch {
    // ignora falhas de armazenamento
  }
}

export function vendorApiUrl(vendor: FirewallVendor, path: string): string {
  const clean = path.startsWith('/') ? path : `/${path}`;
  const url = `${getVendorApiBase(vendor)}${clean}`;
  const siteId = getSelectedSiteId(vendor);
  if (!siteId) return url;
  return `${url}${url.includes('?') ? '&' : '?'}site=${encodeURIComponent(siteId)}`;
}
