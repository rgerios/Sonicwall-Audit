import type { FirewallVendor } from '../types.ts';

export function getVendorApiBase(vendor: FirewallVendor): string {
  return vendor === 'fortigate' ? '/api/fortigate' : '/api/sonicwall';
}

export function vendorApiUrl(vendor: FirewallVendor, path: string): string {
  const clean = path.startsWith('/') ? path : `/${path}`;
  return `${getVendorApiBase(vendor)}${clean}`;
}
