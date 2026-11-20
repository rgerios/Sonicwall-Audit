import type { FirewallVendor } from '../types.ts';

export interface VendorThemeTokens {
  vendor: FirewallVendor;
  label: string;
  platformSubtitle: string;
  sampleButtonLabel: string;
  cliName: string;
  defaultUdpPort: number;
  chartGrid: string;
  chartAxis: string;
  chartPrimary: string;
  chartAllow: string;
  chartBlocked: string;
  pdfHeaderRgb: [number, number, number];
  pdfBorderRgb: [number, number, number];
  pdfHeadingRgb: [number, number, number];
  pdfAccentRgb: [number, number, number];
  pdfMutedRgb: [number, number, number];
  pdfAltRowRgb: [number, number, number];
  pdfTerminalRgb: [number, number, number];
}

export const VENDOR_THEMES: Record<FirewallVendor, VendorThemeTokens> = {
  sonicwall: {
    vendor: 'sonicwall',
    label: 'SonicWall',
    platformSubtitle: 'SonicOS 6.5 / 7',
    sampleButtonLabel: 'Carregar Amostra TZ470',
    cliName: 'SonicOS CLI',
    defaultUdpPort: 5514,
    chartGrid: '#DAD5D0',
    chartAxis: '#556363',
    chartPrimary: '#0075DB',
    chartAllow: '#0075DB',
    chartBlocked: '#DC2626',
    pdfHeaderRgb: [239, 237, 235],
    pdfBorderRgb: [218, 213, 208],
    pdfHeadingRgb: [31, 41, 41],
    pdfAccentRgb: [31, 41, 41],
    pdfMutedRgb: [85, 99, 99],
    pdfAltRowRgb: [248, 246, 244],
    pdfTerminalRgb: [19, 27, 27],
  },
  fortigate: {
    vendor: 'fortigate',
    label: 'FortiGate',
    platformSubtitle: 'FortiOS 7.x',
    sampleButtonLabel: 'Carregar Amostra FortiGate 100F',
    cliName: 'FortiOS CLI',
    defaultUdpPort: 5515,
    chartGrid: '#DDDCDC',
    chartAxis: '#5F5F5F',
    chartPrimary: '#1F4456',
    chartAllow: '#1C8388',
    chartBlocked: '#DA291C',
    pdfHeaderRgb: [237, 236, 236],
    pdfBorderRgb: [221, 220, 220],
    pdfHeadingRgb: [17, 17, 17],
    pdfAccentRgb: [218, 41, 28],
    pdfMutedRgb: [95, 95, 95],
    pdfAltRowRgb: [247, 246, 246],
    pdfTerminalRgb: [26, 26, 26],
  },
};
