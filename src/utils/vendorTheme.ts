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
    chartGrid: '#EACACA',
    chartAxis: '#7B4242',
    chartPrimary: '#9B2C2C',
    chartAllow: '#2563EB',
    chartBlocked: '#C53030',
    pdfHeaderRgb: [249, 234, 234],
    pdfBorderRgb: [234, 202, 202],
    pdfHeadingRgb: [69, 18, 18],
    pdfAccentRgb: [155, 44, 44],
    pdfMutedRgb: [123, 66, 66],
    pdfAltRowRgb: [252, 244, 244],
    pdfTerminalRgb: [38, 16, 16],
  },
};
