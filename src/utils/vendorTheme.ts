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
    chartGrid: '#CAD9EE',
    chartAxis: '#486581',
    chartPrimary: '#1D4E89',
    chartAllow: '#2B6CB0',
    chartBlocked: '#DC2626',
    pdfHeaderRgb: [233, 240, 250],
    pdfBorderRgb: [202, 217, 238],
    pdfHeadingRgb: [16, 42, 67],
    pdfAccentRgb: [29, 78, 137],
    pdfMutedRgb: [72, 101, 129],
    pdfAltRowRgb: [243, 247, 252],
    pdfTerminalRgb: [15, 30, 51],
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
