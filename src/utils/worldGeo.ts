import { feature } from 'topojson-client';
import { geoCentroid, geoNaturalEarth1, geoPath } from 'd3-geo';
import type { Topology } from 'topojson-specification';
import type { Feature, FeatureCollection, Geometry } from 'geojson';
import isoCountries from 'i18n-iso-countries';
import pt from 'i18n-iso-countries/langs/pt.json';
import world from 'world-atlas/countries-110m.json';

isoCountries.registerLocale(pt);

export const MAP_W = 960;
export const MAP_H = 480;

export interface WorldCountry {
  code: string;
  name: string;
  d: string;
  centroid: [number, number];
}

interface WorldGeo {
  countries: WorldCountry[];
  byCode: Map<string, WorldCountry>;
  sphere: string;
  project: (lon: number, lat: number) => [number, number];
}

// geoCentroid erra em países com territórios distantes: posição usada para marcar o "centro" visual
const CENTROID_OVERRIDES: Record<string, [number, number]> = {
  FR: [2.5, 46.6],
  US: [-98.5, 39.5],
  NO: [9.5, 61.5],
  NL: [5.3, 52.2],
  RU: [90, 60],
  CA: [-100, 58],
  CL: [-71, -33],
  ES: [-3.7, 40.2],
  PT: [-8, 39.6],
};

let cache: WorldGeo | null = null;

export function getWorldGeo(): WorldGeo {
  if (cache) return cache;
  const projection = geoNaturalEarth1().fitSize([MAP_W, MAP_H], { type: 'Sphere' });
  const path = geoPath(projection);
  const topo = world as unknown as Topology;
  const fc = feature(topo, topo.objects.countries) as unknown as FeatureCollection<Geometry>;
  const countries: WorldCountry[] = [];
  for (const f of fc.features as Array<Feature<Geometry>>) {
    const numeric = String(f.id ?? '').padStart(3, '0');
    const code = isoCountries.numericToAlpha2(numeric);
    const d = path(f);
    if (!code || !d) continue;
    countries.push({
      code,
      name: isoCountries.getName(code, 'pt') || code,
      d,
      centroid: CENTROID_OVERRIDES[code] ?? (geoCentroid(f) as [number, number]),
    });
  }
  cache = {
    countries,
    byCode: new Map(countries.map((c) => [c.code, c])),
    sphere: path({ type: 'Sphere' }) ?? '',
    project: (lon, lat) => (projection([lon, lat]) ?? [0, 0]) as [number, number],
  };
  return cache;
}

/** Nome do país em português (cai no código se desconhecido). */
export function countryName(code: string): string {
  return isoCountries.getName(code, 'pt') || code;
}

/** Lista de países (código e nome) para o seletor. */
export function allCountries(): Array<{ code: string; name: string }> {
  return Object.entries(isoCountries.getNames('pt', { select: 'official' }))
    .map(([code, name]) => ({ code, name }))
    .sort((a, b) => a.name.localeCompare(b.name, 'pt-BR'));
}

/** Bandeira em emoji a partir do código ISO de 2 letras. */
export function flagEmoji(code: string): string {
  if (!/^[A-Z]{2}$/.test(code)) return '';
  return String.fromCodePoint(...[...code].map((c) => 0x1f1e6 + c.charCodeAt(0) - 65));
}
