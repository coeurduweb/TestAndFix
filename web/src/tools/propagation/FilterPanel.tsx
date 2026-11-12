// The filters row of the propagation page (Signal, 2026-11-11; replaces the v2 side column and
// drawer: "on doit scroller pour filtrer, c'est inacceptable"). One line of chips under the tool
// bar, always in view:
//   Où: "Monde", one chip per continent with three flags and its number of resolvers, "Pays…"
//       (popover on the spot: countries and UN sub-regions);
//   Résolveurs: the representative selection or everybody;  Réseau: IPv4 and/or IPv6;
//   Statut: filters the list and the map (what the answers were).
// Where to measure goes to the URL (the parent navigates and measures again); the status filter
// does not ask again.
import { Globe2 } from 'lucide-react';
import { fmtCount } from '../dns/fmt';
import { t } from '../../lib/i18n';
import { CountryPicker } from './CountryPicker';
import type { FilterId } from './model';
import type { ContinentChip, PlaceOption } from './places';
import { Flag } from './ResolverList';
import { hasPlaces, type Family, type Selection } from './selection';

export interface StatusFilter {
  id: FilterId;
  label: string;
  n: number;
}

export function FilterBar({
  sel,
  onChange,
  chips,
  countries,
  regions,
  families,
  defaultCount,
  allCount,
  ipv6 = true,
  filters,
  filter,
  onFilter,
}: {
  sel: Selection;
  onChange: (s: Selection) => void;
  chips: ContinentChip[];
  countries: PlaceOption[];
  regions: PlaceOption[];
  families: { '4': number; '6': number };
  defaultCount: number;
  allCount: number;
  /** false when the server cannot reach IPv6 resolvers */
  ipv6?: boolean;
  filters: StatusFilter[];
  filter: FilterId;
  onFilter: (f: FilterId) => void;
}) {
  const places = hasPlaces(sel);
  const noPlaces = { ...sel, continents: [], regions: [], countries: [] };
  const contOn = (c: ContinentChip) => c.codes.every((x) => sel.continents.includes(x));
  const toggleCont = (c: ContinentChip) => {
    const on = contOn(c);
    const next = on ? sel.continents.filter((x) => !c.codes.includes(x)) : [...new Set([...sel.continents, ...c.codes])].sort();
    onChange({ ...sel, continents: next });
  };
  const picked = [...sel.countries.map((c) => `country:${c}`), ...sel.regions.map((r) => `region:${r}`)];
  const fam: { id: Family; label: string; n?: number }[] = [
    { id: 'any', label: t('IPv4 et IPv6') },
    { id: '4', label: 'IPv4', n: families['4'] },
    { id: '6', label: 'IPv6', n: families['6'] },
  ];
  return (
    <div className="pp-filters">
      <div className="pp-fgrp" role="group" aria-label={t('Où mesurer')}>
        <em aria-hidden>{t('Où')}</em>
        <button type="button" className="chip" aria-pressed={!places} onClick={() => onChange(noPlaces)} title={t('Aucun lieu imposé')}>
          <Globe2 aria-hidden />
          {t('Monde')} <small>{fmtCount(sel.all ? allCount : defaultCount)}</small>
        </button>
        {chips.map((c) => (
          <button key={c.id} type="button" className="chip" aria-pressed={contOn(c)} onClick={() => toggleCont(c)} title={t('Les résolveurs locaux de {name}', { name: c.name })}>
            <span className="flags" aria-hidden>
              {c.flags.map((cc) => (
                <Flag key={cc} cc={cc} />
              ))}
            </span>
            {c.name} <small>{fmtCount(c.count)}</small>
          </button>
        ))}
        <CountryPicker
          countries={countries}
          regions={regions}
          chips={chips}
          picked={picked}
          onApply={(keys) =>
            onChange({
              ...sel,
              countries: keys.filter((k) => k.startsWith('country:')).map((k) => k.slice(8)).sort(),
              regions: keys.filter((k) => k.startsWith('region:')).map((k) => k.slice(7)).sort(),
            })
          }
        />
      </div>
      <div className="pp-fgrp" role="group" aria-label={t('Résolveurs')}>
        <em aria-hidden>{t('Résolveurs')}</em>
        <button type="button" className="chip" aria-pressed={!places && !sel.all} onClick={() => onChange({ ...noPlaces, all: false })} title={t('Les grands résolveurs publics et quelques-uns par région du monde')}>
          {t('Essentiels')} <small>{fmtCount(defaultCount)}</small>
        </button>
        <button type="button" className="chip" aria-pressed={!places && sel.all} onClick={() => onChange({ ...noPlaces, all: true })} title={t('Tous les résolveurs qualifiés aujourd’hui')}>
          {t('Tous')} <small>{fmtCount(allCount)}</small>
        </button>
      </div>
      <div className="pp-fgrp" role="group" aria-label={t('Réseau')}>
        <em aria-hidden>{t('Réseau')}</em>
        {fam.map((f) => {
          const off = f.id !== 'any' && (f.n === 0 || (f.id === '6' && !ipv6));
          return (
            <button
              key={f.id}
              type="button"
              className="chip"
              aria-pressed={sel.family === f.id}
              onClick={() => onChange({ ...sel, family: f.id })}
              disabled={off}
              title={f.id === '6' && !ipv6 ? t('IPv6 non disponible depuis notre serveur') : f.id === '6' && f.n === 0 ? t('Aucun résolveur IPv6 qualifié pour l’instant') : undefined}
            >
              {f.label}
              {f.n !== undefined && <small>{fmtCount(f.n)}</small>}
            </button>
          );
        })}
      </div>
      <div className="pp-fgrp" role="group" aria-label={t('Filtrer par état')}>
        <em aria-hidden>{t('Statut')}</em>
        {filters.map((f) => (
          <button key={f.id} type="button" className="chip" aria-pressed={filter === f.id} onClick={() => onFilter(f.id)}>
            {f.id !== 'all' && <span className={`dot dot--${f.id === 'error' ? 'out' : f.id === 'fresh' || f.id === 'regional' ? 'ok' : 'warn'}`} aria-hidden />}
            {f.label} <small>{fmtCount(f.n)}</small>
          </button>
        ))}
      </div>
    </div>
  );
}
