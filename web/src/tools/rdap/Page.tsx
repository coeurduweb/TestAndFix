// Whois et RDAP. /whois/:domain (one domain: registry and registrar side by side), /whois?liste=a,b
// (a list: a table filled as answers come, exportable). The former /rdap routes lead here.
import { Navigate, useLocation, useParams, useSearchParams } from 'react-router';
import { Notice } from '../../components/ui';
import { toDomain } from '../../lib/detect';
import { t } from '../../lib/i18n';
import { WhoisBatch } from './Batch';
import { WhoisHero } from './Hero';
import { BATCH_MAX, parseList } from './model';
import { WhoisSingle } from './Single';
import './whois.css';

export default function WhoisPage() {
  const { domain: raw } = useParams();
  const [params] = useSearchParams();
  const location = useLocation();
  if (location.pathname === '/rdap' || location.pathname.startsWith('/rdap/'))
    return <Navigate replace to={location.pathname.replace(/^\/rdap/, '/whois') + location.search} />;

  if (raw) {
    const d = toDomain(raw);
    if (d) return <WhoisSingle key={d} domain={d} />;
    return (
      <WhoisHero>
        <Notice tone="error" title={t('« {value} » n’est pas un nom de domaine', { value: raw.length > 60 ? raw.slice(0, 57) + '…' : raw })}>
          {t('Saisissez un nom comme exemple.fr, ou collez une liste de domaines.')}
        </Notice>
      </WhoisHero>
    );
  }
  const liste = params.get('liste');
  if (liste !== null) {
    const p = parseList(liste.split(',').join('\n'));
    if (p.domains.length === 1 && !p.invalid.length) return <WhoisSingle key={p.domains[0]} domain={p.domains[0]} />;
    if (p.domains.length) {
      const kept = p.domains.slice(0, BATCH_MAX);
      return <WhoisBatch key={kept.join(',')} domains={kept} dropped={p.domains.slice(BATCH_MAX)} invalid={p.invalid} />;
    }
    return (
      <WhoisHero>
        <Notice tone="warn" title={t('Aucun nom de domaine dans la liste')}>
          {t('Collez un domaine par ligne (ou séparés par des virgules), {max} au plus.', { max: BATCH_MAX })}
        </Notice>
      </WhoisHero>
    );
  }
  return <WhoisHero />;
}
