// Réputation d'IP. /ip/:ip (one address, live), /ip/203.0.113.0%2F24 (a range, /24 to /32),
// /ip?liste=a,b,c (several addresses). The form takes one address, a range, or several lines.
import { Navigate, useParams, useSearchParams } from 'react-router';
import { isIp, toDomain } from '../../lib/detect';
import { DomainRep } from './Domain';
import { BatchIp } from './Batch';
import { InvalidInput, invalidReason, IpHero } from './Form';
import { cleanToken, isRange, parseInput } from './model';
import { SingleIp } from './Single';
import { t } from '../../lib/i18n';
import './ip.css';

export default function IpPage() {
  const { ip, prefix } = useParams();
  const [params] = useSearchParams();
  const liste = params.get('liste') ?? params.get('plage');
  const ignored = (params.get('ignorees') ?? '').split(',').filter(Boolean);

  if (ip) {
    // /ip/203.0.113.0%2F24 today; /ip/203.0.113.0/24 once the route /ip/:ip/:prefix exists
    const tok = cleanToken(prefix ? `${ip}/${prefix}` : ip);
    // a domain (an URL or an e-mail address give theirs): domain reputation, same screen (US-069)
    if (!prefix && !isIp(tok) && !isRange(tok)) {
      const dom = toDomain(ip);
      if (dom && dom !== ip) return <Navigate to={`/ip/${encodeURIComponent(dom)}`} replace />;
      if (dom) return <DomainRep key={dom} domain={dom} />;
    }
    const bad = invalidReason(tok);
    if (bad) return <InvalidInput key={tok} value={prefix ? `${ip}/${prefix}` : ip} reason={bad} />;
    if (isRange(tok)) return <BatchIp key={tok} items={[tok]} />;
    return <SingleIp key={tok} ip={tok} />;
  }
  if (liste) {
    const p = parseInput(liste);
    if (p.items.length === 1 && !isRange(p.items[0]) && !ignored.length) return <SingleIp key={p.items[0]} ip={p.items[0]} />;
    if (p.items.length) return <BatchIp key={p.items.join(',')} items={p.items} invalidInput={[...ignored, ...p.invalid]} />;
    return <InvalidInput value={liste.split(',').join('\n')} reason={invalidReason(cleanToken(p.invalid[0] ?? liste)) ?? t('Aucune adresse IP dans la liste.')} />;
  }
  return <IpHero />;
}
