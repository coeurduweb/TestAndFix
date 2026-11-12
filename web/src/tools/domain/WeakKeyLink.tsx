// A DKIM key under 2048 bits: where to change it (provider console) and the generator, prefilled.
import { Link } from 'react-router';
import { ArrowRight } from 'lucide-react';
import { providerName } from '../../components/Report';
import { t } from '../../lib/i18n';
import { suggestSelectors } from '../gen-dkim/keys';
import type { DkimKey } from './model';
import { keyProvider, readableProvider } from './rows';

export const isWeakKey = (k: DkimKey) => k.keyType === 'rsa' && k.bits !== undefined && k.bits < 2048;

export function WeakKeyLink({ k, domain }: { k: DkimKey; domain: string }) {
  if (!isWeakKey(k)) return null;
  const managed = k.cnameProvider ?? k.knownFor?.[0];
  const next = suggestSelectors()[0];
  return (
    <p className="field__hint">
      {managed && (
        <>
          {keyProvider(k, providerName)?.startsWith('CNAME')
            ? t('Clé déléguée : passez-la à 2048 bits dans la console de ce service. Si vous signez vous-même :')
            : t('Clé de {provider} : passez-la à 2048 bits dans la console de ce service. Si vous signez vous-même :', { provider: readableProvider(managed, providerName) })}{' '}
        </>
      )}
      <Link className="dm-more dm-more--inline" to={`/generateurs/dkim?domaine=${encodeURIComponent(domain)}&selecteur=${encodeURIComponent(next)}`}>
        {t('Générer une clé de 2048 bits sous le sélecteur {next}, pour remplacer {selector}', { next, selector: k.selector })}
        <ArrowRight aria-hidden />
      </Link>
    </p>
  );
}
