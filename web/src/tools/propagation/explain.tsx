// Why a resolver is not up to date, what to do, the command to check it yourself, the sources.
// Written for this name, type and resolver.
import { CodeBlock } from '../../components/ui';
import { t } from '../../lib/i18n';
import { fmtClock, fmtIn, fmtTtl } from '../dns/fmt';
import { cleanProvider, displayName, type AuthorityEvent, type ResolverEvent } from './model';

export const SRC = {
  ttl: 'https://www.rfc-editor.org/rfc/rfc1035#section-3.2.1',
  negative: 'https://www.rfc-editor.org/rfc/rfc2308',
  ecs: 'https://www.rfc-editor.org/rfc/rfc7871',
  notify: 'https://www.rfc-editor.org/rfc/rfc1996',
  serial: 'https://www.rfc-editor.org/rfc/rfc1982',
  googleFlush: 'https://developers.google.com/speed/public-dns/cache',
  cloudflarePurge: 'https://one.one.one.one/purge-cache/',
};

export function Sources({ links }: { links: [string, string][] }) {
  return (
    <p className="issue__refs">
      {t('Sources :')}{' '}
      {links.map(([label, href], i) => (
        <span key={href}>
          <a href={href} target="_blank" rel="noreferrer noopener">
            {label}
          </a>
          {i < links.length - 1 ? ', ' : ''}
        </span>
      ))}
    </p>
  );
}

function Steps({ items }: { items: string[] }) {
  if (!items.length) return null;
  return (
    <ol className="issue__steps">
      {items.map((x, i) => (
        <li key={i}>{x}</li>
      ))}
    </ol>
  );
}

const digCmd = (server: string, name: string, type: string, extra = '') => `dig @${server} ${name} ${type}${extra}`;

/** One line, shown under the value of a resolver that is not plainly up to date. */
export function shortReason(e: ResolverEvent, authority: AuthorityEvent | undefined, sameAsUpToDate = false): string | null {
  const ref = authority?.reference;
  const wait = e.refreshAt ? Math.max(0, (new Date(e.refreshAt).getTime() - Date.now()) / 1000) : null;
  const timing = { time: e.refreshAt ? fmtClock(e.refreshAt) : '', in: e.refreshAt ? fmtIn(e.refreshAt) : '' };
  switch (e.status) {
    case 'fresh':
      return e.geo?.explained ? t('Valeur que les autoritaires donnent à son réseau (ECS) : à jour.') : null;
    case 'regional': {
      const op = e.regionalAsn ? `AS${e.regionalAsn.asn}${e.regionalAsn.name ? ` ${cleanProvider(e.regionalAsn.name)}` : ''}` : t('même opérateur');
      return t('Même opérateur que les autoritaires ({op}) : réponse adaptée à la région, pas un retard.', { op });
    }
    case 'stale':
      if (sameAsUpToDate && ref?.ttl != null && e.ttl != null && e.ttl > ref.ttl)
        return t('Même valeur que des résolveurs à jour, mais TTL plus long que celui de la zone ({ttl} contre {zoneTtl}) : cache qui ne respecte pas le TTL.', { ttl: fmtTtl(e.ttl), zoneTtl: fmtTtl(ref.ttl) });
      if (sameAsUpToDate) return t('Même valeur que des résolveurs à jour : servie à d’autres réseaux, non confirmée pour celui-ci.');
      if (e.uncertain) return t('Zone en rotation ou par lieu : valeur peut-être légitime, non confirmée (ECS).');
      return wait === null ? t('Ancienne valeur en cache.') : wait > 0 ? t('Ancienne valeur en cache, mise à jour vers {time} ({in}).', timing) : t('Ancienne valeur en cache, TTL expiré : relancez.');
    case 'missing':
      return wait === null ? t('Absence du nom en cache (cache négatif).') : wait > 0 ? t('Absence du nom en cache (cache négatif), mise à jour vers {time} ({in}).', timing) : t('Absence du nom en cache (cache négatif), TTL expiré : relancez.');
    case 'rewritten':
      return t('Réécrit ou bloque la réponse : non compté, sera écarté de la liste.');
    case 'error':
      return e.dnssec ? t('{code} : il valide DNSSEC, vérifiez les signatures de la zone. Non compté.', { code: e.rcode ?? t('Erreur') }) : t('{code} : il n’a pas pu joindre les autoritaires. Non compté.', { code: e.rcode ?? t('Erreur') });
    case 'timeout':
      return t('Pas de réponse en 4 s. Non compté dans le pourcentage.');
  }
}

/** The late resolvers (stale or missing, not uncertain): why, what to do, how to check, sources. */
export function LateIssue({ late, name, type, authority }: { late: ResolverEvent[]; name: string; type: string; authority?: AuthorityEvent }) {
  if (!late.length) return null;
  const ns = authority?.servers.find((s) => !s.error);
  const missing = late.filter((e) => e.status === 'missing').length;
  const last = late.map((e) => e.refreshAt).filter((x): x is string => !!x).sort().at(-1) ?? null;
  const google = late.some((e) => e.provider?.toLowerCase().includes('google'));
  const cloudflare = late.some((e) => e.provider?.toLowerCase().includes('cloudflare'));
  const ttl = authority?.reference.ttl ?? null;
  const steps = [
    last ? t('Attendez : le dernier cache expire vers {time} ({in}). Rien à corriger dans la zone.', { time: fmtClock(last), in: fmtIn(last) }) : t('Attendez l’expiration de leurs caches : rien à corriger dans la zone.'),
    ttl !== null
      ? t('Avant un prochain changement, baissez le TTL (aujourd’hui {ttl}) à 5 min au moins un TTL complet à l’avance.', { ttl: fmtTtl(ttl) })
      : t('Avant un prochain changement, baissez le TTL à 5 min au moins un TTL complet à l’avance.'),
    ...(missing ? [t('Un nom demandé avant d’exister reste caché absent le temps du minimum du SOA : créez l’enregistrement avant de l’annoncer.')] : []),
    ...(google ? [t('Google Public DNS : videz son cache pour ce nom avec le formulaire officiel.')] : []),
    ...(cloudflare ? [t('Cloudflare 1.1.1.1 : videz son cache pour ce nom avec le formulaire officiel.')] : []),
  ];
  const links: [string, string][] = [[t('RFC 1035 §3.2.1 (TTL)'), SRC.ttl]];
  if (missing) links.push([t('RFC 2308 (cache négatif)'), SRC.negative]);
  if (google) links.push([t('Google, vider le cache'), SRC.googleFlush]);
  if (cloudflare) links.push([t('Cloudflare, vider le cache'), SRC.cloudflarePurge]);
  const cmds = [...late.slice(0, 3).map((e) => digCmd(e.ip, name, type, ' +noall +answer')), ns ? digCmd(ns.ns, name, type, ' +norecurse +noall +answer') : null].filter(Boolean).join('\n');
  return (
    <article className="issue issue--out" id="issue-late">
      <h3 className="issue__title">
        {late.length > 1 ? t('{n} résolveurs servent encore une ancienne réponse', { n: late.length }) : t('{name} sert encore une ancienne réponse', { name: displayName(late[0]) })}
      </h3>
      <p className="issue__why">
        {missing === late.length
          ? t('Ils gardent en cache l’absence du nom jusqu’à l’expiration de son TTL, puis redemanderont aux autoritaires. La zone est à jour, la propagation suit son cours.')
          : t('Ils gardent en cache l’ancienne valeur jusqu’à l’expiration de son TTL, puis redemanderont aux autoritaires. La zone est à jour, la propagation suit son cours.')}
      </p>
      <ol className="issue__steps">
        {steps.map((x, i) => (
          <li key={i}>{x}</li>
        ))}
      </ol>
      <CodeBlock code={cmds} label={t('Vérifier vous-même')} />
      <Sources links={links} />
    </article>
  );
}

/** Divergent authoritative servers: what it means and how to align them. */
export function DivergenceDetail({ a, name, type }: { a: AuthorityEvent; name: string; type: string }) {
  const ok = a.servers.filter((s) => !s.error);
  const cmds = [...new Set(ok.map((s) => s.ns))].flatMap((ns) => [digCmd(ns, name, type, ' +norecurse +short'), digCmd(ns, a.zone, 'SOA', ' +norecurse +short')]);
  const d = a.divergence;
  let why: string;
  let steps: string[];
  if (d.dynamic) {
    why = t('Même serial partout, réponses différentes : la zone répond selon le lieu, le poids ou en rotation (CDN, GSLB, round robin). Toute valeur servie par un autoritaire compte comme à jour ; une autre valeur est marquée « incertaine ».');
    steps = [t('Rien à corriger si ce comportement est voulu.')];
  } else if (d.sameAnswerDifferentSerials) {
    why = t('Même réponse partout, serials différents : deux fournisseurs DNS numérotent la zone chacun à sa façon, ou la zone est mise à jour en continu (cas des TLD). Sans effet sur la propagation de ce nom.');
    steps = [t('Rien à corriger pour ce nom. Si un seul fournisseur héberge la zone, vérifiez que tous ses serveurs reçoivent les mises à jour (NOTIFY, transfert IXFR).')];
  } else {
    why = t('Les autoritaires ne servent pas la même version de la zone : selon le serveur qu’il interroge, un résolveur obtient l’ancienne ou la nouvelle valeur. La référence retenue est celle du serial le plus récent ({serial}).', { serial: a.serials[0] ?? '?' });
    steps = [
      t('Chez votre hébergeur DNS, vérifiez que la modification est publiée sur tous les serveurs de la zone (transfert de zone, NOTIFY).'),
      t('Avec deux fournisseurs (primaire et secondaire, ou multi-fournisseurs), publiez le changement chez chacun.'),
      t('Relancez la mesure : la référence suit le serial le plus récent.'),
    ];
  }
  return (
    <article className={`issue ${d.dynamic || d.sameAnswerDifferentSerials ? 'issue--info' : 'issue--out'}`} id="issue-divergence">
      <h3 className="issue__title">{d.dynamic ? t('La zone répond selon le lieu ou en rotation') : d.sameAnswerDifferentSerials ? t('Même réponse, serials différents') : t('Les serveurs autoritaires ne sont pas d’accord')}</h3>
      <p className="issue__why">{why}</p>
      <Steps items={steps} />
      <CodeBlock code={cmds.join('\n')} label={t('Interroger chaque serveur')} />
      <Sources links={[[t('RFC 1996 (NOTIFY)'), SRC.notify], [t('RFC 1982 (serial)'), SRC.serial]]} />
    </article>
  );
}

/** Expected value not yet served by the authoritative servers. */
export function ExpectedDetail({ a, name, type }: { a: AuthorityEvent; name: string; type: string }) {
  const nss = [...new Set(a.servers.map((s) => s.ns))];
  return (
    <article className="issue issue--out" id="issue-expected">
      <h3 className="issue__title">{t('Les autoritaires ne publient pas encore la valeur attendue')}</h3>
      <p className="issue__why">
        {t('Les serveurs autoritaires ne publient pas encore la valeur attendue : aucun résolveur ne peut la voir tant que la zone n’est pas modifiée. Les résolveurs sont comparés à la valeur attendue, pas à celle des autoritaires.')}
      </p>
      <Steps
        items={[
          t('Modifiez la zone chez le fournisseur qui détient la délégation de {zone} : {servers}. Une modification faite ailleurs (ancien hébergeur, registrar) n’est jamais servie.', { zone: a.zone, servers: nss.join(', ') }),
          t('Vérifiez l’orthographe de la valeur attendue (point final, guillemets des TXT).'),
        ]}
      />
      <CodeBlock code={nss.slice(0, 2).map((ns) => digCmd(ns, name, type, ' +norecurse +short')).join('\n')} label={t('Ce que servent les autoritaires')} />
    </article>
  );
}
