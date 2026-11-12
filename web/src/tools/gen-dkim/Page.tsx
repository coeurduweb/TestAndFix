// DKIM generator: key pair made by WebCrypto in this browser, dated selector, TXT record ready to
// publish (split in 255-character strings), private key downloaded as PEM. Nothing is sent.
import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router';
import { Download, RefreshCw, ShieldCheck } from 'lucide-react';
import { useAuth } from '../../app/auth';
import { CodeBlock, Field, Notice, Skel } from '../../components/ui';
import { api } from '../../lib/api';
import { msg, rich, t, tn } from '../../lib/i18n';
import { pushRecent } from '../../lib/recent';
import type { CheckResult } from '../../lib/types';
import { errorMessage } from '../../lib/useCheck';
import { Block, Checks, DomainField, GenLayout, MobileDock, PrefillNote, RecordPanel, Segmented, useCopyShortcut, useParam, type PrefillState } from '../gen-spf/GenParts';
import { Details } from '../../components/Verdict';
import { splitTxt } from '../gen-spf/txt';
import { cleanSelector, dkimRecord, generateDkimKey, keyName, SELECTOR, suggestSelectors, type DkimKeyPair, type KeyKind } from './keys';

interface DkimData {
  keys: { selector: string; keyType: string; bits?: number; cnameProvider?: string; revoked: boolean }[];
}

const KINDS: KeyKind[] = ['rsa2048', 'rsa4096', 'ed25519'];
const KIND_HINT: Record<KeyKind, string> = {
  rsa2048: msg('Compris par tous les destinataires. La norme demande au moins 1024 bits et recommande 2048 (RFC 8301 §3.2).'),
  rsa4096: msg("Plus robuste, mais l'enregistrement fait 754 caractères en 3 chaînes : certaines interfaces DNS tronquent les TXT longs sans prévenir. Vérifiez après publication."),
  ed25519: msg('Clé courte (44 caractères), signature rapide (RFC 8463). Compatibilité encore partielle : voir ci-dessous.'),
};

export default function GenDkimPage() {
  const { authenticated, loading: authLoading } = useAuth();
  const [domain, setDomain] = useParam('domaine');
  const [selParam, setSelParam] = useParam('selecteur');
  const [kindParam, setKindParam] = useParam('cle');
  const suggestions = useMemo(() => suggestSelectors(), []);
  const selector = cleanSelector(selParam) || suggestions[0];
  const kind: KeyKind = KINDS.includes(kindParam as KeyKind) ? (kindParam as KeyKind) : 'rsa2048';
  const [selText, setSelText] = useState(selector);
  const [key, setKey] = useState<DkimKeyPair | null>(null);
  const [genError, setGenError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [prefill, setPrefill] = useState<PrefillState>({ kind: 'off' });
  const [existing, setExisting] = useState<DkimData['keys'] | null>(null);

  const generate = useCallback(async (k: KeyKind) => {
    setBusy(true);
    setGenError(null);
    try {
      setKey(await generateDkimKey(k));
    } catch (e) {
      setKey(null);
      setGenError(
        k === 'ed25519'
          ? t('Ce navigateur ne sait pas générer de clé Ed25519 (WebCrypto). Utilisez un Chrome, Firefox ou Safari récent, ou choisissez RSA 2048.')
          : t('Génération impossible : {message}', { message: (e as Error).message }),
      );
    } finally {
      setBusy(false);
    }
  }, []);

  useEffect(() => {
    void generate(kind);
  }, [kind, generate]);

  useEffect(() => setSelText(selector), [selector]);

  // Existing selectors of the domain (signed in only): avoid reusing a name that already signs.
  useEffect(() => {
    setExisting(null);
    if (!domain) return setPrefill({ kind: 'off' });
    pushRecent({ value: domain, path: `/generateurs/dkim?domaine=${domain}`, label: msg('Générateur DKIM') });
    if (authLoading) return;
    if (!authenticated) return setPrefill({ kind: 'anonymous' });
    let alive = true;
    setPrefill({ kind: 'loading' });
    api<CheckResult<DkimData>>(`/api/dkim/${encodeURIComponent(domain)}?selectors=${encodeURIComponent(selector)}&historique=0`)
      .then((r) => {
        if (!alive) return;
        setExisting(r.data.keys);
        setPrefill({ kind: 'done', at: r.measuredAt, what: r.data.keys.length ? tn(r.data.keys.length, '{n} clé publiée', '{n} clés publiées') : t('aucune clé trouvée') });
      })
      .catch((e) => alive && setPrefill({ kind: 'error', message: errorMessage(e) }));
    return () => {
      alive = false;
    };
    // the selector is only a hint for the discovery; changing it does not need a new lookup
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [domain, authenticated, authLoading]);

  const record = key ? dkimRecord(key.k, key.publicB64) : '';
  useCopyShortcut(record, t('Clé publique copiée'));
  const name = keyName(selector, domain || t('votre-domaine.fr'));
  const validSel = SELECTOR.test(selText.trim() ? cleanSelector(selText) : selector);
  const clash = existing?.find((k) => k.selector.toLowerCase() === selector);
  const fileName = `${selector}._domainkey.${domain || 'domaine'}.private.pem`;
  const href = useMemo(() => (key ? URL.createObjectURL(new Blob([key.privatePem], { type: 'application/x-pem-file' })) : ''), [key]);
  useEffect(() => () => {
    if (href) URL.revokeObjectURL(href);
  }, [href]);

  const commitSelector = (raw: string) => {
    const s = cleanSelector(raw);
    if (s && SELECTOR.test(s)) setSelParam(s === suggestions[0] ? null : s);
  };

  const weak = existing?.filter((k) => k.keyType !== 'ed25519' && (k.bits ?? 2048) < 2048) ?? [];
  const nParts = splitTxt(record).length;
  return (
    <GenLayout
      title={t('Générateur DKIM')}
      desc={t("Paire de clés créée dans ce navigateur, enregistrement TXT prêt à publier, clé privée à installer sur votre serveur d'envoi.")}
      aside={
        <>
      {genError && <Notice tone="error" title={t('Clé non générée')}>{genError}</Notice>}
      {!key && !genError && (
        <div className="gen-hero surface" aria-busy="true" aria-label={t('Génération de la clé')}>
          <Skel w="40%" />
          <Skel w="100%" />
          <Skel w="85%" />
        </div>
      )}
      {key && (
        <RecordPanel
          name={name}
          value={record}
          copyLabel={t('Copier la clé publique')}
          copyWhat={t('Clé publique copiée')}
          tone={clash ? 'bad' : undefined}
          nameHint={domain ? undefined : t('saisissez le domaine pour le nom exact')}
          pills={[
            key.k === 'ed25519' ? { label: t('Ed25519 : à doubler d’une RSA'), tone: 'watch' } : { label: t('RSA {n} bits', { n: key.bits }), tone: 'good' },
            { label: nParts > 1 ? t('{n} caractères, {parts} chaînes', { n: record.length, parts: nParts }) : t('{n} caractères', { n: record.length }) },
            clash ? { label: t('sélecteur {selector} déjà pris', { selector }), tone: 'bad' } : { label: t('sélecteur {selector}', { selector }) },
          ]}
          actions={
            <a className="btn" href={href} download={fileName}>
              <Download aria-hidden />
              {t('Télécharger la clé privée')}
            </a>
          }
        >
          <div className="notice gen-safe">
            <ShieldCheck aria-hidden />
            <div>
              {rich("<b>La clé privée ne quitte pas ce navigateur.</b> Créée ici par WebCrypto, envoyée à aucun serveur (pas même TestAndFix), gardée nulle part. Téléchargez-la maintenant : elle disparaît si vous quittez ou rechargez la page.", undefined, { b: (c) => <strong>{c}</strong> })}
            </div>
          </div>
        </RecordPanel>
      )}
        </>
      }
      dock={key ? <MobileDock value={record} what={t('Clé publique copiée')} /> : undefined}
    >
      <div className="gen-card surface">
        <DomainField value={domain} onCommit={(d) => setDomain(d || null)} />
        {domain && <PrefillNote state={prefill} domain={domain} />}
      </div>
      <div className="gen-cards">
        <Block title={t('Sélecteur')}>
          {existing && existing.length > 0 && (
            <p className="field__hint">
              {t('Déjà publiés : {list}.', { list: existing.map((k) => `${k.selector} (${k.keyType === 'ed25519' ? 'Ed25519' : `RSA ${k.bits ?? '?'}`}${k.cnameProvider ? ', ' + t('délégué') : ''}${k.revoked ? ', ' + t('révoquée') : ''})`).join(', ') })}
            </p>
          )}
          {weak.length > 0 && (
            <div className="stack-sm">
              <Checks
                items={weak.map((k) => ({
                  key: k.selector,
                  tone: 'watch' as const,
                  main: <Link className="mono" to={`/dkim/${encodeURIComponent(domain)}?selecteur=${encodeURIComponent(k.selector)}`}>{k.selector}</Link>,
                  note: t('{n} bits, faible', { n: k.bits }),
                }))}
              />
              <p className="field__hint">
                {rich("La norme demande au moins 1024 bits et en recommande 2048 (<a>RFC 8301 §3.2</a>) : remplacez ces clés, chez le service qui les a créées s'il s'agit de la sienne (Google, Mailjet…), ou par celle-ci sous un nouveau sélecteur pour votre serveur.", undefined, { a: (c) => <a href="https://www.rfc-editor.org/rfc/rfc8301#section-3.2" target="_blank" rel="noreferrer noopener">{c}</a> })}
              </p>
            </div>
          )}
          <Field
            label={t('Nom du sélecteur')}
            hint={t('Un nom par clé, jamais réutilisé : dater le sélecteur rend la rotation simple.')}
            error={!validSel ? t('Lettres, chiffres et traits d’union seulement (RFC 6376 §3.1), sans espace.') : null}
          >
            {(id, d) => (
              <input
                id={id}
                aria-describedby={d}
                className="input input--mono"
                value={selText}
                spellCheck={false}
                autoCapitalize="off"
                autoComplete="off"
                onChange={(e) => setSelText(e.target.value)}
                onBlur={(e) => commitSelector(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && commitSelector((e.target as HTMLInputElement).value)}
              />
            )}
          </Field>
          <div className="chips" aria-label={t('Sélecteurs proposés')}>
            {suggestions.map((x) => (
              <button key={x} type="button" className="chip mono" aria-pressed={x === selector} onClick={() => setSelParam(x === suggestions[0] ? null : x)}>
                {x}
              </button>
            ))}
          </div>
          {clash && (
            <Notice tone="warn" title={t('Le sélecteur {selector} porte déjà une clé sur {domain}', { selector, domain })}>
              {t("Publier la nouvelle clé sous ce nom remplacerait l'ancienne : les messages déjà signés et en transit échoueraient. Choisissez un autre sélecteur.")}
            </Notice>
          )}
        </Block>

        <Block title={t('Type de clé')}>
          <Segmented
            label={t('Algorithme')}
            value={kind}
            onChange={(k) => setKindParam(k === 'rsa2048' ? null : k)}
            options={[
              { value: 'rsa2048', label: 'RSA 2048', recommended: true },
              { value: 'rsa4096', label: 'RSA 4096' },
              { value: 'ed25519', label: 'Ed25519' },
            ]}
            hint={t(KIND_HINT[kind])}
          />
          {kind === 'ed25519' && (
            <Notice tone="warn" title={t('Ed25519 seule ne suffit pas')}>
              {t("Les destinataires qui ne prennent pas encore en charge Ed25519 ignorent cette signature : pour eux le message n'est pas signé et DMARC dépend du seul SPF. Signez aussi en RSA 2048 sous un autre sélecteur (RFC 8463 §6), et gardez Ed25519 en complément.")}
              <div style={{ marginTop: 'var(--s2)' }}>
                <a className="btn btn--sm" style={{ whiteSpace: 'normal', textAlign: 'left', height: 'auto', paddingBlock: 'var(--s1)' }} href={`/generateurs/dkim?${new URLSearchParams({ ...(domain ? { domaine: domain } : {}), selecteur: `${selector}rsa` })}`} target="_blank" rel="noreferrer">
                  {t('Générer la clé RSA 2048 complémentaire ({selector}rsa)', { selector })}
                </a>
              </div>
            </Notice>
          )}
          <div>
            <button type="button" className="btn" onClick={() => generate(kind)} disabled={busy} aria-busy={busy || undefined}>
              <RefreshCw aria-hidden className={busy ? 'spin' : undefined} />
              {t('Nouvelle paire de clés')}
            </button>
          </div>
        </Block>

        <Block title={t('Mise en service')}>
          <ol className="issue__steps">
            <li>
              {domain
                ? rich("Installez la clé privée dans le logiciel qui signe (OpenDKIM, rspamd, Exim, panneau d'hébergement) avec le sélecteur <m>{selector}</m> et le domaine <m>{domain}</m>.", { selector, domain }, { m: (c) => <span className="mono">{c}</span> })
                : rich("Installez la clé privée dans le logiciel qui signe (OpenDKIM, rspamd, Exim, panneau d'hébergement) avec le sélecteur <m>{selector}</m> et votre domaine.", { selector }, { m: (c) => <span className="mono">{c}</span> })}
            </li>
            <li>{rich("Publiez l'enregistrement TXT <m>{name}</m> chez votre hébergeur DNS.", { name }, { m: (c) => <span className="mono">{c}</span> })}</li>
            <li>
              {domain
                ? rich("Activez la signature, envoyez un message, puis <l>contrôlez la clé publiée</l> et l'en-tête DKIM-Signature reçu.", undefined, { l: (c) => <Link to={`/dkim/${encodeURIComponent(domain)}?selecteur=${encodeURIComponent(selector)}`}>{c}</Link> })
                : t("Activez la signature, envoyez un message, puis contrôlez la clé publiée et l'en-tête DKIM-Signature reçu.")}
            </li>
            <li>{t("Remplacement d'une ancienne clé : laissez-la publiée quelques jours pour les messages en transit, puis retirez-la.")}</li>
          </ol>
          <p className="field__hint">
            {t("Google Workspace, Microsoft 365, Brevo et les autres services d'envoi créent leur clé eux-mêmes : publiez celle qu'ils affichent, pas celle-ci.")}
          </p>
        </Block>
      </div>

      {key && (
        <Details title={t('Clé privée en clair (PKCS#8, PEM)')}>
          <CodeBlock code={key.privatePem} label={fileName} />
          <p className="field__hint" style={{ marginTop: 'var(--s3)' }}>{rich('Touche <k>C</k> : copier la clé publique.', undefined, { k: (c) => <kbd>{c}</kbd> })}</p>
        </Details>
      )}
    </GenLayout>
  );
}
