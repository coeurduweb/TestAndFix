// MTA-STS generator: MX read from the DNS (signed in) or typed, testing or enforce, max_age; produces
// the policy file, the _mta-sts record with a dated id and the TLS-RPT record.
import { useEffect, useMemo, useRef, useState } from 'react';
import { Link, useSearchParams } from 'react-router';
import { Download, Plus, RefreshCw, X } from 'lucide-react';
import { useAuth } from '../../app/auth';
import { CodeBlock, Notice } from '../../components/ui';
import { api } from '../../lib/api';
import { rich, t, tn, msg } from '../../lib/i18n';
import { pushRecent } from '../../lib/recent';
import type { CheckResult } from '../../lib/types';
import { errorMessage } from '../../lib/useCheck';
import { Block, Checks, DomainField, GenLayout, MobileDock, PrefillNote, RecordPanel, Segmented, useCopyShortcut, useParam, type PrefillState } from '../gen-spf/GenParts';
import { parseMailto, stampId } from '../gen-spf/txt';
import { covered, defaultSts, MAX_AGE_MAX, MAX_AGES, parseMxList, policyFile, stsRecord, tlsRptRecord, validId, type StsMode, type StsModel } from './mtasts-build';

interface StsData {
  record?: string;
  id?: string;
  policy?: { mode?: string; mx: string[]; maxAge?: number };
  mx: { host: string; preference: number; covered: boolean | null }[];
  tlsrpt: { record?: string; rua: string[] };
}

const KEYS = ['mode', 'mx', 'max_age', 'rua'];

function fromParams(p: URLSearchParams): StsModel | null {
  if (!KEYS.some((k) => p.has(k))) return null;
  const m = defaultSts();
  m.mode = p.get('mode') === 'enforce' ? 'enforce' : 'testing';
  m.mx = parseMxList((p.get('mx') ?? '').replace(/,/g, '\n')).mx;
  const age = Number(p.get('max_age'));
  if (Number.isFinite(age) && age > 0) m.maxAge = Math.min(MAX_AGE_MAX, age);
  m.tlsRua = (p.get('rua') ?? '').split(',').filter(Boolean);
  return m;
}

/** Host name breakable after each dot only. */
const wbr = (h: string) => h.split('.').flatMap((part, i, a) => (i < a.length - 1 ? [part, '.', <wbr key={i} />] : [part]));

function secondsLabel(s: number): string {
  const d = s / 86400;
  if (s === MAX_AGE_MAX) return t('1 an');
  if (Number.isInteger(d / 7) && d >= 7) return tn(d / 7, '{n} semaine', '{n} semaines');
  if (Number.isInteger(d)) return tn(d, '{n} jour', '{n} jours');
  return t('{n} h', { n: Math.round(s / 3600) });
}

export default function GenMtaStsPage() {
  const { authenticated, loading: authLoading } = useAuth();
  const [domain, setDomain] = useParam('domaine');
  const [params, setParams] = useSearchParams();
  const fromUrl = useRef(fromParams(params));
  const [m, setM] = useState<StsModel>(() => fromUrl.current ?? defaultSts(domain || undefined));
  const [dnsMx, setDnsMx] = useState<string[] | null>(null);
  const [published, setPublished] = useState<StsData | null>(null);
  const [prefill, setPrefill] = useState<PrefillState>({ kind: 'off' });
  const [mxText, setMxText] = useState('');
  const [mxErr, setMxErr] = useState<string | null>(null);
  const [ruaText, setRuaText] = useState('');

  useEffect(() => {
    setDnsMx(null);
    setPublished(null);
    if (!domain) return setPrefill({ kind: 'off' });
    pushRecent({ value: domain, path: `/generateurs/mta-sts?domaine=${domain}`, label: msg('Générateur MTA-STS') });
    if (authLoading) return;
    if (!authenticated) {
      if (!fromUrl.current) setM((x) => (x.tlsRua.length ? x : { ...x, tlsRua: [`tlsrpt@${domain}`] }));
      return setPrefill({ kind: 'anonymous' });
    }
    const keepUrl = fromUrl.current !== null;
    let alive = true;
    setPrefill({ kind: 'loading' });
    api<CheckResult<StsData>>(`/api/mta-sts/${encodeURIComponent(domain)}?historique=0`)
      .then((r) => {
        if (!alive) return;
        fromUrl.current = null;
        const d = r.data;
        const hosts = [...d.mx].sort((a, b) => a.preference - b.preference).map((x) => x.host.replace(/\.$/, '').toLowerCase());
        setDnsMx(hosts);
        setPublished(d);
        if (!keepUrl) {
          const base = defaultSts(domain);
          const pol = d.policy;
          const mx = pol?.mx.length ? [...pol.mx, ...hosts.filter((h) => !covered(h, pol.mx))] : hosts;
          setM({
            ...base,
            mx,
            mode: pol?.mode === 'enforce' ? 'enforce' : 'testing',
            maxAge: pol?.maxAge && pol.maxAge > 0 ? Math.min(MAX_AGE_MAX, pol.maxAge) : base.maxAge,
            tlsRua: d.tlsrpt.rua.length ? d.tlsrpt.rua.map((u) => u.replace(/^mailto:/i, '')) : base.tlsRua,
          });
        }
        setPrefill({ kind: 'done', at: r.measuredAt, what: [t('{n} MX', { n: hosts.length }), d.record ? t('politique MTA-STS publiée') : t('aucune politique publiée'), d.tlsrpt.record ? t('TLS-RPT publié') : t('pas de TLS-RPT')].join(', ') });
      })
      .catch((e) => alive && setPrefill({ kind: 'error', message: errorMessage(e) }));
    return () => {
      alive = false;
    };
  }, [domain, authenticated, authLoading]);

  useEffect(() => {
    const n = new URLSearchParams(params);
    for (const k of KEYS) n.delete(k);
    n.set('mode', m.mode);
    if (m.mx.length) n.set('mx', m.mx.join(','));
    if (m.maxAge !== 604800) n.set('max_age', String(m.maxAge));
    if (m.tlsRua.length) n.set('rua', m.tlsRua.join(','));
    if (n.toString() !== params.toString()) setParams(n, { replace: true });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [m]);

  const file = useMemo(() => policyFile(m), [m]);
  const [idForced, setIdForced] = useState(false);
  const rpt = tlsRptRecord(m.tlsRua);
  useCopyShortcut(file, t('Fichier de politique copié'));
  const href = useMemo(() => URL.createObjectURL(new Blob([file], { type: 'text/plain' })), [file]);
  useEffect(() => () => URL.revokeObjectURL(href), [href]);

  const set = (patch: Partial<StsModel>) => setM((x) => ({ ...x, ...patch }));
  const addMx = (raw: string) => {
    const r = parseMxList(raw);
    setMxErr(r.errors.length ? t("Pas un nom d'hôte : {list}", { list: r.errors.join(', ') }) : null);
    if (r.mx.length) set({ mx: [...new Set([...m.mx, ...r.mx])] });
    setMxText(r.errors.join('\n'));
  };
  const addRua = (raw: string) => {
    const ok = raw.split(/[\s,;]+/).filter(Boolean).map(parseMailto).flatMap((r) => ('uri' in r ? [r.address] : []));
    if (ok.length) set({ tlsRua: [...new Set([...m.tlsRua, ...ok])] });
    setRuaText('');
  };
  const d = domain || t('votre-domaine.fr');
  const uncovered = (dnsMx ?? []).filter((h) => !covered(h, m.mx));
  const extra = dnsMx ? m.mx.filter((p) => !dnsMx.some((h) => covered(h, [p]))) : [];
  const policyChanged = published?.policy && published.record ? (published.policy.mode !== m.mode || published.policy.maxAge !== m.maxAge || published.policy.mx.join() !== m.mx.join()) : true;
  // unchanged policy: keep the published id, so that senders do not refetch for nothing
  const id = !policyChanged && published?.id && !idForced ? published.id : m.id;
  const sts = stsRecord(id);

  return (
    <GenLayout
      title={t('Générateur MTA-STS')}
      desc={t('Fichier de politique, enregistrement _mta-sts daté et rapports TLS-RPT : le chiffrement exigé pour le courrier que vous recevez (RFC 8461, RFC 8460).')}
      aside={
        <>
      <RecordPanel
        label={t('Fichier de politique produit')}
        name={`https://mta-sts.${d}/.well-known/mta-sts.txt`}
        type={t('fichier texte')}
        value={file.trimEnd()}
        copy={file}
        copyLabel={t('Copier le fichier')}
        copyWhat={t('Fichier de politique copié')}
        zone={false}
        tone={m.mx.length === 0 || uncovered.length ? 'bad' : undefined}
        pills={[
          { label: t('mode {mode}', { mode: m.mode }), tone: m.mode === 'enforce' ? 'good' : undefined },
          m.mx.length === 0
            ? { label: t('aucun MX'), tone: 'bad' }
            : dnsMx
              ? { label: t('{n} MX couverts sur {total}', { n: dnsMx.length - uncovered.length, total: dnsMx.length }), tone: uncovered.length ? 'bad' : 'good' }
              : { label: tn(m.mx.length, '{n} MX listé', '{n} MX listés') },
          { label: t('cache {duration}', { duration: secondsLabel(m.maxAge) }), tone: m.mode === 'enforce' && m.maxAge < 604800 ? 'watch' : undefined },
        ]}
        actions={
          <a className="btn" href={href} download="mta-sts.txt">
            <Download aria-hidden /> {t('Télécharger')}
          </a>
        }
      >
        <p className="field__hint">
          {rich("À servir en HTTPS sur mta-sts.{d} avec un certificat valide pour ce nom, sans redirection, en <m>Content-Type: text/plain</m>. À chaque modification du fichier, un nouvel id dans _mta-sts : sinon les expéditeurs gardent l'ancienne version jusqu'à la fin du cache.", { d }, { m: (c) => <span className="mono">{c}</span> })}
        </p>
      </RecordPanel>
      <section className="gen-card surface" aria-labelledby="sts-dns-t">
        <h2 className="gen-card__title" id="sts-dns-t">{t('Enregistrements DNS à publier')}</h2>
        <div className="gen-card__body">
          <div className="gen-hero__name"><span>{t('Nom')}</span><code>_mta-sts.{d}</code><span>· TXT</span></div>
          <CodeBlock code={sts} label={t('Valeur')} tone="suggested" copyLabel={t('Copier')} />
          <div className="gen-row" style={{ alignItems: 'center' }}>
            <button type="button" className="btn btn--sm" onClick={() => { setIdForced(true); set({ id: stampId() }); }}>
              <RefreshCw aria-hidden /> {t('Nouvel id daté')}
            </button>
            <span className="field__hint">
              {!policyChanged && !idForced ? t("Politique identique à celle publiée : l'id actuel est gardé. Tout changement du fichier demande un nouvel id daté.") : validId(id) ? t('id valide : {n} lettres et chiffres (32 au plus).', { n: id.length }) : t('id invalide : {n} lettres et chiffres (32 au plus).', { n: id.length })}
            </span>
          </div>
          {m.tlsRua.length > 0 && (
            <>
              <div className="gen-hero__name" style={{ marginTop: 'var(--s3)' }}><span>{t('Nom')}</span><code>_smtp._tls.{d}</code><span>· TXT</span></div>
              <CodeBlock code={rpt} label={t('Valeur')} tone="suggested" copyLabel={t('Copier')} />
            </>
          )}
          {domain && (
            <div>
              <Link className="btn btn--ghost" to={`/mta-sts/${encodeURIComponent(domain)}`}>{t('Contrôler MTA-STS de {domain}', { domain })}</Link>
            </div>
          )}
        </div>
      </section>
        </>
      }
      dock={<MobileDock value={file.trim().replace(/\n/g, ' · ')} copy={file} what={t('Fichier de politique copié')} />}
    >
      <div className="gen-card surface">
        <DomainField value={domain} onCommit={(x) => {
          fromUrl.current = null;
          setDomain(x || null);
          if (x) setM((y) => ({ ...y, tlsRua: y.tlsRua.length && !y.tlsRua.every((a) => /^tlsrpt@/i.test(a)) ? y.tlsRua : [`tlsrpt@${x}`] }));
        }} />
        {domain && <PrefillNote state={prefill} domain={domain} />}
        {published?.record && <CodeBlock code={published.record} label={t("_mta-sts.{domain} publié aujourd'hui", { domain })} />}
      </div>
      <div className="gen-cards">
          <Block title={t('Mode et durée')}>
            <div className="gen-block">
              <Segmented<StsMode>
                label={t('Que font les expéditeurs si le TLS échoue')}
                value={m.mode}
                onChange={(mode) => set({ mode })}
                options={[
                  { value: 'testing', label: 'testing', recommended: !published?.policy || published.policy.mode !== 'enforce' },
                  { value: 'enforce', label: 'enforce', recommended: published?.policy?.mode === 'enforce' },
                ]}
                hint={
                  m.mode === 'testing'
                    ? t('Ils livrent quand même et vous envoient un rapport TLS-RPT. Pour démarrer : quelques semaines sans échec dans les rapports, puis enforce.')
                    : t('Ils refusent de livrer à un MX non listé ou au certificat invalide. Une politique fausse bloque votre courrier entrant.')
                }
              />
              {m.mode === 'enforce' && published?.policy?.mode !== 'enforce' && (
                <Notice tone="warn" title={t('Passer en enforce sans période de test')}>
                  {t("Vérifiez d'abord dans les rapports TLS-RPT qu'aucun MX n'échoue : en enforce, un MX oublié dans la liste ou un certificat expiré arrête la réception.")}
                </Notice>
              )}
              <Segmented<string>
                label={t('Durée de cache (max_age)')}
                value={String(m.maxAge)}
                onChange={(v) => set({ maxAge: Number(v) })}
                options={MAX_AGES.map((x) => ({ value: String(x.value), label: t(x.label), recommended: x.value === 604800 }))}
                hint={t("{n} secondes. Les expéditeurs gardent la politique en cache ce temps-là ; en enforce, moins d'une semaine affaiblit la protection (RFC 8461 §10.2), plus de 31557600 est refusé.", { n: m.maxAge })}
              />
            </div>
          </Block>

          <Block title={t('Rapports TLS-RPT')}>
            <div className="gen-block">
              <div className="chips">
                {m.tlsRua.map((a) => (
                  <span key={a} className="chip mono gen-on">
                    {a}
                    <button type="button" className="gen-chip-x" aria-label={t('Retirer {value}', { value: a })} onClick={() => set({ tlsRua: m.tlsRua.filter((x) => x !== a) })}>
                      <X size={12} aria-hidden />
                    </button>
                  </span>
                ))}
                {domain && !m.tlsRua.includes(`tlsrpt@${domain}`) && (
                  <button type="button" className="chip" onClick={() => set({ tlsRua: [...m.tlsRua, `tlsrpt@${domain}`] })}>
                    <Plus aria-hidden /> <span className="mono">tlsrpt@{domain}</span>
                  </button>
                )}
              </div>
              <form className="gen-row" onSubmit={(e) => { e.preventDefault(); addRua(ruaText); }}>
                <div className="field">
                  <label className="field__label" htmlFor="sts-rua">{t('Adresse des rapports')}</label>
                  <input id="sts-rua" className="input input--mono" value={ruaText} placeholder={`tlsrpt@${d}`} onChange={(e) => setRuaText(e.target.value)} onBlur={(e) => e.target.value.trim() && addRua(e.target.value)} />
                </div>
                <button type="submit" className="btn"><Plus aria-hidden /> {t('Ajouter')}</button>
              </form>
              {m.tlsRua.length === 0 && <p className="field__hint out-text">{t('Sans adresse, les échecs de chiffrement restent invisibles.')}</p>}
            </div>
          </Block>
          <Block title={t('Serveurs MX autorisés')}>
            <div className="gen-block">
              {m.mx.length > 0 && (
                <div className="chips" aria-label={t('MX de la politique')}>
                  {m.mx.map((h) => (
                    <span key={h} className="chip mono gen-on">
                      {h}
                      <button type="button" className="gen-chip-x" aria-label={t('Retirer {value}', { value: h })} onClick={() => set({ mx: m.mx.filter((x) => x !== h) })}>
                        <X size={12} aria-hidden />
                      </button>
                    </span>
                  ))}
                </div>
              )}
              <form className="gen-row" onSubmit={(e) => { e.preventDefault(); addMx(mxText); }}>
                <div className="field">
                  <label className="field__label" htmlFor="sts-mx">{t('Ajouter des MX')}</label>
                  <textarea id="sts-mx" className="textarea textarea--mono" rows={2} style={{ minHeight: '2.5rem' }} value={mxText}
                    placeholder={'mx1.exemple.fr\n*.mail.protection.outlook.com'} aria-describedby="sts-mx-h"
                    onChange={(e) => setMxText(e.target.value)} onBlur={(e) => e.target.value.trim() && addMx(e.target.value)}
                    onKeyDown={(e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); addMx((e.target as HTMLTextAreaElement).value); } }} />
                  {mxErr ? <span className="field__error" id="sts-mx-h" role="alert">{mxErr}</span> : <span className="field__hint" id="sts-mx-h">{t('Un par ligne, la sortie de dig MX se colle telle quelle. « *. » couvre un seul niveau.')}</span>}
                </div>
                <button type="submit" className="btn" style={{ marginBottom: '1.35rem' }}><Plus aria-hidden /> {t('Ajouter')}</button>
              </form>
              {dnsMx && dnsMx.length > 0 && (
                <Checks
                  items={dnsMx.map((h) => {
                    const by = m.mx.find((p) => covered(h, [p]));
                    return { key: h, tone: by ? ('ok' as const) : ('bad' as const), main: <span className="mono">{wbr(h)}</span>, note: by ? (by === h ? t('listé') : rich('via <m>{by}</m>', { by }, { m: () => <span className="mono">{wbr(by)}</span> })) : t('oublié dans la politique') };
                  })}
                />
              )}
              {uncovered.length > 0 && (
                <div className="stack-sm">
                  <Notice tone={m.mode === 'enforce' ? 'error' : 'warn'} title={tn(uncovered.length, '{n} MX du DNS absent de la politique', '{n} MX du DNS absents de la politique')}>
                    {m.mode === 'enforce' ? t('En enforce, les expéditeurs refuseront de livrer à {list}.', { list: uncovered.join(', ') }) : t('En enforce, les expéditeurs refuseraient de livrer à {list}.', { list: uncovered.join(', ') })}
                  </Notice>
                  <div>
                    <button type="button" className="btn" onClick={() => set({ mx: [...m.mx, ...uncovered] })}>
                      <Plus aria-hidden /> {t('Ajouter les MX manquants')}
                    </button>
                  </div>
                </div>
              )}
              {extra.length > 0 && <p className="field__hint">{t("Listés mais absents du DNS : {list}. Sans effet, à retirer si ce serveur n'existe plus.", { list: extra.join(', ') })}</p>}
              {!dnsMx && m.mx.length === 0 && <p className="field__hint">{t('Connecté, TestAndFix lit les MX de {d} ; sinon collez-les ici.', { d })}</p>}
            </div>
          </Block>

      </div>
    </GenLayout>
  );
}
