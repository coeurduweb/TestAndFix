// DMARC generator: a progressive assistant on one page. Policy recommended from what is published
// (and from the stored aggregate reports when there are some), report address proposed, advanced
// tags folded with their meaning, authorisation record for an external report address.
import { useEffect, useMemo, useRef, useState } from 'react';
import { Link, useSearchParams } from 'react-router';
import { Check, Plus, X } from 'lucide-react';
import { useAuth } from '../../app/auth';
import { CodeBlock, Notice } from '../../components/ui';
import { api } from '../../lib/api';
import { msg, rich, t, tn } from '../../lib/i18n';
import { pushRecent } from '../../lib/recent';
import type { CheckResult } from '../../lib/types';
import { errorMessage } from '../../lib/useCheck';
import { Block, DomainField, GenLayout, MobileDock, PrefillNote, RecordPanel, Segmented, useCopyShortcut, useParam, type PrefillState } from '../gen-spf/GenParts';
import { Details } from '../../components/Verdict';
import { parseMailto, quoteTxt } from '../gen-spf/txt';
import { advise, buildDmarc, defaultModel, externalAuthorizations, parseDmarc, plan, strength, type Align, type DmarcModel, type FoOpt, type Policy } from './dmarc-build';

interface DmarcData {
  record?: string;
  inherited: boolean;
  foundAt?: string;
}
interface ReportsQuery {
  aggregate: { messages: number; reports: number } | null;
  recommendation: { target: Policy; headline: string; reasons: string[] } | null;
}
interface DnsData {
  answers: { type: string; value: string }[];
}

const POLICY_TEXT: Record<Policy, string> = {
  none: msg('Observation : les messages en échec sont livrés normalement, seuls les rapports arrivent. Ne protège pas encore contre l’usurpation.'),
  quarantine: msg('Les messages en échec vont en spam (quarantaine).'),
  reject: msg('Les messages en échec sont refusés : la protection complète.'),
};
const STEP_WHEN: Record<Policy, string> = {
  none: msg('dès maintenant, avec une adresse rua= pour recevoir les rapports'),
  quarantine: msg("quand les rapports ne montrent plus d'envoi légitime non aligné"),
  reject: msg('après quelques semaines en quarantine sans anomalie'),
};
const FO_TEXT: Record<FoOpt, string> = {
  '0': msg('SPF et DKIM échouent tous les deux (par défaut)'),
  '1': msg("l'un des deux échoue"),
  d: msg('la signature DKIM échoue'),
  s: msg('le SPF échoue'),
};

const KEYS = ['p', 'sp', 'np', 'adkim', 'aspf', 't', 'rua', 'ruf', 'fo'];

function fromParams(p: URLSearchParams): DmarcModel | null {
  if (!KEYS.some((k) => p.has(k))) return null;
  const m = defaultModel();
  const pol = (v: string | null): Policy | '' => (v === 'none' || v === 'quarantine' || v === 'reject' ? v : '');
  m.p = pol(p.get('p')) || 'none';
  m.sp = pol(p.get('sp'));
  m.np = pol(p.get('np'));
  m.adkim = p.get('adkim') === 's' ? 's' : 'r';
  m.aspf = p.get('aspf') === 's' ? 's' : 'r';
  m.t = p.get('t') === 'y';
  m.rua = (p.get('rua') ?? '').split(',').filter(Boolean);
  m.ruf = (p.get('ruf') ?? '').split(',').filter(Boolean);
  m.fo = (p.get('fo') ?? '').split(':').filter((x): x is FoOpt => ['0', '1', 'd', 's'].includes(x));
  return m;
}
function toParams(m: DmarcModel): Record<string, string> {
  const o: Record<string, string> = { p: m.p };
  if (m.sp) o.sp = m.sp;
  if (m.np) o.np = m.np;
  if (m.adkim === 's') o.adkim = 's';
  if (m.aspf === 's') o.aspf = 's';
  if (m.t) o.t = 'y';
  o.rua = m.rua.join(',');
  if (m.ruf.length) o.ruf = m.ruf.join(',');
  if (m.fo.length) o.fo = m.fo.join(':');
  return o;
}

/** Several report addresses, typed tolerantly, shown as chips. */
function AddressList({ label, values, onChange, suggestions, hint }: { label: string; values: string[]; onChange: (v: string[]) => void; suggestions: { value: string; label: string }[]; hint: string }) {
  const [text, setText] = useState('');
  const [err, setErr] = useState<string | null>(null);
  const add = (raw: string) => {
    const parts = raw.split(/[\s,;]+/).filter(Boolean);
    const ok: string[] = [];
    const bad: string[] = [];
    for (const x of parts) {
      const r = parseMailto(x);
      if ('uri' in r) ok.push(r.address);
      else bad.push(x);
    }
    if (ok.length) onChange([...new Set([...values, ...ok])]);
    setErr(bad.length ? t('Pas une adresse e-mail : {list}', { list: bad.join(', ') }) : null);
    setText(bad.join(' '));
  };
  const id = `addr-${label.replace(/\W+/g, '')}`;
  const left = suggestions.filter((s) => !values.some((v) => v.toLowerCase() === s.value.toLowerCase()));
  return (
    <div className="stack-sm">
      <form
        className="gen-row"
        onSubmit={(e) => {
          e.preventDefault();
          add(text);
        }}
      >
        <div className="field">
          <label className="field__label" htmlFor={id}>
            {label}
          </label>
          <input id={id} className="input input--mono" value={text} placeholder="dmarc@exemple.fr" autoComplete="off" spellCheck={false}
            aria-describedby={`${id}-h`} onChange={(e) => setText(e.target.value)} onBlur={(e) => e.target.value.trim() && add(e.target.value)} />
          {err ? <span className="field__error" id={`${id}-h`} role="alert">{err}</span> : <span className="field__hint" id={`${id}-h`}>{hint}</span>}
        </div>
        <button type="submit" className="btn" style={{ marginBottom: '1.35rem' }}>
          <Plus aria-hidden /> {t('Ajouter')}
        </button>
      </form>
      {(values.length > 0 || left.length > 0) && (
        <div className="chips">
          {values.map((v) => (
            <span key={v} className="chip mono gen-on">
              <Check aria-hidden />
              {v}
              <button type="button" className="gen-chip-x" aria-label={t('Retirer {value}', { value: v })} onClick={() => onChange(values.filter((x) => x !== v))}>
                <X size={12} aria-hidden />
              </button>
            </span>
          ))}
          {left.map((s) => (
            <button key={s.value} type="button" className="chip" aria-pressed={false} onClick={() => onChange([...values, s.value])}>
              <Plus aria-hidden />
              <span className="mono">{s.value}</span>
              <span className="gen-chip-cost">{s.label}</span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

export default function GenDmarcPage() {
  const { authenticated, loading: authLoading } = useAuth();
  const [domain, setDomain] = useParam('domaine');
  const [params, setParams] = useSearchParams();
  const fromUrl = useRef(fromParams(params));
  const [m, setM] = useState<DmarcModel>(() => fromUrl.current ?? defaultModel(domain || undefined));
  const [prefill, setPrefill] = useState<PrefillState>({ kind: 'off' });
  const [published, setPublished] = useState<{ record?: string; inherited: boolean; foundAt?: string } | null>(null);
  const [dropped, setDropped] = useState<string[]>([]);
  const [reports, setReports] = useState<ReportsQuery | null>(null);
  const [authz, setAuthz] = useState<Record<string, boolean | undefined>>({});

  // DNS and stored reports, signed in only.
  useEffect(() => {
    setPublished(null);
    setReports(null);
    setDropped([]);
    if (!domain) return setPrefill({ kind: 'off' });
    pushRecent({ value: domain, path: `/generateurs/dmarc?domaine=${domain}`, label: msg('Générateur DMARC') });
    if (authLoading) return;
    if (!authenticated) {
      if (!fromUrl.current) setM((x) => (x.rua.length ? x : { ...x, rua: [`dmarc@${domain}`] }));
      return setPrefill({ kind: 'anonymous' });
    }
    const keepUrl = fromUrl.current !== null;
    let alive = true;
    setPrefill({ kind: 'loading' });
    Promise.allSettled([
      api<CheckResult<DmarcData>>(`/api/dmarc/${encodeURIComponent(domain)}?historique=0`),
      api<ReportsQuery>(`/api/dmarc-reports?domain=${encodeURIComponent(domain)}`),
    ]).then(([d, rep]) => {
      if (!alive) return;
      fromUrl.current = null;
      const rq = rep.status === 'fulfilled' && rep.value.aggregate && rep.value.aggregate.messages > 0 ? rep.value : null;
      setReports(rq);
      if (d.status === 'rejected') {
        setPrefill({ kind: 'error', message: errorMessage(d.reason) });
        return;
      }
      const data = d.value.data;
      setPublished({ record: data.record, inherited: data.inherited, foundAt: data.foundAt });
      if (!keepUrl) {
        if (data.record && !data.inherited) {
          const parsed = parseDmarc(data.record, domain);
          setDropped(parsed.dropped);
          const next = advise(parsed.model.p, rq?.recommendation).policy;
          setM({ ...parsed.model, p: rq ? next : parsed.model.p, rua: parsed.model.rua.length ? parsed.model.rua : [`dmarc@${domain}`] });
        } else {
          setM({ ...defaultModel(domain), p: advise(null, rq?.recommendation).policy });
        }
      }
      const what = [data.record ? (data.inherited ? t('DMARC hérité de {foundAt}', { foundAt: data.foundAt }) : t('DMARC publié')) : t('aucun DMARC publié'), rq ? t('{n} rapports stockés', { n: rq.aggregate!.reports }) : t('aucun rapport stocké')].join(', ');
      setPrefill({ kind: 'done', at: d.value.measuredAt, what });
    });
    return () => {
      alive = false;
    };
  }, [domain, authenticated, authLoading]);

  useEffect(() => {
    const want = toParams(m);
    const n = new URLSearchParams(params);
    for (const k of KEYS) n.delete(k);
    for (const [k, v] of Object.entries(want)) if (v) n.set(k, v);
    if (n.toString() !== params.toString()) setParams(n, { replace: true });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [m]);

  const record = useMemo(() => buildDmarc(m), [m]);
  useCopyShortcut(record, t('DMARC copié'));
  const publishedPolicy = published?.record && !published.inherited ? parseDmarc(published.record).model.p : null;
  const advice = advise(publishedPolicy, reports?.recommendation, prefill.kind === 'done');
  const auths = domain ? externalAuthorizations(domain, [...m.rua, ...m.ruf]) : [];
  const authKey = auths.map((a) => a.name).join('|');

  // Is each external authorisation already published? (signed in only)
  useEffect(() => {
    if (!authenticated || !auths.length) return;
    let alive = true;
    const t = setTimeout(() => {
      for (const a of auths) {
        if (authz[a.name] !== undefined) continue;
        api<CheckResult<DnsData>>(`/api/dns/${encodeURIComponent(a.name)}?type=TXT&historique=0`)
          .then((r) => alive && setAuthz((x) => ({ ...x, [a.name]: r.data.answers.some((y) => y.type === 'TXT' && /v=DMARC1/i.test(y.value)) })))
          .catch(() => undefined);
      }
    }, 500);
    return () => {
      alive = false;
      clearTimeout(t);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [authKey, authenticated]);

  const set = (patch: Partial<DmarcModel>) => setM((x) => ({ ...x, ...patch }));
  const eff = (x: Policy | '') => (x || m.p) as Policy;
  const subWeaker = m.sp !== '' && strength(m.sp) < strength(m.p);
  const ruaCount = m.rua.filter((a) => 'uri' in parseMailto(a)).length;
  const name = `_dmarc.${domain || t('votre-domaine.fr')}`;
  const polSeg = (label: string, value: Policy | '', onChange: (v: Policy | '') => void, inherit: string) => (
    <Segmented<Policy | 'inherit'>
      label={label}
      value={value || 'inherit'}
      onChange={(v) => onChange(v === 'inherit' ? '' : v)}
      options={[
        { value: 'inherit', label: inherit },
        { value: 'none', label: 'none' },
        { value: 'quarantine', label: 'quarantine' },
        { value: 'reject', label: 'reject' },
      ]}
    />
  );

  const authOk = auths.every((a) => authz[a.name]);
  const strict = m.adkim === 's' || m.aspf === 's';
  return (
    <GenLayout
      title={t('Générateur DMARC')}
      desc={t("Une politique progressive, de none à reject, avec l'adresse des rapports et les réglages avancés expliqués. Norme RFC 9989.")}
      aside={
      <RecordPanel
        name={name}
        value={record}
        copyWhat={t('DMARC copié')}
        tone={ruaCount === 0 ? 'watch' : undefined}
        nameHint={domain ? t('un seul enregistrement DMARC : remplacez l’existant') : t('saisissez le domaine pour le nom exact')}
        pills={[
          { label: m.t ? t('p={p} en mode test', { p: m.p }) : `p=${m.p}`, tone: m.p === 'reject' && !m.t ? 'good' : 'watch' },
          ruaCount ? { label: tn(ruaCount, '{n} adresse de rapports', '{n} adresses de rapports'), tone: 'good' } : { label: t('aucune adresse de rapports'), tone: 'bad' },
          ...(auths.length ? [{ label: authOk ? t('autorisation externe publiée') : t('autorisation externe à publier'), tone: (authOk ? 'good' : 'watch') as 'good' | 'watch' }] : []),
          ...(subWeaker ? [{ label: t('sous-domaines plus faibles (sp={sp})', { sp: m.sp }), tone: 'watch' as const }] : []),
          ...(strict ? [{ label: t('alignement strict'), tone: 'watch' as const }] : []),
        ]}
        actions={
          domain ? (
            <Link className="btn btn--ghost" to={`/dmarc/${encodeURIComponent(domain)}`}>
              {t('Contrôler le DMARC publié')}
            </Link>
          ) : undefined
        }
      />
      }
      dock={<MobileDock value={record} what={t('DMARC copié')} />}
    >
      <div className="gen-card surface">
        <DomainField
          value={domain}
          onCommit={(d) => {
            fromUrl.current = null;
            setDomain(d || null);
            if (d) setM((x) => ({ ...x, rua: x.rua.length && !x.rua.every((a) => /^dmarc@/i.test(a)) ? x.rua : [`dmarc@${d}`] }));
          }}
        />
        {domain && <PrefillNote state={prefill} domain={domain} />}
      </div>

      {(published?.record || dropped.length > 0) && (
        <div className="gen-block">
          {published?.record && (
            <CodeBlock code={published.record} label={published.inherited ? t('DMARC hérité de {foundAt}', { foundAt: published.foundAt }) : t("DMARC publié aujourd'hui sur {domain}", { domain })} />
          )}
          {dropped.length > 0 && (
            <p className="field__hint">{t("Retirés : {list}. pct=, ri= et rf= n'existent plus dans la RFC 9989 ; une autre balise inconnue est ignorée par les destinataires.", { list: dropped.join(', ') })}</p>
          )}
        </div>
      )}

      <div className="gen-cards">
          <Block title={t('Politique')}>
            <div className="gen-block">
              <Segmented
                label={t('Que faire des messages qui échouent à DMARC')}
                value={m.p}
                onChange={(p) => set({ p, t: p === 'none' ? false : m.t })}
                options={(['none', 'quarantine', 'reject'] as Policy[]).map((p) => ({ value: p, label: p, recommended: p === advice.policy }))}
                hint={t(POLICY_TEXT[m.p])}
              />
              <p className="gen-lede">
                <strong>{t('Recommandé : {policy}.', { policy: advice.policy })}</strong> {advice.reason}
                {advice.basis === 'reports' && reports?.aggregate && <> {rich('Selon vos {n} rapports stockés (<l>les voir</l>).', { n: reports.aggregate.reports }, { l: (c) => <Link to={`/rapports-dmarc?domaine=${encodeURIComponent(domain)}`}>{c}</Link> })}</>}
                {advice.basis !== 'reports' && domain && authenticated && (
                  <> {rich("Déposez des rapports dans l'<l>analyseur</l> pour une recommandation mesurée.", undefined, { l: (c) => <Link to="/rapports-dmarc">{c}</Link> })}</>
                )}
              </p>
              {m.p !== 'none' && (
                <label className="gen-check">
                  <input type="checkbox" checked={m.t} onChange={(e) => set({ t: e.target.checked })} />
                  <span>
                    {rich("Mode test <m>t=y</m> : appliquer la politique un cran en dessous pendant la transition ({shift}). RFC 9989 §4.7, à la place de l'ancien pct=.", { shift: m.p === 'reject' ? t('reject devient quarantine') : t('quarantine devient none') }, { m: (c) => <span className="mono">{c}</span> })}
                  </span>
                </label>
              )}
              <div className="stack-sm">
                <span className="gen-label">{t('Plan progressif')}</span>
                <ol className="gen-plan">
                  {plan(m).map((step) => {
                    const state = step.policy === m.p ? t('choisi') : publishedPolicy && strength(step.policy) <= strength(publishedPolicy) ? t('publié') : strength(step.policy) < strength(m.p) ? t('avant') : t('ensuite');
                    return (
                      <li key={step.policy} data-current={step.policy === m.p || undefined}>
                        <button type="button" className="gen-plan__step" aria-pressed={step.policy === m.p} onClick={() => set({ p: step.policy, t: step.policy === 'none' ? false : m.t })}>
                          <span className="mono">p={step.policy}</span>
                          <span className="gen-plan__when">{t(STEP_WHEN[step.policy])}</span>
                          <span className={`tag ${step.policy === m.p ? 'tag--lab' : ''}`}>{state}</span>
                        </button>
                      </li>
                    );
                  })}
                </ol>
              </div>
            </div>
          </Block>

          <Block title={t('Rapports')}>
            <div className="gen-block">
              <AddressList
                label={t('Adresse des rapports agrégés (rua)')}
                values={m.rua}
                onChange={(rua) => set({ rua })}
                hint={t('Une boîte dédiée : elle reçoit des rapports XML chaque jour. Plusieurs adresses possibles.')}
                suggestions={[
                  ...(domain ? [{ value: `dmarc@${domain}`, label: t('proposée') }] : []),
                  { value: 'rua@dmarc.brevo.com', label: 'Brevo' },
                ]}
              />
              {ruaCount === 0 && (
                <Notice tone="warn" title={t('Aucune adresse de rapports')}>
                  {t('Sans rua=, vous ne saurez pas qui envoie en votre nom ni quels services échouent : impossible de monter vers quarantine sans risque.')}
                </Notice>
              )}
              {auths.map((a) => (
                <div key={a.name} className="stack-sm">
                  <Notice tone={authz[a.name] ? 'info' : 'warn'} title={authz[a.name] ? t('{domain} accepte déjà vos rapports', { domain: a.reportDomain }) : t('{domain} doit accepter vos rapports', { domain: a.reportDomain })}>
                    {authz[a.name]
                      ? t("L'autorisation {name} est publiée : les rapports seront envoyés à {address}.", { name: a.name, address: a.address })
                      : t("L'adresse {address} est hors de {domain} : les destinataires n'y envoient les rapports que si le propriétaire de {reportDomain} publie l'enregistrement ci-dessous (RFC 9990 §4). Les services d'analyse le font en général pour vous.", { address: a.address, domain, reportDomain: a.reportDomain })}
                  </Notice>
                  {!authz[a.name] && (
                    <div style={{ paddingTop: 'var(--s2)' }}>
                      <CodeBlock code={`${a.name}. IN TXT ${quoteTxt([a.value])}`} label={t('À publier sur {domain}', { domain: a.reportDomain })} />
                    </div>
                  )}
                </div>
              ))}
            </div>
          </Block>

          </div>
          <Details title={t('Réglages avancés')} count={t('sous-domaines, alignement, rapports d’échec')}>
            <div className="stack" style={{ gap: 'var(--s5)' }}>
              <div className="stack-sm">
                {polSeg(t('Sous-domaines existants (sp=)'), m.sp, (sp) => set({ sp }), t('comme p ({p})', { p: m.p }))}
                <p className="field__hint">{t('factures.{domain} et les autres sous-domaines publiés. Sans sp=, ils suivent p=.', { domain: domain || 'example.com' })}</p>
                {subWeaker && <p className="field__hint out-text">{t('sp={sp} est plus faible que p={p} : un usurpateur peut envoyer depuis un sous-domaine sans être bloqué.', { sp: m.sp, p: m.p })}</p>}
              </div>
              <div className="stack-sm">
                {polSeg(t('Sous-domaines inexistants (np=)'), m.np, (np) => set({ np }), t('comme sp ({sp})', { sp: eff(m.sp) }))}
                <p className="field__hint">
                  {t("Les noms qui n'existent pas dans le DNS, souvent inventés par les usurpateurs. np=reject les bloque sans toucher à vos vrais sous-domaines (RFC 9989 §4.7).")}
                  {m.p !== 'none' && strength(eff(m.np || m.sp)) < strength('reject') && ' ' + t('Recommandé ici : reject.')}
                </p>
              </div>
              <div className="stack-sm">
                <Segmented<Align> label={t('Alignement DKIM (adkim=)')} value={m.adkim} onChange={(adkim) => set({ adkim })} options={[{ value: 'r', label: t('relâché'), recommended: true }, { value: 's', label: t('strict') }]} />
                <Segmented<Align> label={t('Alignement SPF (aspf=)')} value={m.aspf} onChange={(aspf) => set({ aspf })} options={[{ value: 'r', label: t('relâché'), recommended: true }, { value: 's', label: t('strict') }]} />
                <p className="field__hint">
                  {t('Relâché (par défaut) : un sous-domaine du même domaine suffit, par exemple em1234.{domain} chez SendGrid ou mg.{domain} chez Mailgun. Strict : égalité exacte des domaines ; ces services échouent alors à DMARC.', { domain: domain || 'example.com' })}
                </p>
                {(m.adkim === 's' || m.aspf === 's') && (
                  <p className="field__hint out-text">{t('Alignement strict : vérifiez que chaque service signe avec d={domain} exactement et envoie avec un Return-Path sur ce domaine.', { domain: domain || t('votre domaine') })}</p>
                )}
              </div>
              <div className="stack-sm">
                <AddressList
                  label={t("Rapports d'échec détaillés (ruf)")}
                  values={m.ruf}
                  onChange={(ruf) => set({ ruf, fo: ruf.length ? m.fo : [] })}
                  hint={t('Rarement envoyés par les grands fournisseurs ; peuvent contenir des extraits de messages et des adresses personnelles : boîte à protéger.')}
                  suggestions={[]}
                />
                {m.ruf.length > 0 && (
                  <div className="stack-sm">
                    <span className="gen-label">{t("Quand envoyer un rapport d'échec (fo=)")}</span>
                    {(['0', '1', 'd', 's'] as FoOpt[]).map((o) => (
                      <label key={o} className="gen-check">
                        <input
                          type="checkbox"
                          checked={o === '0' ? !m.fo.some((x) => x !== '0') : m.fo.includes(o)}
                          onChange={(e) =>
                            set({ fo: o === '0' ? [] : e.target.checked ? [...m.fo.filter((x) => x !== '0'), o] : m.fo.filter((x) => x !== o) })
                          }
                        />
                        <span>
                          {rich('<m>{o}</m> : {text}', { o, text: t(FO_TEXT[o]) }, { m: (c) => <span className="mono">{c}</span> })}
                        </span>
                      </label>
                    ))}
                  </div>
                )}
              </div>
              <p className="field__hint">{t('pct=, ri= et rf= ne sont pas proposés : la RFC 9989 les a supprimés. psd= est réservé aux registres de domaines.')}</p>
            </div>
          </Details>
    </GenLayout>
  );
}
