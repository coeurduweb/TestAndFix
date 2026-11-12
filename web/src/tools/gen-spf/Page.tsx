// SPF generator: services detected from the live SPF and MX, official includes from the knowledge
// base, addresses, final rule; the record is rebuilt on every change with its DNS lookup count.
import { useEffect, useMemo, useRef, useState } from 'react';
import { Link, useSearchParams } from 'react-router';
import { Check, Plus, X } from 'lucide-react';
import { useAuth } from '../../app/auth';
import { LabRow } from '../../components/Report';
import { CodeBlock, Field, Notice } from '../../components/ui';
import { api } from '../../lib/api';
import { msg, rich, t, tn } from '../../lib/i18n';
import { pushRecent } from '../../lib/recent';
import type { CheckResult } from '../../lib/types';
import { errorMessage } from '../../lib/useCheck';
import { Block, CompactTable, DomainField, GenLayout, MobileDock, PrefillNote, RecordPanel, Segmented, useCopyShortcut, useParam, type PrefillState } from './GenParts';
import { Details } from '../../components/Verdict';
import { ProviderSearch } from './ProviderSearch';
import { COSTS_MEASURED_ON, providerByKey } from './providers';
import { parseIpInput, rawTermCost, SPF_LOOKUP_LIMIT, type BuiltTerm, type CostSource } from './spf-build';
import { build, FREQUENT, fromDns, fromParams, initialState, selIncludes, STATE_PARAMS, toParams, type GenState, type Sel, type TreeTerm } from './state';
import { splitTxt } from './txt';

interface SpfData {
  record?: string;
  tree?: { terms: TreeTerm[] };
  lookupCount?: number;
}
interface DnsData {
  answers: { type: string; value: string }[];
}

const SOURCE_LABEL: Record<CostSource | 'free', string> = {
  free: msg('aucune requête'),
  fixed: msg('exactement 1'),
  reference: msg('mesuré le {date}'),
  dns: msg('lu dans le DNS à l’instant'),
  estimated: msg('estimé : 1 pour l’include, inconnu au-delà'),
};

const refDate = COSTS_MEASURED_ON.split('-').reverse().join('/');

export default function GenSpfPage() {
  const { authenticated, loading: authLoading } = useAuth();
  const [domain, setDomain] = useParam('domaine');
  const [params, setParams] = useSearchParams();
  const fromUrl = useRef(fromParams(params));
  const [st, setSt] = useState<GenState>(() => fromUrl.current ?? initialState());
  const [prefill, setPrefill] = useState<PrefillState>({ kind: 'off' });
  const [published, setPublished] = useState<string | null | undefined>(undefined);
  const [ipText, setIpText] = useState('');
  const [ipErr, setIpErr] = useState<string | null>(null);

  const built = useMemo(() => build(st), [st]);
  useCopyShortcut(built.record, t('SPF copié'));

  // DNS prefill, only when signed in; a composition carried by the URL wins the first time.
  useEffect(() => {
    if (!domain) {
      setPrefill({ kind: 'off' });
      setPublished(undefined);
      return;
    }
    pushRecent({ value: domain, path: `/generateurs/spf?domaine=${domain}`, label: msg('Générateur SPF') });
    if (authLoading) return;
    if (!authenticated) {
      setPrefill({ kind: 'anonymous' });
      return;
    }
    const keepUrl = fromUrl.current !== null;
    let alive = true;
    setPrefill({ kind: 'loading' });
    Promise.allSettled([
      api<CheckResult<SpfData>>(`/api/spf/${encodeURIComponent(domain)}?historique=0`),
      api<CheckResult<DnsData>>(`/api/dns/${encodeURIComponent(domain)}?type=MX&historique=0`),
    ]).then(([spf, mx]) => {
      if (!alive) return;
      fromUrl.current = null;
      if (spf.status === 'rejected' && mx.status === 'rejected') {
        setPrefill({ kind: 'error', message: errorMessage(spf.reason) });
        return;
      }
      const s = spf.status === 'fulfilled' ? spf.value.data : undefined;
      const hosts = mx.status === 'fulfilled' ? mx.value.data.answers.filter((a) => a.type === 'MX').map((a) => a.value.split(/\s+/).pop() ?? '') : [];
      setPublished(s?.record ?? null);
      if (!keepUrl) setSt(fromDns(s?.record, s?.tree?.terms, hosts));
      const what = [s?.record ? t('SPF publié') : t('aucun SPF publié'), hosts.length ? t('{n} MX', { n: hosts.length }) : t('aucun MX')].join(', ');
      setPrefill({ kind: 'done', at: spf.status === 'fulfilled' ? spf.value.measuredAt : new Date().toISOString(), what });
    });
    return () => {
      alive = false;
    };
  }, [domain, authenticated, authLoading]);

  // URL mirrors the composition (shareable, survives a reload)
  useEffect(() => {
    const want = toParams(st);
    const n = new URLSearchParams(params);
    for (const k of STATE_PARAMS) n.delete(k);
    for (const [k, v] of Object.entries(want)) n.set(k, v);
    if (n.toString() !== params.toString()) setParams(n, { replace: true });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [st]);

  const update = (f: (s: GenState) => GenState) => setSt((s) => f(s));
  const setSel = (key: string, patch: Partial<Sel>) =>
    update((s) => ({ ...s, sels: s.sels.map((x) => (x.key === key ? { ...x, ...patch } : x)) }));
  const toggleProvider = (key: string) =>
    update((s) => {
      const ex = s.sels.find((x) => x.key === key);
      if (ex) return { ...s, noMail: false, sels: s.sels.map((x) => (x.key === key ? { ...x, on: !x.on } : x)) };
      return { ...s, noMail: false, sels: [...s.sels, { key, on: true, via: 'user' }] };
    });

  const measureInclude = async (target: string) => {
    if (!authenticated) return;
    try {
      const r = await api<CheckResult<SpfData>>(`/api/spf/${encodeURIComponent(target)}?historique=0`);
      if (typeof r.data.lookupCount === 'number' && r.data.record) {
        const cost = 1 + r.data.lookupCount;
        update((s) => ({ ...s, custom: s.custom.map((c) => (c.domain === target ? { ...c, cost, source: 'dns' } : c)) }));
      }
    } catch {
      /* stays estimated */
    }
  };
  const addInclude = (target: string) => {
    update((s) => (s.custom.some((c) => c.domain === target) ? s : { ...s, noMail: false, custom: [...s.custom, { domain: target, cost: 1, source: 'estimated' }] }));
    void measureInclude(target);
  };
  const addIps = (raw: string) => {
    const r = parseIpInput(raw);
    if (r.errors.length) setIpErr(t('Non reconnu : {list}. Attendu : une IPv4, une IPv6 ou une plage (203.0.113.0/24).', { list: r.errors.join(', ') }));
    else setIpErr(null);
    if (r.ip4.length || r.ip6.length)
      update((s) => ({ ...s, noMail: false, ip4: [...new Set([...s.ip4, ...r.ip4])], ip6: [...new Set([...s.ip6, ...r.ip6])] }));
    setIpText(r.errors.join(' '));
  };

  const shownKeys = new Set(st.sels.map((s) => s.key));
  const frequent = FREQUENT.filter((k) => !shownKeys.has(k));
  const selectedOn = new Set(st.sels.filter((s) => s.on).map((s) => s.key));
  const broad = parseIpInput([...st.ip4, ...st.ip6].join(' ')).broad;
  const name = domain || t('votre-domaine.fr');
  const parts = splitTxt(built.record);
  const estimatedTerms = built.terms.filter((t) => t.source === 'estimated');

  const tone = built.overLimit ? 'bad' : built.lookups >= 9 ? 'watch' : undefined;
  return (
    <GenLayout
      title={t('Générateur SPF')}
      desc={t("Cochez vos services d'envoi : l'enregistrement se compose en direct, requêtes DNS comptées (limite {limit}).", { limit: SPF_LOOKUP_LIMIT })}
      aside={
      <RecordPanel
        name={name}
        value={built.record}
        copyWhat={t('SPF copié')}
        tone={tone}
        nameHint={domain ? t('à la racine (@), à la place de tout SPF existant : un seul par domaine') : t('saisissez le domaine pour le nom exact')}
        pills={[
          {
            label: built.estimated
              ? tn(built.lookups, '{n} requête DNS (estimé) sur {limit}', '{n} requêtes DNS (estimé) sur {limit}', { limit: SPF_LOOKUP_LIMIT })
              : tn(built.lookups, '{n} requête DNS sur {limit}', '{n} requêtes DNS sur {limit}', { limit: SPF_LOOKUP_LIMIT }),
            tone: built.overLimit ? 'bad' : built.lookups >= 9 ? 'watch' : 'good',
          },
          { label: built.redirect ? `redirect=${built.redirect}` : t('règle finale {q}all', { q: st.noMail ? '-' : st.all }) },
          { label: parts.length > 1 ? t('{n} caractères, {parts} chaînes', { n: built.record.length, parts: parts.length }) : t('{n} caractères', { n: built.record.length }) },
        ]}
        actions={
          domain ? (
            <Link className="btn btn--ghost" to={`/spf/${encodeURIComponent(domain)}`}>
              {t('Contrôler le SPF publié')}
            </Link>
          ) : undefined
        }
      >
        {built.overLimit && (
          <div className="stack-sm">
            <Notice tone="error" title={t('{n} requêtes : le SPF entier échouerait', { n: built.lookups })}>
              {rich(
                "Au-delà de {limit}, les destinataires renvoient permerror. Les plus coûteux : {costly}. Retirez un service qui n'envoie plus, remplacez a et mx par des ip4:, ou faites aplatir cet enregistrement par <spf>l'analyse SPF</spf>, qui propose une version aplatie. Source : <rfc>RFC 7208 §4.6.4</rfc>.",
                { limit: SPF_LOOKUP_LIMIT, costly: [...built.terms].sort((a, b) => b.cost - a.cost).slice(0, 3).map((x) => `${x.term} (${x.cost})`).join(', ') },
                {
                  spf: (c) => (domain ? <Link to={`/spf/${encodeURIComponent(domain)}?enregistrement=${encodeURIComponent(built.record)}`}>{c}</Link> : c),
                  rfc: (c) => <a href="https://www.rfc-editor.org/rfc/rfc7208#section-4.6.4" target="_blank" rel="noreferrer noopener">{c}</a>,
                },
              )}
            </Notice>
            {(st.a || st.mx) && (() => {
              const alt = build({ ...st, a: false, mx: false });
              return (
                <div className="stack-sm" style={{ paddingTop: 'var(--s2)' }}>
                  <CodeBlock code={alt.record} label={tn(alt.lookups, 'Sans a ni mx : {n} requête', 'Sans a ni mx : {n} requêtes')} tone={alt.overLimit ? undefined : 'suggested'} />
                  <div>
                    <button type="button" className="btn btn--sm" onClick={() => update((s) => ({ ...s, a: false, mx: false }))}>
                      {t('Retirer a et mx')}
                    </button>
                  </div>
                </div>
              );
            })()}
          </div>
        )}
        {estimatedTerms.length > 0 && (
          <p className="field__hint">
            {estimatedTerms.length > 1
              ? t('Estimé : {terms} comptent 1 requête chacun ; leurs propres include ne sont pas connus{end}', { terms: estimatedTerms.map((x) => x.term).join(', '), end: authenticated ? '.' : t(' sans session (connecté, TestAndFix les mesure).') })
              : t('Estimé : {terms} compte 1 requête chacun ; leurs propres include ne sont pas connus{end}', { terms: estimatedTerms.map((x) => x.term).join(', '), end: authenticated ? '.' : t(' sans session (connecté, TestAndFix les mesure).') })}
          </p>
        )}
      </RecordPanel>
      }
      dock={<MobileDock value={built.record} what={t('SPF copié')} status={<span className={`tag ${built.overLimit ? 'tag--out' : ''}`}>{built.lookups}/10</span>} />}
    >
      <div className="gen-card surface">
        <DomainField value={domain} onCommit={(d) => { fromUrl.current = null; setDomain(d || null); }} />
        {domain && <PrefillNote state={prefill} domain={domain} />}
      </div>

      {(published || published === null || st.notes.length > 0) && (
        <div className="gen-block">
          {published && <CodeBlock code={published} label={t("SPF publié aujourd'hui sur {domain}", { domain })} />}
          {published === null && <p className="field__hint">{t('Aucun SPF publié sur {domain} : celui-ci sera le premier.', { domain })}</p>}
          {st.notes.length > 0 && (
            <ul className="field__hint" style={{ margin: 0, paddingLeft: '1.1rem' }}>
              {st.notes.map((n) => (
                <li key={n}>{n}</li>
              ))}
            </ul>
          )}
        </div>
      )}

      <div className="gen-cards">
          <Block title={t("Services d'envoi")} aside={<span className="tag">{tn(st.sels.filter((x) => x.on).length + st.custom.length, '{n} retenu', '{n} retenus')}</span>}>
            <div className="gen-card__body">
              {st.sels.length > 0 && (
                <div className="chips" aria-label={t('Services retenus')}>
                  {st.sels.map((s) => {
                    const p = providerByKey(s.key)!;
                    const cost = selIncludes({ ...s, on: true }).reduce((n, i) => n + i.cost, 0);
                    return (
                      <button
                        key={s.key}
                        type="button"
                        className="chip"
                        aria-pressed={s.on}
                        onClick={() => toggleProvider(s.key)}
                        title={s.evidence ? t('Détecté : {evidence}', { evidence: s.evidence }) : undefined}
                      >
                        {s.on && <Check aria-hidden />}
                        {p.name}
                        <span className="gen-chip-cost">{t('{n} req.', { n: p.include || p.accountInclude ? cost : 0 })}</span>
                      </button>
                    );
                  })}
                </div>
              )}
              {st.sels.some((s) => s.via !== 'user') && (
                <p className="field__hint">
                  {t("Cochés d'office : {list}. Un clic décoche.", { list: st.sels.filter((s) => s.via !== 'user').map((s) => `${providerByKey(s.key)!.name} (${s.evidence})`).join(' ; ') })}
                </p>
              )}
              {frequent.length > 0 && (
                <div className="stack-sm">
                  <span className="field__hint">{t('Fréquents')}</span>
                  <div className="chips">
                    {frequent.map((k) => {
                      const p = providerByKey(k)!;
                      return (
                        <button key={k} type="button" className="chip" aria-pressed={false} onClick={() => toggleProvider(k)}>
                          <Plus aria-hidden />
                          {p.name}
                          <span className="gen-chip-cost">{t('{n} req.', { n: p.cost ?? 0 })}</span>
                        </button>
                      );
                    })}
                  </div>
                </div>
              )}
              <ProviderSearch selected={selectedOn} onProvider={(k) => (shownKeys.has(k) ? setSel(k, { on: true }) : toggleProvider(k))} onInclude={addInclude} />

              {st.sels.filter((s) => s.on).map((s) => {
                const p = providerByKey(s.key)!;
                if (!p.elsewhere && !p.note && !p.accountInclude && !p.extra) return null;
                return (
                  <div key={s.key} className="stack-sm" style={{ fontSize: 'var(--fs-sm)' }}>
                    <div>
                      <strong>{p.name}</strong>
                      {p.elsewhere && !s.forced && <span className="tag" style={{ marginLeft: 'var(--s2)' }}>{t('rien dans ce SPF')}</span>}
                    </div>
                    {(p.elsewhere || p.note) && <p className="muted">{t((p.elsewhere ?? p.note)!)}</p>}
                    {p.elsewhere && p.include && (
                      <label className="gen-check">
                        <input type="checkbox" checked={!!s.forced} onChange={(e) => setSel(s.key, { forced: e.target.checked })} />
                        <span>
                          {rich("Ce domaine est bien celui d'envoi : ajouter <m>include:{include}</m> ({cost})", { include: p.include, cost: tn(p.cost ?? 1, '{n} requête', '{n} requêtes') }, { m: (c) => <span className="mono">{c}</span> })}
                        </span>
                      </label>
                    )}
                    {p.extra && (
                      <label className="gen-check">
                        <input type="checkbox" checked={!!s.extra} onChange={(e) => setSel(s.key, { extra: e.target.checked })} />
                        <span>
                          {rich('{label} : <m>include:{include}</m> ({n} requêtes)', { label: t(p.extra.label), include: p.extra.include, n: p.extra.cost }, { m: (c) => <span className="mono">{c}</span> })}
                        </span>
                      </label>
                    )}
                    {p.accountInclude && (
                      <Field
                        label={t('Include de votre compte {name}', { name: p.name })}
                        hint={t(p.accountInclude.hint)}
                        error={s.account && !p.accountInclude.pattern.test(s.account.replace(/^include:/i, '').trim()) ? t('Forme attendue : {placeholder}', { placeholder: p.accountInclude.placeholder }) : null}
                      >
                        {(id, d) => (
                          <input id={id} aria-describedby={d} className="input input--mono" placeholder={p.accountInclude!.placeholder} value={s.account ?? ''}
                            onChange={(e) => setSel(s.key, { account: e.target.value.replace(/^include:/i, '').trim(), dnsCost: undefined })} />
                        )}
                      </Field>
                    )}
                  </div>
                );
              })}

              {st.custom.length > 0 && (
                <div className="stack-sm">
                  <span className="field__hint">{t('Includes hors catalogue')}</span>
                  <div className="chips">
                    {st.custom.map((c) => (
                      <span key={c.domain} className="chip mono gen-on">
                        include:{c.domain}
                        <span className="gen-chip-cost">{t('{n} req.', { n: c.source === 'estimated' ? `≥ ${c.cost}` : c.cost })}</span>
                        <button type="button" className="gen-chip-x" aria-label={t('Retirer include:{domain}', { domain: c.domain })} onClick={() => update((s) => ({ ...s, custom: s.custom.filter((x) => x.domain !== c.domain) }))}>
                          <X size={12} aria-hidden />
                        </button>
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </Block>

          <Block title={t('Vos propres serveurs')}>
            <div className="gen-card__body">
              <form
                className="gen-row"
                onSubmit={(e) => {
                  e.preventDefault();
                  addIps(ipText);
                }}
              >
                <Field label={t('Adresses IP à autoriser')} hint={t('IPv4, IPv6 ou plage, plusieurs à la fois séparées par des espaces. Aucune requête DNS.')} error={ipErr}>
                  {(id, d) => (
                    <input id={id} aria-describedby={d} className="input input--mono" value={ipText} placeholder="203.0.113.10 2001:db8::25"
                      onChange={(e) => setIpText(e.target.value)}
                      onPaste={(e) => {
                        const t = e.clipboardData.getData('text');
                        if (/[\s,;]/.test(t.trim())) {
                          e.preventDefault();
                          addIps(t);
                        }
                      }}
                      onBlur={(e) => e.target.value.trim() && addIps(e.target.value)} />
                  )}
                </Field>
                <button type="submit" className="btn" style={{ marginBottom: ipErr ? '1.4rem' : '1.35rem' }}>
                  <Plus aria-hidden /> {t('Ajouter')}
                </button>
              </form>
              {st.ip4.length + st.ip6.length > 0 && (
                <div className="chips" aria-label={t('Adresses autorisées')}>
                  {[...st.ip4.map((v) => ['ip4', v]), ...st.ip6.map((v) => ['ip6', v])].map(([k, v]) => (
                    <span key={v} className="chip mono gen-on">
                      {k}:{v}
                      <button type="button" className="gen-chip-x" aria-label={t('Retirer {value}', { value: v })}
                        onClick={() => update((s) => ({ ...s, ip4: s.ip4.filter((x) => x !== v), ip6: s.ip6.filter((x) => x !== v) }))}>
                        <X size={12} aria-hidden />
                      </button>
                    </span>
                  ))}
                </div>
              )}
              {broad.length > 0 && (
                <Notice tone="warn" title={t('Plage très large')}>
                  {t("{list} : des milliers d'adresses que vous ne contrôlez pas pourraient envoyer en votre nom. Limitez-vous à vos serveurs (une IPv4 seule s'écrit sans /32), ou utilisez l'include officiel du service.", { list: broad.join(', ') })}
                </Notice>
              )}
              <label className="gen-check">
                <input type="checkbox" checked={st.a} onChange={(e) => update((s) => ({ ...s, a: e.target.checked, noMail: false }))} />
                <span>
                  {rich('<m>a</m> : le serveur de {domain} (adresse du site) envoie aussi. 1 requête.', { domain: domain || t('votre domaine') }, { m: (c) => <span className="mono">{c}</span> })}
                </span>
              </label>
              <label className="gen-check">
                <input type="checkbox" checked={st.mx} onChange={(e) => update((s) => ({ ...s, mx: e.target.checked, noMail: false }))} />
                <span>
                  {rich('<m>mx</m> : vos serveurs de réception envoient aussi. 1 requête ; inutile chez la plupart des fournisseurs, qui ont leur include.', undefined, { m: (c) => <span className="mono">{c}</span> })}
                </span>
              </label>
              {st.others.length > 0 && (
                <div className="stack-sm">
                  <span className="field__hint">{t("Termes repris de l'enregistrement publié")}</span>
                  <div className="chips">
                    {st.others.map((o) => (
                      <span key={o} className="chip mono gen-on">
                        {o}
                        <span className="gen-chip-cost">{t('{n} req.', { n: rawTermCost(o) })}</span>
                        <button type="button" className="gen-chip-x" aria-label={t('Retirer {value}', { value: o })} onClick={() => update((s) => ({ ...s, others: s.others.filter((x) => x !== o) }))}>
                          <X size={12} aria-hidden />
                        </button>
                      </span>
                    ))}
                  </div>
                  {st.others.some((o) => /^[+~?-]?ptr/i.test(o)) && (
                    <p className="field__hint out-text">{t('ptr est à proscrire (RFC 7208 §5.5) : lent, ignoré par certains destinataires. Remplacez-le par les ip4: des serveurs.')}</p>
                  )}
                </div>
              )}
            </div>
          </Block>

          <Block title={t('Règle finale')}>
            <div className="gen-card__body">
              <Segmented
                label={t('Pour toute autre adresse')}
                value={st.noMail ? '-' : st.all}
                onChange={(v) => update((s) => ({ ...s, all: v, noMail: false }))}
                options={[
                  { value: '~', label: <span className="mono">~all</span>, recommended: true, title: t('Échec souple') },
                  { value: '-', label: <span className="mono">-all</span>, title: t('Rejet') },
                ]}
                hint={
                  st.all === '~'
                    ? t('Échec souple : le message est marqué, la décision revient au DMARC. Passez à -all quand vous êtes sûr que tous vos services sont listés.')
                    : t('Rejet : certains destinataires refusent dès la commande MAIL FROM (RFC 7208 §8.4). À réserver à une liste de services complète.')
                }
              />
              {built.redirect && <p className="field__hint">{t('redirect={redirect} est gardé : la règle finale est alors celle de {redirect}.', { redirect: built.redirect })}</p>}
              <label className="gen-check">
                <input type="checkbox" checked={st.noMail} onChange={(e) => update((s) => ({ ...s, noMail: e.target.checked }))} />
                <span>
                  {rich("{domain} n'envoie jamais de courrier : publier <m>v=spf1 -all</m> (RFC 7505 §4.2), avec un DMARC p=reject.", { domain: domain || t('Ce domaine') }, { m: (c) => <span className="mono">{c}</span> })}
                </span>
              </label>
            </div>
          </Block>
      </div>

      <Details title={t('Détail du compte, terme par terme')} count={tn(built.terms.length, '{n} terme', '{n} termes')}>
        <CompactTable columns={[t('Terme'), t('Requêtes'), t('Source'), '']}>
          {built.terms.map((x: BuiltTerm) => (
            <LabRow key={x.term} label={<span className="mono">{x.term}</span>} measured={x.cost} reference={<span className="gen-src">{t(SOURCE_LABEL[x.source], { date: refDate })}</span>} deviation={{ kind: 'info', text: x.cost ? String(x.cost) : '0' }} />
          ))}
        </CompactTable>
        <p className="field__hint" style={{ marginTop: 'var(--s3)' }}>
          {rich("Coût d'un include officiel : 1 pour lui-même et les requêtes de son propre SPF, mesurés par TestAndFix le {date}. Un fournisseur qui modifie son SPF change ce chiffre : vérifiez après publication. Touche <k>C</k> : copier l'enregistrement.", { date: refDate }, { k: (c) => <kbd>{c}</kbd> })}
        </p>
      </Details>
    </GenLayout>
  );
}
