// DKIM: automatic discovery over the common selectors, one row per key found (bits measured
// against 2048, provider from the CNAME, flags), selectors added by hand remembered per domain.
import { useEffect, useId, useMemo, useState } from 'react';
import { useParams, useSearchParams } from 'react-router';
import { Plus, X } from 'lucide-react';
import { providerName } from '../../components/Report';
import { Details } from '../../components/Verdict';
import { CodeBlock, Notice } from '../../components/ui';
import { toDomain } from '../../lib/detect';
import { fmtInt, plural } from '../../lib/format';
import { rich, t } from '../../lib/i18n';
import type { CheckResult } from '../../lib/types';
import { useCheck } from '../../lib/useCheck';
import { MetricTable } from '../domain/MetricTable';
import { PastedRecord, ReportFrame, SeeAlso, ToolEmpty, useRecent } from '../domain/common';
import type { DkimData, DkimKey } from '../domain/model';
import { keyMetric, type Metric } from '../domain/rows';
import { WeakKeyLink } from '../domain/WeakKeyLink';
import { forget, parseSelectors, remember, rememberedElsewhere, rememberedFor } from './selectors';

function KeyExtra({ k, domain }: { k: DkimKey; domain: string }) {
  return (
    <div className="stack-sm">
      <WeakKeyLink k={k} domain={domain} />
      <CodeBlock code={k.record} label={t('TXT de {name}', { name: k.name })} />
      <dl className="report-head__meta" style={{ marginTop: 0 }}>
        {k.cnames.length > 0 && (
          <div>
            <dt>CNAME</dt>
            <dd>{[k.name, ...k.cnames].join(' → ')}</dd>
          </div>
        )}
        {k.hashAlgorithms?.length ? (
          <div>
            <dt>{t('Hachage (h=)')}</dt>
            <dd>{k.hashAlgorithms.join(', ')}</dd>
          </div>
        ) : null}
        {k.serviceTypes?.length ? (
          <div>
            <dt>{t('Service (s=)')}</dt>
            <dd>{k.serviceTypes.join(', ')}</dd>
          </div>
        ) : null}
        {k.ttl !== undefined && (
          <div>
            <dt>TTL</dt>
            <dd>{fmtInt(k.ttl)} s</dd>
          </div>
        )}
      </dl>
      {k.notes && <p className="field__hint">{k.notes}</p>}
      {k.wildcard && <p className="field__hint">{t('Le domaine répond à n’importe quel sélecteur : cette clé est peut-être un joker, pas une vraie clé.')}</p>}
    </div>
  );
}

function AddSelectors({
  domain,
  tried,
  added,
  remembered,
  onAdd,
  onRemove,
}: {
  domain: string;
  tried: string[];
  added: string[];
  remembered: string[];
  onAdd: (s: string[]) => void;
  onRemove: (s: string) => void;
}) {
  const [value, setValue] = useState('');
  const [error, setError] = useState<string | null>(null);
  const listId = useId();
  const elsewhere = useMemo(() => rememberedElsewhere(domain).filter((e) => !added.includes(e.selector) && !remembered.includes(e.selector)), [domain, added, remembered]);
  const submit = (raw: string) => {
    const s = parseSelectors(raw);
    if (!s.length) {
      setError(t('Aucun sélecteur reconnu. Exemple : s1, ou un en-tête DKIM-Signature entier (sa balise s= est lue).'));
      return;
    }
    setError(null);
    setValue('');
    onAdd(s);
  };
  const mine = [...new Set([...remembered, ...added])];
  return (
    <div className="dm-selectors">
      <form
        className="page-form"
        onSubmit={(e) => {
          e.preventDefault();
          submit(value);
        }}
      >
        <div className="field">
          <label className="field__label" htmlFor={`${listId}-in`}>
            {t('Sélecteurs à ajouter')}
          </label>
          <input
            id={`${listId}-in`}
            className="input input--mono"
            list={listId}
            value={value}
            onChange={(e) => setValue(e.target.value)}
            placeholder="s2024, s2025"
            spellCheck={false}
            autoCapitalize="off"
            autoComplete="off"
            aria-describedby={`${listId}-hint`}
          />
          <datalist id={listId}>
            {elsewhere.map((e) => (
              <option key={`e-${e.selector}`} value={e.selector}>
                {t('ajouté pour {domain}', { domain: e.domain })}
              </option>
            ))}
            {tried.map((s) => (
              <option key={s} value={s}>
                {t('essayé d’office')}
              </option>
            ))}
          </datalist>
          {error ? (
            <span className="field__error" role="alert">
              {error}
            </span>
          ) : (
            <span className="field__hint" id={`${listId}-hint`}>
              {t('Le sélecteur est la balise s= de l’en-tête DKIM-Signature d’un message envoyé. Plusieurs à la fois : séparez-les par une virgule. Ils sont retenus pour ce domaine.')}
            </span>
          )}
        </div>
        <button type="submit" className="btn btn--primary">
          <Plus aria-hidden />
          {t('Ajouter et mesurer')}
        </button>
      </form>
      {mine.length > 0 && (
        <div className="chips" aria-label={t('Sélecteurs ajoutés pour ce domaine')}>
          {mine.map((s) => (
            <button key={s} type="button" className="chip mono dm-chip-remove" onClick={() => onRemove(s)} aria-label={t('Retirer le sélecteur {selector}', { selector: s })}>
              {s}
              <X aria-hidden />
            </button>
          ))}
        </div>
      )}
      {elsewhere.length > 0 && (
        <div className="chips" aria-label={t('Sélecteurs ajoutés pour d’autres domaines')}>
          <span className="field__hint" style={{ alignSelf: 'center' }}>
            {t('Déjà utilisés ailleurs :')}
          </span>
          {elsewhere.slice(0, 6).map((e) => (
            <button key={e.selector} type="button" className="chip mono" onClick={() => onAdd([e.selector])} title={t('ajouté pour {domain}', { domain: e.domain })}>
              <Plus aria-hidden />
              {e.selector}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

export default function DkimPage() {
  const { domain: raw } = useParams();
  const [params, setParams] = useSearchParams();
  const domain = raw ? toDomain(raw) : undefined;
  const focus = params.get('selecteur')?.trim().toLowerCase() || undefined;
  const added = useMemo(() => parseSelectors(params.get('selecteurs') ?? ''), [params]);
  const [remembered, setRemembered] = useState<string[]>([]);
  useEffect(() => setRemembered(domain ? rememberedFor(domain) : []), [domain]);
  const extra = [...new Set([...(focus ? [focus] : []), ...added, ...remembered])];
  const url = domain ? `/api/dkim/${encodeURIComponent(domain)}${extra.length ? `?selectors=${encodeURIComponent(extra.join(','))}` : ''}` : null;
  const { data: r, error, loading, rerun } = useCheck<CheckResult<DkimData>>(url);
  useRecent(domain, `/dkim/${domain}`, 'DKIM');

  if (!domain) {
    const record = params.get('enregistrement');
    return (
      <ToolEmpty
        title="DKIM"
        desc={t('Découverte automatique des clés sur une centaine de sélecteurs courants, taille réelle de chaque clé, fournisseur reconnu par son CNAME.')}
        basePath="/dkim"
        examples={[
          { domain: 'cnn.com', why: t('dix clés, dont trois de 1024 bits et un CNAME cassé') },
        ]}
      >
        {raw && <Notice tone="error" title={t('« {raw} » n’est pas un nom de domaine', { raw })}>{t('Saisissez un nom comme exemple.fr.')}</Notice>}
        {record && <PastedRecord record={record} kind="DKIM" basePath="/dkim" />}
      </ToolEmpty>
    );
  }

  const add = (s: string[]) => {
    remember(domain, s);
    setRemembered(rememberedFor(domain));
    const next = new URLSearchParams(params);
    next.set('selecteurs', [...new Set([...added, ...s])].join(','));
    setParams(next, { replace: true });
  };
  const removeSel = (s: string) => {
    forget(domain, s);
    setRemembered(rememberedFor(domain));
    const next = new URLSearchParams(params);
    const left = added.filter((x) => x !== s);
    if (left.length) next.set('selecteurs', left.join(','));
    else next.delete('selecteurs');
    if (focus === s) next.delete('selecteur');
    setParams(next, { replace: true });
  };

  return (
    <ReportFrame
      domain={domain}
      r={r}
      loading={loading}
      error={error}
      rerun={rerun}
      facts={(r) => {
        const bits = r.data.keys.filter((k) => k.keyType === 'rsa' && k.bits).map((k) => k.bits!);
        return [
          { label: t('Clés trouvées'), value: fmtInt(r.data.keys.length) },
          ...(bits.length ? [{ label: t('Plus petite clé RSA'), value: t('{n} bits', { n: Math.min(...bits) }) }] : []),
          { label: t('Sélecteurs essayés'), value: fmtInt(r.data.tried) },
        ];
      }}
      issueExtra={(f, r) => {
        if (!/^dkim\.key_(1024|below_1024)$/.test(f.id)) return null;
        const k = r.data.keys.find((x) => (f.evidence ?? '').includes(x.name));
        return k ? <WeakKeyLink k={k} domain={domain} /> : null;
      }}
      afterIssues={(r) => (
        <section className="block" aria-labelledby="add-t">
          <h2 className="block__title" id="add-t">
            {r.data.keys.length ? t('Une clé manque ? Ajoutez son sélecteur') : t('Aucune clé trouvée : ajoutez le sélecteur')}
          </h2>
          <div className="issue">
            <AddSelectors domain={domain} tried={r.data.selectorsTried} added={added} remembered={remembered} onAdd={add} onRemove={removeSel} />
          </div>
        </section>
      )}
    >
      {(r) => {
        const d = r.data;
        const rows: Metric[] = d.keys.map((k) => keyMetric(k, providerName));
        const missing = extra.filter((s) => !d.keys.some((k) => k.selector === s));
        for (const s of missing)
          rows.push({
            key: `missing-${s}`, label: s, mono: true, sub: s === focus ? t('sélecteur demandé') : t('ajouté à la main'),
            measured: t('aucune clé publiée'), reference: t('clé DKIM'), dev: { kind: 'out', text: t('absente'), direction: 'down' },
          });
        const extraRows = Object.fromEntries(d.keys.map((k) => [`key-${k.selector}`, <KeyExtra key={k.selector} k={k} domain={domain} />]));
        return (
          <>
            {d.wildcard && (
              <Notice tone="warn" title={t('Le domaine répond à n’importe quel sélecteur')}>
                {t('Une clé est publiée en joker (*._domainkey) : les clés listées peuvent ne pas être utilisées pour signer.')}
              </Notice>
            )}
            {(d.errors.length > 0 || d.other.length > 0) && (
              <Notice tone="warn" title={t('Réponses à vérifier')}>
                <ul style={{ margin: 0, paddingLeft: '1.1rem' }}>
                  {d.errors.map((e) => (
                    <li key={`e-${e.selector}`}>
                      {rich('<m>{selector}</m> : requête en échec ({error}), la clé n’a pas pu être lue.', { selector: e.selector, error: e.error }, { m: (c) => <span className="mono">{c}</span> })}
                    </li>
                  ))}
                  {d.other.map((o) => (
                    <li key={`o-${o.selector}`}>
                      {rich('<m>{selector}</m> répond, mais pas avec une clé DKIM : <m>{record}</m>', { selector: o.selector, record: o.record.slice(0, 80) }, { m: (c) => <span className="mono">{c}</span> })}
                    </li>
                  ))}
                </ul>
              </Notice>
            )}
            {rows.length > 0 && (
              <Details title={t('Clés publiées')} count={plural(d.keys.length, 'clé', 'clés')} defaultOpen>
                <MetricTable rows={rows} extra={extraRows} sort openKey={focus ? (d.keys.some((k) => k.selector === focus) ? `key-${focus}` : `missing-${focus}`) : undefined} />
              </Details>
            )}
            <Details title={t('Ce que la découverte ne peut pas trouver')} count={plural(d.selectorsTried.length, 'sélecteur essayé', 'sélecteurs essayés')} defaultOpen={!d.keys.length}>
              <ul className="dm-limits">
                {d.limits.map((l, i) => (
                  <li key={i}>{l}</li>
                ))}
              </ul>
              <p className="mono dm-tried" style={{ marginTop: 'var(--s3)' }}>{d.selectorsTried.join(' · ')}</p>
            </Details>
            <SeeAlso
              links={[
                { to: `/domaine/${domain}`, label: t('Scanner {domain}', { domain }) },
                { to: `/generateurs/dkim?domaine=${encodeURIComponent(domain)}`, label: t('Générer une clé de 2048 bits') },
                { to: `/dmarc/${domain}`, label: 'DMARC' },
              ]}
            />
          </>
        );
      }}
    </ReportFrame>
  );
}
