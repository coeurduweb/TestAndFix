import { useEffect, useState } from 'react';
import { Navigate, useParams, useSearchParams } from 'react-router';
import { toDomain } from '../../lib/detect';
import { ShieldCheck } from 'lucide-react';
import { ToolHero } from '../../components/ToolHero';
import { Details, IssueList } from '../../components/Verdict';
import {
  LabRow, LabTable, MeasuredMeta, providerName, ReportHeader, RerunButton, ShareButton, Unavailable,
} from '../../components/Report';
import { CodeBlock, Field, Notice, Skel, SubmitButton } from '../../components/ui';
import { get } from '../../lib/api';
import { msg, t, tn } from '../../lib/i18n';
import { pushRecent } from '../../lib/recent';
import type { CheckResult } from '../../lib/types';
import { errorMessage, useCheck } from '../../lib/useCheck';
import '../domain/domain.css';

interface SpfTermNode {
  term: string;
  mechanism: string;
  qualifier?: string;
  kind: string;
  target?: string;
  lookups: number;
  voids: number;
  cumulative?: number;
  overLimit?: boolean;
  networks?: string[];
  child?: SpfNode;
  error?: string;
  note?: string;
}
interface SpfNode {
  domain: string;
  record?: string;
  records: string[];
  status: string;
  error?: string;
  terms: SpfTermNode[];
}
interface SpfData {
  domain: string;
  record?: string;
  records: string[];
  source: 'dns' | 'input';
  tree: SpfNode;
  lookupCount: number;
  voidCount: number;
  lookupLimit: number;
  voidLimit: number;
  ipv4: string[];
  ipv6: string[];
  dynamic: string[];
  allQualifier?: string;
  includes?: string[];
  providers: string[];
  responseSize: number;
  suggested?: string;
  suggestedSplit?: string;
  suggestedLookupCount?: number;
}
interface EvalResult {
  ip: string;
  result: string;
  reason?: string;
  mechanism?: { term: string; domain: string };
  chain?: { term: string; domain: string }[];
  lookups: number;
}

const ALL_MEANING: Record<string, string> = {
  '-': msg('-all (rejet)'),
  '~': msg('~all (échec souple)'),
  '?': msg('?all (neutre)'),
  '+': msg('+all (tout autorisé)'),
};

const allMeaning = (q: string) => (ALL_MEANING[q] ? t(ALL_MEANING[q]) : q);
const isLeafNet = (x: SpfTermNode) => (x.mechanism === 'ip4' || x.mechanism === 'ip6') && !x.error;

function Tree({ node, depth = 0 }: { node: SpfNode; depth?: number }) {
  const nets = node.terms.filter(isLeafNet);
  const shown = depth > 0 ? node.terms.filter((x) => !isLeafNet(x) && x.mechanism !== 'all') : node.terms;
  return (
    <ul className="spf-tree" style={{ listStyle: 'none', margin: 0, paddingLeft: depth ? 'var(--s4)' : 0, borderLeft: depth ? '1px solid var(--rule)' : 0 }}>
      {depth === 0 && (
        <li className="mono" style={{ fontSize: 'var(--fs-sm)', padding: '0.2rem 0', fontWeight: 650 }}>
          {node.domain}
        </li>
      )}
      {depth > 0 && nets.length > 0 && (
        <li className="muted" style={{ fontSize: 'var(--fs-xs)', padding: '0.15rem 0' }}>
          <details>
            <summary style={{ cursor: 'pointer' }}>
              {tn(nets.length, "{n} plage d'adresses", "{n} plages d'adresses")}
            </summary>
            <code style={{ display: 'block', whiteSpace: 'pre-wrap', paddingTop: 'var(--s1)' }}>{nets.map((n) => n.term).join('  ')}</code>
          </details>
        </li>
      )}
      {shown.map((x, i) => (
        <li key={i} style={{ padding: '0.15rem 0' }}>
          <div style={{ display: 'flex', gap: 'var(--s3)', alignItems: 'baseline', flexWrap: 'wrap' }}>
            <code style={{ color: x.overLimit || x.error ? 'var(--out)' : 'var(--ink)', fontWeight: x.overLimit ? 700 : 450 }}>{x.term}</code>
            {x.lookups > 0 && (
              <span className="muted mono" style={{ fontSize: 'var(--fs-xs)' }}>
                {tn(x.lookups, '{n} requête', '{n} requêtes')}
                {x.cumulative !== undefined && ' · ' + t('total {n}', { n: x.cumulative })}
              </span>
            )}
            {x.overLimit && <span className="tag tag--out">{t('dépasse 10')}</span>}
            {x.voids > 0 && <span className="tag tag--warn">{t('réponse vide')}</span>}
            {x.error && <span className="out-text" style={{ fontSize: 'var(--fs-xs)' }}>{x.error}</span>}
            {x.note && <span className="muted" style={{ fontSize: 'var(--fs-xs)' }}>{x.note}</span>}
          </div>
          {x.child && x.child.terms.length > 0 && <Tree node={x.child} depth={depth + 1} />}
          {x.child && x.child.status !== 'ok' && x.child.error && (
            <div className="out-text" style={{ fontSize: 'var(--fs-xs)', paddingLeft: 'var(--s4)' }}>{x.child.error}</div>
          )}
        </li>
      ))}
    </ul>
  );
}

function IpEval({ domain }: { domain: string }) {
  const [ip, setIp] = useState('');
  const [busy, setBusy] = useState(false);
  const [res, setRes] = useState<EvalResult | null>(null);
  const [err, setErr] = useState<string | null>(null);
  return (
    <form
      className="page-form"
      style={{ marginTop: 'var(--s3)', marginBottom: 0 }}
      onSubmit={async (e) => {
        e.preventDefault();
        setBusy(true);
        setErr(null);
        try {
          const r = await get<CheckResult<EvalResult> | EvalResult>(`/api/spf/${encodeURIComponent(domain)}/eval?ip=${encodeURIComponent(ip.trim())}`);
          setRes(('data' in r ? r.data : r) as EvalResult);
        } catch (x) {
          setErr(errorMessage(x));
        } finally {
          setBusy(false);
        }
      }}
    >
      <div style={{ flex: '0 1 22rem' }}>
      <Field label={t("Cette IP a-t-elle le droit d'envoyer ?")} hint={t('IPv4 ou IPv6 du serveur qui envoie')} error={err}>
        {(id, d) => <input id={id} aria-describedby={d} className="input input--mono" value={ip} onChange={(e) => setIp(e.target.value)} placeholder="8.8.8.8" required />}
      </Field>
      </div>
      <SubmitButton busy={busy}>{t('Évaluer')}</SubmitButton>
      {res && (
        <div style={{ flexBasis: '100%' }}>
          <LabTable columns={[t('Évaluation'), t('Résultat'), t('Mécanisme décisif'), '']}>
            <LabRow
              label={<span className="mono">{res.ip}</span>}
              measured={res.result}
              reference={res.mechanism ? `${res.mechanism.term} (${res.mechanism.domain})` : res.reason}
              deviation={res.result === 'pass' ? { kind: 'ok', text: t('autorisée') } : { kind: 'out', text: res.result, direction: 'down' }}
            />
          </LabTable>
        </div>
      )}
    </form>
  );
}

/** The "all" that applies: the root's, or the one of the redirect= target. */
function effectiveAll(node: SpfNode | undefined, depth = 0): { q?: string; via?: string } {
  if (!node || depth > 10) return {};
  const all = node.terms.find((t) => t.mechanism === 'all');
  if (all) return { q: all.qualifier ?? '+', via: depth ? node.domain : undefined };
  const redirect = node.terms.find((t) => t.mechanism === 'redirect');
  return redirect ? effectiveAll(redirect.child, depth + 1) : {};
}

export default function SpfPage() {
  const { domain } = useParams();
  const [params] = useSearchParams();
  const record = params.get('enregistrement');
  // validated in the browser: an invalid name never reaches the server
  const valid = domain ? toDomain(domain) : undefined;
  const url = domain && valid === domain
    ? `/api/spf/${encodeURIComponent(domain)}${record ? `?record=${encodeURIComponent(record)}` : ''}`
    : null;
  const { data: r, error, loading, rerun } = useCheck<CheckResult<SpfData>>(url);

  useEffect(() => {
    if (domain) pushRecent({ value: domain, path: `/spf/${domain}`, label: 'SPF' });
  }, [domain]);

  if (domain && valid && valid !== domain) return <Navigate to={`/spf/${encodeURIComponent(valid)}${record ? `?enregistrement=${encodeURIComponent(record)}` : ''}`} replace />;
  if (domain && !valid) {
    return (
      <>
        <Notice tone="warn" title={t("« {domain} » n'est pas un nom de domaine", { domain })}>{t('Corrigez-le ci-dessous : une URL ou une adresse e-mail marchent aussi.')}</Notice>
        <ToolHero icon={ShieldCheck} title="SPF" desc={t("Qui a le droit d'envoyer des mails au nom de votre domaine ?")} basePath="/spf" examples={['gmail.com', 'github.com']} />
      </>
    );
  }
  if (!domain) {
    return (
      <ToolHero
        icon={ShieldCheck}
        title="SPF"
        desc={t("Qui a le droit d'envoyer des mails au nom de votre domaine ? Arbre des include, limite des 10 requêtes, correction prête à copier.")}
        basePath="/spf"
        examples={['gmail.com', 'github.com', 'microsoft.com']}
      />
    );
  }

  const d = r?.data;
  const eff = d ? (d.allQualifier ? { q: d.allQualifier } : effectiveAll(d.tree)) : {};
  return (
    <div className="dm-report">
      <ReportHeader
        subject={<span className="mono">{domain}</span>}
        meta={
          r && d
            ? [
                { label: t('Requêtes DNS'), value: t('{n} sur {limit}', { n: d.lookupCount, limit: d.lookupLimit }) },
                { label: t('Règle finale'), value: eff.q ? allMeaning(eff.q) : t('absente') },
                ...MeasuredMeta(r),
              ]
            : []
        }
        score={r?.score}
        findings={r?.findings}
        passed={r?.passed}
        pending={loading && !r}
        actions={
          <>
            <RerunButton onClick={rerun} busy={loading} />
            <ShareButton />
          </>
        }
      />
      {error && <Notice tone="error" title={t('Mesure impossible')}>{errorMessage(error)}</Notice>}
      {loading && !r && (
        <div className="issues" aria-busy="true">
          {[0, 1].map((i) => (
            <div key={i} className="issue">
              <Skel w="30%" />
              <Skel w="70%" />
              <Skel w="55%" />
            </div>
          ))}
        </div>
      )}
      {r && d && (
        <>
          {d.suggested && d.suggested !== d.record && (
            <section className="block" aria-labelledby="fix-t">
              <h2 className="block__title" id="fix-t">{t("L'enregistrement corrigé à publier")}</h2>
              <div className="issue">
                <CodeBlock code={d.suggested} label={t('TXT de {domain}', { domain })} tone="suggested" copyLabel={t("Copier l'enregistrement")} />
                {d.suggestedSplit && d.suggestedSplit !== d.suggested && <CodeBlock code={d.suggestedSplit} label={t('Découpé en chaînes de 255 caractères')} />}
                {d.suggestedLookupCount !== undefined && (
                  <p className="field__hint">{tn(d.suggestedLookupCount, 'Avec cette version : {n} requête DNS sur 10.', 'Avec cette version : {n} requêtes DNS sur 10.')}</p>
                )}
              </div>
            </section>
          )}

          <IssueList findings={r.findings} passed={r.passed} />

          <section className="block dm-tech" aria-labelledby="tech-t">
            <h2 className="block__title" id="tech-t">{t('Détails techniques')}</h2>
            <Details title={t('Enregistrement et compteurs')} count={t('{n} requêtes, {size} octets', { n: d.lookupCount, size: d.responseSize })}>
              {d.record && <CodeBlock code={d.record} label={d.source === 'input' ? t('Enregistrement collé') : t('TXT de {domain}', { domain })} />}
              <LabTable>
                <LabRow label={t('Enregistrements SPF publiés')} measured={d.records.length} reference={t('1 exactement')}
                  deviation={d.records.length === 1 ? { kind: 'ok' } : { kind: 'out', direction: d.records.length > 1 ? 'up' : 'down', text: d.records.length > 1 ? `${d.records.length - 1}` : '1' }} />
                <LabRow label={t('Requêtes DNS déclenchées')} measured={d.lookupCount} reference={`≤ ${d.lookupLimit}`}
                  deviation={d.lookupCount <= d.lookupLimit ? { kind: 'ok', text: d.lookupCount >= 8 ? t('limite proche') : t('conforme') } : { kind: 'out', direction: 'up', text: String(d.lookupCount - d.lookupLimit) }} />
                <LabRow label={t('Requêtes sans réponse (void)')} measured={d.voidCount} reference={`≤ ${d.voidLimit}`}
                  deviation={d.voidCount <= d.voidLimit ? { kind: 'ok' } : { kind: 'out', direction: 'up', text: String(d.voidCount - d.voidLimit) }} />
                <LabRow label={t('Règle finale')} measured={eff.q ? `${allMeaning(eff.q)}${eff.via ? ', ' + t('via {via}', { via: eff.via }) : ''}` : t('absente')} reference={t('-all ou ~all')}
                  deviation={eff.q === '-' || eff.q === '~' ? { kind: 'ok' } : { kind: 'out', direction: 'down', text: eff.q ? t('trop permissive') : t('absente') }} />
                <LabRow label={t('Taille de la réponse DNS')} measured={t('{n} octets', { n: d.responseSize })} reference={t('≤ 512 octets')}
                  deviation={d.responseSize <= 512 ? { kind: 'ok' } : { kind: 'warn', direction: 'up', text: String(d.responseSize - 512) }} />
                {d.providers.length > 0 && <LabRow label={t("Services d'envoi reconnus")} measured={d.providers.map(providerName).join(', ')} deviation={{ kind: 'info', text: t('noté') }} />}
              </LabTable>
            </Details>
            <Details title={t('Arbre des include')} count={t('{n} include', { n: d.includes?.length ?? 0 })}>
              <Tree node={d.tree} />
            </Details>
            <Details title={t('Adresses autorisées')} count={t('{v4} IPv4, {v6} IPv6', { v4: d.ipv4.length, v6: d.ipv6.length })}>
              {d.ipv4.length + d.ipv6.length === 0 ? (
                <p className="muted">{t('Aucune adresse autorisée de façon statique.')}</p>
              ) : (
                <CodeBlock code={[...d.ipv4, ...d.ipv6].join('\n')} label={t('ip4 / ip6 aplatis')} />
              )}
              {d.dynamic.length > 0 && <p className="field__hint">{t("Non aplatissables (évalués à l'envoi) : {list}", { list: d.dynamic.join(', ') })}</p>}
            </Details>
            <Details title={t('Tester une adresse IP contre ce SPF')}>
              <IpEval domain={domain} />
            </Details>
          </section>
          <Unavailable items={r.unavailable} />
        </>
      )}
    </div>
  );
}
