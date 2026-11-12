// Frame shared by the detailed domain pages (direction v2 "Clair et direct", 2026-11-10):
// without input the tool hero; with input the verdict band (findings and passed always given),
// the complete fix on top when one is computed, what to fix as cards, what is fine, then the
// technical tables folded in Details. NXDOMAIN replaces the whole report by one verdict.
import { useEffect, useState, type ReactNode } from 'react';
import { Link } from 'react-router';
import { ArrowRight } from 'lucide-react';
import { LabRow, LabTable, MeasuredMeta, ReportHeader, RerunButton, ShareButton, Unavailable } from '../../components/Report';
import { ToolHero } from '../../components/ToolHero';
import { IssueList, Verdict } from '../../components/Verdict';
import { CodeBlock, Notice, Skel } from '../../components/ui';
import { TOOLS } from '../../app/tools';
import { rich, t, tn } from '../../lib/i18n';
import { pushRecent } from '../../lib/recent';
import type { CheckResult, Finding, PassedCheck } from '../../lib/types';
import { errorMessage } from '../../lib/useCheck';
import { guessDomains, isNxResult, parseTagList } from './rows';
import './domain.css';

export function useRecent(domain: string | undefined, path: string, label: string) {
  useEffect(() => {
    if (domain) pushRecent({ value: domain, path, label });
  }, [domain, path, label]);
}

/** Landing state: one task on screen. Notices (invalid input, pasted record) above the hero. */
export function ToolEmpty({
  title,
  desc,
  basePath,
  examples,
  children,
}: {
  title: string;
  desc: string;
  basePath: string;
  examples?: { domain: string; why?: string }[];
  children?: ReactNode;
}) {
  const icon = TOOLS.find((x) => x.path === basePath)?.icon;
  return (
    <>
      {children && <div className="stack dm-above-hero">{children}</div>}
      <ToolHero icon={icon} title={title} desc={desc} basePath={basePath} examples={examples?.map((e) => e.domain)} />
    </>
  );
}

/** A record pasted in the universal input: shown as written, the server only measures domains. */
export function PastedRecord({ record, kind, basePath }: { record: string; kind: string; basePath: string }) {
  const tags = parseTagList(record);
  const guesses = guessDomains(record);
  return (
    <div className="stack">
      <Notice tone="warn" title={t('TestAndFix ne sait pas encore analyser un enregistrement {kind} collé', { kind })}>
        {t('Il mesure ce que le DNS publie réellement. Saisissez le domaine ci-dessous : la mesure part tout de suite et contrôle ce même enregistrement tel que les serveurs de messagerie le lisent.')}
        {guesses.length > 0 && (
          <span className="dm-guess">
            {' '}
            {tn(guesses.length, 'Domaine cité dans l’enregistrement :', 'Domaines cités dans l’enregistrement :')}{' '}
            {guesses.map((g, i) => (
              <span key={g}>
                {i > 0 && ', '}
                <Link to={`${basePath}/${g}`} className="mono">
                  {g}
                </Link>
              </span>
            ))}
          </span>
        )}
      </Notice>
      <CodeBlock code={record} label={t('Enregistrement collé')} />
      {tags.length > 1 && (
        <LabTable>
          {tags.map((tg, i) => (
            <LabRow key={i} label={<span className="mono">{tg.name}</span>} measured={tg.value || t('(vide)')} deviation={{ kind: 'info', text: t('non évalué') }} />
          ))}
        </LabTable>
      )}
    </div>
  );
}

/** "À corriger" then "À surveiller": the shared IssueList (same words as the verdict), with an extra per card. */
export function Issues({ findings, extra, title = t('À corriger'), passed }: { findings: Finding[]; extra?: (f: Finding) => ReactNode; title?: string; passed?: PassedCheck[] }) {
  return <IssueList findings={findings} extra={extra} title={title} passed={passed} />;
}

/** Cards in place of the expected ones while measuring. */
export function SkeletonCards({ n = 2 }: { n?: number }) {
  return (
    <div className="issues" role="status" aria-busy="true" aria-label={t('Mesure en cours')}>
      {Array.from({ length: n }, (_, i) => (
        <div key={i} className="issue">
          <Skel w="30%" />
          <Skel w="70%" />
          <Skel w="55%" />
        </div>
      ))}
    </div>
  );
}

/** The complete record to publish, computed for the whole object: on top, in its own block. */
export function FixBlock({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="block" aria-labelledby="fix-t">
      <h2 className="block__title" id="fix-t">
        {title}
      </h2>
      <div className="issue">{children}</div>
    </section>
  );
}

/** Verdict band, fix block, cards, passes, then the technical details (children). */
export function ReportFrame<D>({
  domain,
  r,
  loading,
  error,
  rerun,
  facts,
  noScore,
  fix,
  issueExtra,
  sentence,
  afterIssues,
  skeleton,
  children,
}: {
  domain: string;
  r: CheckResult<D> | null;
  loading: boolean;
  error: unknown;
  rerun: () => void;
  /** 2 to 4 key facts, shown before the time of measure. */
  facts?: (r: CheckResult<D>) => { label: string; value: ReactNode }[];
  /** The result measured nothing that a score could summarise (source unreachable). */
  noScore?: (r: CheckResult<D>) => boolean;
  fix?: (r: CheckResult<D>) => ReactNode;
  issueExtra?: (f: Finding, r: CheckResult<D>) => ReactNode;
  sentence?: (r: CheckResult<D>) => ReactNode;
  /** A block right after the cards (an action that completes the measure). */
  afterIssues?: (r: CheckResult<D>) => ReactNode;
  /** kept for the callers; v2 shows skeleton cards */
  skeleton?: unknown;
  /** Technical details: Details blocks, the most useful one open. */
  children: (r: CheckResult<D>) => ReactNode;
}) {
  void skeleton;
  const hide = !!r && !!noScore?.(r);
  const nx = !!r && isNxResult(r);
  return (
    <div className="dm-report">
      {hide && r ? (
        <NeutralVerdict
          subject={<span className="mono">{domain}</span>}
          sentence={sentence?.(r) ?? t('Rien n’a pu être mesuré : la note n’aurait pas de sens.')}
          facts={[...(facts?.(r) ?? []), ...MeasuredMeta(r)]}
          actions={
            <>
              <RerunButton onClick={rerun} busy={loading} />
              <ShareButton />
            </>
          }
        />
      ) : (
      <ReportHeader
        subject={<span className="mono">{domain}</span>}
        meta={r ? [...(nx ? [] : facts?.(r) ?? []), ...MeasuredMeta(r)] : []}
        score={hide ? undefined : r?.score}
        findings={r?.findings}
        passed={r?.passed}
        sentence={r ? (nx ? t('{domain} n’existe pas dans le DNS : il n’y a rien à mesurer sur ce nom.', { domain }) : sentence?.(r)) : undefined}
        pending={loading && !r}
        actions={
          <>
            <RerunButton onClick={rerun} busy={loading} />
            <ShareButton />
          </>
        }
      />
      )}
      {error ? (
        <Notice tone="error" title={t('Mesure impossible')}>
          {errorMessage(error)}{' '}
          <button type="button" className="btn btn--sm" onClick={rerun} style={{ marginLeft: 'var(--s2)' }}>
            {t('Réessayer')}
          </button>
        </Notice>
      ) : null}
      {loading && !r && <SkeletonCards />}
      {r && nx && (
        <>
          <Notice tone="error" title={t('{domain} n’existe pas dans le DNS', { domain })}>
            {rich('Les serveurs de noms répondent NXDOMAIN : il n’y a rien à mesurer ni à publier sur ce nom tant que le domaine n’est pas enregistré et délégué. Vérifiez l’orthographe, ou son enregistrement (<whois>page Whois</whois>).', undefined, { whois: (c) => <Link to={`/whois/${domain}`}>{c}</Link> })}
          </Notice>
          <Issues findings={nxFindings(r.findings)} />
        </>
      )}
      {r && !nx && (
        <>
          {fix?.(r)}
          <Issues findings={r.findings} passed={r.passed} extra={issueExtra ? (f) => issueExtra(f, r) : undefined} />
          {afterIssues?.(r)}
          <section className="block dm-tech" aria-labelledby="tech-t">
            <h2 className="block__title" id="tech-t">
              {t('Détails techniques')}
            </h2>
            {children(r)}
          </section>
          <Unavailable items={r.unavailable} />
        </>
      )}
    </div>
  );
}

/** Verdict band without a score: the measure could not happen (not a good, not a bad result). */
export function NeutralVerdict({ subject, sentence, facts = [], actions, mood = t('Non mesuré') }: { subject: ReactNode; sentence: ReactNode; facts?: { label: string; value: ReactNode }[]; actions?: ReactNode; mood?: string }) {
  return <Verdict unmeasured subject={subject} sentence={sentence} facts={facts} actions={actions} mood={mood} />;
}

const nxFindings = (all: Finding[]) => {
  const nx = all.filter((f) => /\.domain_nxdomain$/.test(f.id));
  return nx.length ? nx : all.filter((f) => f.penalty > 0);
};

/** Links to sibling pages for the same domain. */
export function SeeAlso({ links }: { links: { to: string; label: string }[] }) {
  return (
    <nav className="dm-seealso" aria-label={t('Pages liées')}>
      <span className="muted">{t('Voir aussi')}</span>
      {links.map((l) => (
        <Link key={l.to} to={l.to} className="dm-more">
          {l.label}
          <ArrowRight aria-hidden />
        </Link>
      ))}
    </nav>
  );
}
