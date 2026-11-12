// The sections of the mail report (data.sections of the server), each a lab table. Where the
// measure has a natural line (SPF, DKIM, DMARC, reverse DNS, SpamAssassin score…), the line is
// written explicitly with its measured and expected values, and carries the findings that
// explain it; the other findings of the section follow, then the passed checks.
import type { ReactNode } from 'react';
import { FindingDetail, FindingRow, LabRow, LabTable, PassedRow, deviationOf, type Deviation } from '../../components/Report';
import { CodeBlock } from '../../components/ui';
import { fmtBytes, fmtPenalty, fmtScore, plural } from '../../lib/format';
import { t } from '../../lib/i18n';
import type { Finding, PassedCheck } from '../../lib/types';
import { authResult, clientSection, PASSED_MEASURED, decodeWords, groupDeviation, humanError, measureOf, PASSED_REF, sectionOrder, sumPenalty, takeByPrefix, tlsName } from './logic';
import type { MailReport, SectionSummary } from './types';

type F = Finding & { section?: string };

interface Ctx {
  r: MailReport;
  findings: F[];
  passed: PassedCheck[];
  usedF: Set<string>;
  usedP: Set<string>;
}

/** One explicit line carrying the findings (and passed checks) whose id starts with a prefix. */
function groupRow(
  ctx: Ctx,
  {
  key,
  label,
  measured,
  reference,
  prefixes,
  findings: given,
  extra,
  okText,
  deviation,
}: {
  key?: string;
  label: ReactNode;
  measured?: ReactNode;
  reference?: ReactNode;
  prefixes?: string[];
  findings?: F[];
  extra?: ReactNode;
  okText?: string;
  deviation?: Deviation;
},
) {
  const fs = given ?? (prefixes ? takeByPrefix(ctx.findings, prefixes, ctx.usedF) : []);
  if (prefixes) takeByPrefix(ctx.passed, prefixes, ctx.usedP);
  const ordered = sectionOrder(fs);
  const dev = deviation && !ordered.some((f) => f.penalty > 0 || (f.advicePenalty ?? 0) > 0) ? deviation : groupDeviation(ordered, okText);
  const detail =
    ordered.length || extra ? (
      <>
        {ordered.map((f) => (
          <div key={f.id} className="mail-group">
            {(ordered.length > 1 || extra) && (
              <div className="mail-group__title">
                {f.title}
                {f.penalty > 0 && <span className="mail-group__pts">{t('{n} pt', { n: fmtPenalty(f.penalty) })}</span>}
              </div>
            )}
            {ordered.length === 1 && !extra ? <FindingDetail f={f} /> : <div className="mail-group__body"><FindingDetail f={f} /></div>}
          </div>
        ))}
        {extra}
      </>
    ) : undefined;
  return <LabRow key={key} label={label} measured={measured} reference={reference} deviation={dev} detail={detail} />;
}

function rest(ctx: Ctx) {
  const fs = sectionOrder(ctx.findings.filter((f) => !ctx.usedF.has(f.id)));
  const ps = ctx.passed.filter((p) => !ctx.usedP.has(p.id));
  return (
    <>
      {fs.map((f) => {
        const m = measureOf(f, ctx.r.data);
        return <FindingRow key={f.id} f={f} measured={m.measured} reference={m.reference} />;
      })}
      {ps.map((p) => (
        <PassedRow key={p.id} p={{ ...p, detail: decodeWords(p.detail) ?? (PASSED_MEASURED[p.id] ? t(PASSED_MEASURED[p.id]) : undefined) }} reference={PASSED_REF[p.id] ? t(PASSED_REF[p.id]) : undefined} />
      ))}
    </>
  );
}

const sub = (main: ReactNode, small?: ReactNode) => (
  <span className="mail-label">
    {main}
    {small && <span className="mail-label__sub">{small}</span>}
  </span>
);

/** Line state when no finding explains it: in range, or off range without points of its own (they are counted elsewhere). */
const ok = (cond: boolean, okText = t('conforme'), badText = t('écart')): Deviation => (cond ? { kind: 'ok', text: okText } : { kind: 'warn', direction: 'down', text: badText });

/* ---------- authentication ---------- */
function AuthRows({ ctx }: { ctx: Ctx }) {
  const a = ctx.r.data.auth;
  const from = ctx.r.data.message.fromDomain;
  if (!a) return <>{rest(ctx)}</>;
  const spf = a.spf;
  const sigs = a.dkim ?? [];
  const dkimFindings = takeByPrefix(ctx.findings, ['dkim.'], ctx.usedF);
  takeByPrefix(ctx.passed, ['dkim.'], ctx.usedP);
  // a DKIM finding goes to the signature it names, the others to the first line
  const forSig = (i: number) =>
    dkimFindings.filter((f) => {
      const text = `${f.title} ${f.evidence ?? ''}`;
      const owner = sigs.findIndex((s) => text.includes(`${s.selector}._domainkey`) || text.includes(`d=${s.domain}`));
      return owner === i || (owner < 0 && i === 0);
    });
  const al = a.alignment;
  const alignText = (x: 'strict' | 'relaxed' | false | undefined, pass: boolean) => (!pass ? t('ne passe pas') : x === 'strict' ? t('aligné (strict)') : x === 'relaxed' ? t('aligné (relaxed)') : t('non aligné'));
  return (
    <>
      {groupRow(ctx, { label: sub('SPF', spf?.domain ? `MAIL FROM ${spf.domain}` : undefined), measured: authResult(spf?.result), reference: "pass", prefixes: ['spf.'], deviation: spf?.result === 'unavailable' ? { kind: 'info', text: t('non mesuré') } : ok(spf?.result === 'pass'), extra: spf?.record ? <CodeBlock code={spf.record} label={t('SPF publié par {domain}', { domain: spf.domain ?? from ?? t('le domaine') })} /> : undefined })}
      {spf?.lookups && spf.record && (
        <LabRow
          label={sub(t('Requêtes DNS du SPF'), 'include, a, mx, redirect…')}
          measured={spf.lookups.count}
          reference={`≤ ${spf.lookups.limit}`}
          deviation={spf.lookups.count <= spf.lookups.limit ? { kind: 'ok' } : { kind: 'out', direction: 'up', text: String(spf.lookups.count - spf.lookups.limit) }}
        />
      )}
      {sigs.length === 0 ? (
        groupRow(ctx, { label: "DKIM", measured: t('aucune signature'), reference: t('signature valide de {domain}', { domain: from ?? t('votre domaine') }), findings: dkimFindings })
      ) : (
        sigs.map((s, i) => (
          groupRow(ctx, { key: `${s.domain}-${s.selector}-${i}`, label: sub('DKIM', `d=${s.domain} s=${s.selector}`), measured: [s.result, s.keyBits ? t('{n} bits', { n: String(s.keyBits) }) : undefined, s.testing ? t('test') : undefined].filter(Boolean).join(' · '), reference: from ? t('pass, clé de 2048 bits conseillée, d={domain}', { domain: from }) : t('pass, clé de 2048 bits conseillée'), findings: forSig(i), deviation: ok(s.result === 'pass') })
        ))
      )}
      {groupRow(ctx, { label: sub('DMARC', a.dmarc?.policyRecordName), measured: a.dmarc ? `${a.dmarc.result ?? 'none'}${a.dmarc.p ? ` (p=${a.dmarc.p})` : ''}` : t('non évalué'), reference: t('pass, p=quarantine ou reject'), prefixes: ['dmarc.'], deviation: ok(a.dmarc?.result === 'pass'), extra: a.dmarc?.record ? <CodeBlock code={a.dmarc.record} label={t('TXT de {name}', { name: a.dmarc.policyRecordName ?? `_dmarc.${from}` })} /> : undefined })}
      {al && (
        groupRow(ctx, { label: sub(t('Alignement sur le From'), al.fromDomain), measured: 
            <>
              {(al.spf as { evaluated?: boolean; label?: string }).evaluated === false
                ? ((al.spf as { label?: string }).label ?? t('SPF non évalué')) // the server label already starts with "SPF"
                : <>{t('SPF {state}', { state: alignText(al.spf.aligned, al.spf.pass) })}</>}
              <br />
              {t('DKIM {state}', { state: al.dkim.length ? alignText(al.dkim.find((d) => d.alignedUnderMode)?.aligned ?? al.dkim[0].aligned, al.dkim.some((d) => d.pass)) : t('absent') })}
            </>
          , reference: t('SPF ou DKIM aligné ({mode})', { mode: al.mode.spf === al.mode.dkim ? al.mode.spf : `aspf ${al.mode.spf}, adkim ${al.mode.dkim}` }), prefixes: ['alignment.'], deviation: ok(al.aligned, t('aligné'), t('non aligné')) })
      )}
      {a.arc && (a.arc.result !== 'none' || ctx.findings.some((f) => f.id.startsWith('arc.'))) && (
        groupRow(ctx, { label: "ARC", measured: `${a.arc.result}${a.arc.instance ? ` · ${plural(a.arc.instance, 'relais', 'relais')}` : ''}`, reference: t('pass si le message a été relayé'), prefixes: ['arc.'], deviation: ok(a.arc.result === 'pass') })
      )}
      {a.bimi && (
        groupRow(ctx, { label: sub('BIMI', t('logo dans la boîte de réception')), measured: a.bimi.result === 'skipped' ? (a.bimi.comment === 'message failed DMARC' ? t('non évalué (DMARC échoue)') : t('non évalué')) : a.bimi.result, reference: t('pass, facultatif'), prefixes: ['bimi.'], deviation: a.bimi.result === 'pass' ? { kind: 'ok' } : { kind: 'info', text: t('facultatif') } })
      )}
      {rest(ctx)}
    </>
  );
}

/* ---------- sending server ---------- */
function InfraRows({ ctx }: { ctx: Ctx }) {
  const d = ctx.r.data;
  const inf = d.infrastructure ?? {};
  const ip = inf.ip ?? d.envelope.clientIp;
  const tls = inf.tls ?? d.envelope.tls;
  const ptr = inf.ptr ?? [];
  return (
    <>
      <LabRow
        label={sub(t("IP d'envoi"), d.envelope.ipSource === 'smtp' ? t('observée à la connexion') : d.envelope.ipSource === 'received' ? (d.envelope.ipReason ?? t('déduite des Received')) : undefined)}
        measured={ip ?? t('inconnue')}
        reference={t('adresse publique')}
        deviation={inf.private ? { kind: 'info', text: t('locale') } : ip ? { kind: 'ok', text: t('publique') } : { kind: 'info', text: t('inconnue') }}
      />
      {groupRow(ctx, { label: sub('Reverse DNS', t('PTR de l’IP')), measured: inf.private ? t('non contrôlé (IP locale)') : ptr.length ? ptr.join(', ') : t('absent'), reference: t('un nom qui revient vers l’IP'), prefixes: ['rdns.'], deviation: inf.private ? { kind: 'info', text: t('non mesuré') } : ok(!!inf.fcrdns, t('confirmé'), t('non confirmé')) })}
      {groupRow(ctx, { label: sub('HELO', t('nom annoncé par le serveur')), measured: inf.helo ?? d.envelope.helo ?? t('inconnu'), reference: t('nom public qui résout vers l’IP'), prefixes: ['helo.'], deviation: { kind: 'ok' } })}
      {groupRow(ctx, { label: sub(t('Chiffrement'), tls?.source === 'received' ? t('premier relais externe') : t('session SMTP reçue')), measured: tls?.used === true ? `${tlsName(tls.protocol) ?? 'TLS'}${tls.cipher ? ` · ${tls.cipher}` : ''}` : tls?.used === false ? t('aucun (en clair)') : t('non indiqué'), reference: t('TLS 1.2 ou plus'), prefixes: ['tls.'], deviation: tls?.used === true ? { kind: 'ok' } : { kind: 'info', text: t('inconnu') } })}
      {rest(ctx)}
    </>
  );
}

/* ---------- SpamAssassin ---------- */
const signed = (n: number) => `${n > 0 ? '+' : ''}${fmtScore(n)}`;

function SpamRows({ ctx }: { ctx: Ctx }) {
  const sa = ctx.r.data.spamassassin;
  if (!sa?.available) {
    return (
      <>
        <LabRow
          label="SpamAssassin"
          measured={sa?.error ? t('non mesuré, {reason}', { reason: humanError(sa.error) }) : t('non mesuré')}
          reference={t('score sous le seuil')}
          deviation={{ kind: 'info', text: t('non mesuré') }}
          detail={
            sa?.error ? (
              <>
                <p className="lab-detail__why">{t('Le service SpamAssassin (spamd) n’a pas répondu. La note est calculée sans lui : relancez l’analyse une fois spamd démarré.')}</p>
                <details className="mail-tech">
                  <summary>{t('Détail technique')}</summary>
                  <code>{sa.error}</code>
                </details>
              </>
            ) : undefined
          }
        />
        {rest(ctx)}
      </>
    );
  }
  const rules = [...(sa.rules ?? [])].sort((a, b) => b.score - a.score);
  takeByPrefix(ctx.passed, ['sa.', 'spamassassin.score'], ctx.usedP);
  const all = ctx.r.findings as F[];
  return (
    <>
      <LabRow
        label={t('Score SpamAssassin')}
        measured={fmtScore(sa.score)}
        reference={`< ${fmtScore(sa.threshold)}`}
        deviation={(sa.score ?? 0) >= (sa.threshold ?? 5) ? { kind: 'out', direction: 'up', text: fmtScore((sa.score ?? 0) - (sa.threshold ?? 5)) } : { kind: 'ok', text: t('sous le seuil') }}
      />
      {rules.map((rule) => {
        const f = all.find((x) => (x.evidence ?? '').includes(`SpamAssassin ${rule.name} `));
        if (f) ctx.usedF.add(f.id);
        const dev: Deviation = f ? deviationOf(f) : rule.score < 0 ? { kind: 'ok', text: t('favorable') } : { kind: 'info', text: rule.score > 0 ? t('sans effet') : t('neutre') };
        return (
          <LabRow
            key={rule.name}
            label={sub(<code className="mail-rule">{rule.name}</code>, rule.description)}
            measured={signed(rule.score)}
            reference={f && f.section !== 'spamassassin' ? t('voir {section}', { section: sectionName(f.section) }) : undefined}
            deviation={dev}
            detail={f ? <FindingDetail f={f} /> : undefined}
          />
        );
      })}
      {rest(ctx)}
    </>
  );
}

/* ---------- blacklists ---------- */
function BlacklistRows({ ctx }: { ctx: Ctx }) {
  const b = ctx.r.data.blacklists;
  if (!b) return <>{rest(ctx)}</>;
  const zones = new Set([...b.clean, ...b.listed, ...b.refused].map((x) => x.zone));
  const refusedF = takeByPrefix(ctx.findings, ['blacklist.query_blocked'], ctx.usedF);
  const listedF = ctx.findings.filter((f) => !ctx.usedF.has(f.id) && f.family === 'blacklist');
  for (const f of listedF) ctx.usedF.add(f.id);
  takeByPrefix(ctx.passed, ['blacklist.'], ctx.usedP);
  const targets = [...new Set([...b.clean, ...b.listed].map((x) => x.target))];
  return (
    <>
      <LabRow
        label={sub(t('Listes interrogées'), targets.length ? t('pour {targets}', { targets: targets.join(', ') }) : undefined)}
        measured={`${plural(zones.size, 'liste', 'listes')} · ${plural(b.checked, 'requête', 'requêtes')}`}
        reference={b.lists ? t('{n} au catalogue', { n: b.lists }) : undefined}
        deviation={{ kind: 'info', text: t('noté') }}
        detail={
          b.clean.length ? (
            <div>
              <div className="lab-detail__label">{t('Absent de')}</div>
              <ul className="mail-plainlist">
                {[...new Map(b.clean.map((c) => [`${c.zone} ${c.target}`, c])).values()].map((c) => (
                  <li key={`${c.zone}-${c.target}`}>
                    {c.name} <span className="mono muted">({c.zone}, {c.target})</span>
                  </li>
                ))}
              </ul>
            </div>
          ) : undefined
        }
      />
      {groupRow(ctx, { label: t('Inscriptions sur liste noire'), measured: b.listed.length, reference: "0", findings: listedF, deviation: b.listed.length ? { kind: 'out', direction: 'up', text: String(b.listed.length) } : { kind: 'ok', text: t('aucune') } })}
      {b.refused.length > 0 && groupRow(ctx, { label: t('Listes qui refusent de répondre'), measured: b.refused.length, reference: "0", findings: refusedF })}
      {b.errors.length > 0 && (
        <LabRow label={t('Listes sans réponse')} measured={b.errors.length} reference="0" deviation={{ kind: 'warn', direction: 'up', text: String(b.errors.length) }} detail={<p className="lab-detail__why">{b.errors.map((e) => `${e.zone} (${e.target}) : ${e.error}`).join(' · ')}</p>} />
      )}
      {rest(ctx)}
    </>
  );
}

/* ---------- unsubscribe ---------- */
function UnsubRows({ ctx }: { ctx: Ctx }) {
  const u = ctx.r.data.unsubscribe;
  if (!u || (!u.listUnsubscribe && !u.isBulk)) {
    const fs = ctx.findings.length + ctx.passed.length;
    return (
      <>
        {!fs && <LabRow label={sub('List-Unsubscribe', t('en-tête de désinscription'))} measured={t('absent')} reference={t('attendu pour les envois en nombre')} deviation={{ kind: 'info', text: t('facultatif ici') }} />}
        {rest(ctx)}
      </>
    );
  }
  const kinds = (u.uris ?? []).map((x) => (x.startsWith('mailto:') ? 'mailto' : x.startsWith('https:') ? 'https' : x.split(':')[0]));
  return (
    <>
      {groupRow(ctx, { label: sub('List-Unsubscribe', t('en-tête de désinscription')), measured: u.listUnsubscribe ? [...new Set(kinds)].join(' + ') || t('présent') : t('absent'), reference: t('une URL https, un mailto en plus'), prefixes: ['unsubscribe.list_unsubscribe_missing', 'unsubscribe.syntax_invalid', 'unsubscribe.http_not_https', 'unsubscribe.mailto_only', 'unsubscribe.multiple_https', 'unsubscribe.header'], deviation: ok(!!u.listUnsubscribe, t('présent')), extra: u.listUnsubscribe ? <CodeBlock code={`List-Unsubscribe: ${u.listUnsubscribe}${u.listUnsubscribePost ? `\nList-Unsubscribe-Post: ${u.listUnsubscribePost}` : ''}`} label={t('En-têtes reçus')} /> : undefined })}
      {groupRow(ctx, { label: sub(t('Désinscription en un clic'), 'RFC 8058'), measured: u.listUnsubscribePost ?? t('absente'), reference: "List-Unsubscribe=One-Click", prefixes: ['unsubscribe.one_click_post_missing', 'unsubscribe.post_value_invalid', 'unsubscribe.one_click'], deviation: ok(!!u.oneClick, t('présente')) })}
      {groupRow(ctx, { label: t('En-têtes couverts par DKIM'), measured: u.coveredByDkim ? t('oui') : t('non'), reference: t('oui'), prefixes: ['unsubscribe.not_dkim_signed'], deviation: ok(!!u.coveredByDkim, t('oui')) })}
      {rest(ctx)}
    </>
  );
}

/* ---------- content ---------- */
function ContentRows({ ctx }: { ctx: Ctx }) {
  const c = ctx.r.data.content;
  return (
    <>
      {rest(ctx)}
      {c?.size !== undefined && <LabRow label={t('Taille du message')} measured={fmtBytes(c.size)} reference={t('≤ 25 Mo, limite de Gmail')} deviation={c.size <= 25_000_000 ? { kind: 'ok' } : { kind: 'out', direction: 'up', text: t('trop gros') }} />}
      {c?.visibleWords !== undefined && <LabRow label={t('Mots visibles')} measured={c.visibleWords} reference={t('≥ 20 mots')} deviation={c.visibleWords >= 20 ? { kind: 'ok' } : { kind: 'info', text: t('court') }} />}
    </>
  );
}

function AttachmentRows({ ctx }: { ctx: Ctx }) {
  const atts = ctx.r.data.attachments ?? [];
  if (!atts.length && !ctx.findings.length) return <LabRow label={t('Pièces jointes')} measured={t('aucune')} reference={t('facultatives')} deviation={{ kind: 'ok', text: t('aucune') }} />;
  return (
    <>
      {rest(ctx)}
      {atts.map((a, i) => (
        <LabRow key={i} label={<span className="mono">{a.filename ?? t('sans nom')}</span>} measured={`${a.contentType ?? t('type inconnu')}${a.size !== undefined ? ` · ${fmtBytes(a.size)}` : ''}`} reference={t('≤ 10 Mo')} deviation={a.size !== undefined && a.size > 10 * 1024 * 1024 ? { kind: 'warn', direction: 'up', text: t('lourde') } : { kind: 'info', text: t('noté') }} />
      ))}
    </>
  );
}

const RENDER: Record<string, (p: { ctx: Ctx }) => ReactNode> = {
  auth: AuthRows,
  infrastructure: InfraRows,
  spamassassin: SpamRows,
  blacklists: BlacklistRows,
  unsubscribe: UnsubRows,
  content: ContentRows,
  attachments: AttachmentRows,
};

let SECTION_NAMES: Record<string, string> = {};
const sectionName = (id?: string) => (id ? (SECTION_NAMES[id] ?? id) : '');

/** Sections as shown: the server's, with the sender reputation set apart from the blacklists. */
export function displaySections(r: MailReport): SectionSummary[] {
  const out: SectionSummary[] = [];
  for (const s of r.data.sections) {
    out.push(s);
    if (s.id === 'blacklists' && r.findings.some((f) => clientSection(f as F) === 'reputation'))
      out.push({ id: 'reputation', title: t('Réputation de l’expéditeur'), lost: 0, status: 'info', findings: [], passed: [] });
  }
  return out;
}

/** The sections of the report (all but compliance, drawn as a matrix), or only some, in the server's order. */
export function ReportSections({ r, skip = ['compliance'], only }: { r: MailReport; skip?: string[]; only?: string[] }) {
  const sections = displaySections(r);
  SECTION_NAMES = Object.fromEntries(sections.map((s) => [s.id, s.title]));
  return (
    <>
      {sections
        .filter((s) => !skip.includes(s.id) && (!only || only.includes(s.id)))
        .map((s) => (
          <OneSection key={s.id} r={r} s={s} />
        ))}
    </>
  );
}

export function sectionStatus(findings: Finding[], passed: number, unavailable = false): ReactNode {
  if (unavailable) return t('non mesuré');
  const total = findings.length + passed;
  if (!total) return undefined;
  const out = findings.filter((f) => f.penalty > 0 && deviationOf(f).kind === 'out').length;
  const warn = findings.filter((f) => f.penalty > 0 && deviationOf(f).kind === 'warn').length;
  const lost = sumPenalty(findings);
  // advice the sender can act on: "conforme" would contradict the rows below (2026-11-12)
  const better = findings.filter((f) => f.impact === 'advice' && !f.outOfReach && (f.advicePenalty ?? 0) > 0).length;
  return (
    <>
      {out > 0 && <b>{t('{n} hors bornes', { n: out })}</b>}
      {out > 0 && warn > 0 && ' · '}
      {warn > 0 && <span className="mail-warn">{t('{n} à surveiller', { n: warn })}</span>}
      {out + warn === 0 ? (better ? t('{n} à améliorer', { n: better }) : t('conforme')) : ` · ${lost >= 2 ? t('{n} pt perdus', { n: fmtPenalty(lost) }) : t('{n} pt perdu', { n: fmtPenalty(lost) })}`}
      {` · ${plural(total, 'contrôle', 'contrôles')}`}
    </>
  );
}

function OneSection({ r, s }: { r: MailReport; s: SectionSummary }) {
  const findings = (r.findings as F[]).filter((f) => clientSection(f) === s.id);
  const passed = r.passed.filter((p) => clientSection(p) === s.id);
  const ctx: Ctx = { r, findings, passed, usedF: new Set(), usedP: new Set() };
  const Render = RENDER[s.id];
  if (!Render && !findings.length && !passed.length) return null;
  const unavailable = s.id === 'spamassassin' && !r.data.spamassassin?.available;
  const status = sectionStatus(findings, passed.length, unavailable);
  return (
    <section id={`s-${s.id}`} className="mr-sec" aria-labelledby={`s-${s.id}-t`}>
      <h3 className="mr-sec__head" id={`s-${s.id}-t`}>
        <span className="mr-sec__title">{s.title}</span>
        {status && <span className="mr-sec__status">{status}</span>}
      </h3>
      {/* called as a function: the rows take their findings from ctx in order, once per render */}
      <LabTable>{Render ? Render({ ctx }) : rest(ctx)}</LabTable>
      {s.id === 'auth' && r.data.auth?.authenticationResults && (
        <details className="mail-raw">
          <summary>{t('En-têtes Authentication-Results écrits par TestAndFix')}</summary>
          <CodeBlock code={r.data.auth.authenticationResults.replace(/\r\n/g, '\n').trim()} />
        </details>
      )}
    </section>
  );
}
