// The report of one received or imported message, "Signal" (validated mockup of 2026-11-11,
// claude.ai/artifact/N8k9en4MPiLdUeQwT2MRDW): the sends on this address, the verdict (what blocks
// delivery, what risks the spam folder), the two indicators (sender, message), the work list with
// the path and the facts of this send beside it, the message as it arrives (desktop and phone,
// full width), then the technical data in tabs. Shared by /mail/:addressId, /mail/message/:id
// and /mail/analyse, and read-only by /partage/:token (a report shared by link: no sends, no
// comparison, no reanalysis, no share button, the raw message read through the share).
import { useEffect, useState, type ReactNode } from "react";
import { Link, useLocation, useSearchParams } from "react-router";
import {
  Copy,
  Download,
  Ellipsis,
  FilePlus2,
  MailCheck,
  GitCompareArrows,
  MailPlus,
  RotateCw,
  Send,
} from "lucide-react";
import {
  ScoreBar,
  IssueList,
  toneOf,
  verdictSentence,
} from "../../components/Verdict";
import { copyText, Notice, Skel, useToast } from "../../components/ui";
import { get, post } from "../../lib/api";
import { fmtBytes, fmtScore, plural } from "../../lib/format";
import { msg, rich, t, tn } from "../../lib/i18n";
import type { Finding } from "../../lib/types";
import { pushRecent } from "../../lib/recent";
import { errorMessage, useCheck } from "../../lib/useCheck";
import { CompareSection } from "./Compare";
import { IndicatorPair, type Axis } from "./Indicators";
import {
  decodeWords,
  findPrevious,
  fmtWhen,
  fromOf,
  headlineOf,
  indicatorsOfReport,
  measureOf,
  numberSends,
  timingOf,
  type Headline,
  type Timing,
} from "./logic";
import { AnalysisProgress } from "./Panels";
import { PathCard } from "./PathView";
import { Pop } from "./Pop";
import { Preview } from "./Preview";
import { ResendPanel, SendsBar } from "./Sends";
import { TechTabs } from "./Tech";
import {
  isReport,
  type AddressInfo,
  type MailReport,
  type MessageSummary,
  type StepState,
  type StoredReport,
} from "./types";
import { useMailStream } from "./useMailStream";
import { ShareAction } from "./Share";
import type { Share } from "../../lib/carnet";

/** Labels of the analysis steps, used until the server sends its own list. */
export const DEFAULT_STEPS: Record<string, string> = {
  parse: msg("Lecture du message"),
  auth: msg("Authentification (SPF, DKIM, DMARC, ARC, BIMI)"),
  infrastructure: msg("Serveur d'envoi (reverse DNS, HELO, TLS)"),
  spamassassin: "SpamAssassin",
  links: msg("Liens et images"),
  blacklists: msg("Listes noires"),
  content: msg("Contenu et en-têtes"),
  compliance: msg("Exigences Gmail, Yahoo, Microsoft"),
};

/** The measured value in an open row: what check saw, and what is expected. */
function Measured({ f, r }: { f: Finding; r: MailReport }) {
  const m = measureOf(f, r.data);
  if (!m.measured && !m.reference) return null;
  return (
    <div className="seen mail-measure">
      {m.measured && (
        <span>{rich("Mesuré <b>{value}</b>", { value: m.measured }, { b: (c) => <b>{c}</b> })}</span>
      )}
      {m.reference && (
        <span>{rich("Attendu <b>{value}</b>", { value: m.reference }, { b: (c) => <b>{c}</b> })}</span>
      )}
    </div>
  );
}

/** The address of this message and its other sends: given by the address page, fetched on a permalink. */
function useAddress(
  m: MessageSummary,
  siblings?: MessageSummary[],
  given?: AddressInfo,
): { address?: AddressInfo; messages: MessageSummary[] } {
  const need = !siblings && m.addressId !== "upload";
  const { data } = useCheck<AddressInfo & { messages: MessageSummary[] }>(
    need ? `/api/mail/addresses/${encodeURIComponent(m.addressId)}` : null,
  );
  const address =
    given ??
    (data
      ? {
          id: data.id,
          address: data.address,
          label: data.label,
          createdAt: data.createdAt,
          expiresAt: data.expiresAt,
          expired: data.expired,
        }
      : undefined);
  return { address, messages: siblings ?? data?.messages ?? [] };
}

/** The newest analysed message before this one: same address first, else same From domain. */
function usePrevious(
  m: MessageSummary,
  sameAddress: MessageSummary[],
  off?: boolean,
): MessageSummary | undefined {
  const [cands, setCands] = useState<MessageSummary[]>([]);
  useEffect(() => {
    if (!m.fromDomain || off) return;
    let alive = true;
    get<{ items: MessageSummary[] }>(
      `/api/mail/history?domain=${encodeURIComponent(m.fromDomain)}&limit=50`,
    )
      .then((r) => alive && setCands(r.items))
      .catch(() => {});
    return () => {
      alive = false;
    };
  }, [m.id, m.fromDomain, off]);
  if (off) return undefined;
  const same = m.addressId === "upload" ? [] : sameAddress;
  return (
    findPrevious(m, same) ??
    findPrevious(
      m,
      cands.filter((c) => !!m.fromDomain && c.fromDomain === m.fromDomain),
    )
  );
}

const MOOD = {
  good: msg("Excellent"),
  watch: msg("À améliorer"),
  bad: msg("À corriger"),
} as const;
const DOT = {
  good: "ok",
  watch: "warn",
  bad: "out",
  pending: "pending",
  neutral: "",
} as const;

type Tone = keyof typeof DOT;

/** The verdict strip, the look of components/Verdict, with the headline of the two indicators. */
function MailVerdict({
  tone,
  mood,
  main,
  rest,
  facts,
  score,
  findings,
  actions,
}: {
  tone: Tone;
  mood: string;
  main: string;
  rest?: string;
  facts: { label: string; value: string; mono?: boolean }[];
  score?: number | null;
  findings: Finding[];
  actions: ReactNode;
}) {
  return (
    <header className={`verdict verdict--${tone} mr-verdict`}>
      <div className="verdict__main">
        <div className="verdict__mood">
          <span
            className={`dot${DOT[tone] ? ` dot--${DOT[tone]}` : ""}`}
            aria-hidden
          />
          {mood}
        </div>
        <h1 className="verdict__subject mr-headline">
          {main}
          {rest && <em> {rest}</em>}
        </h1>
        <dl className="verdict__facts mr-who">
          {facts.map((f) => (
            <div key={f.label}>
              <dt className="visually-hidden">{f.label}</dt>
              <dd className={f.mono ? "mono" : undefined}>{f.value}</dd>
            </div>
          ))}
        </dl>
      </div>
      {score !== undefined && (
        <div className="verdict__score">
          <div className="verdict__number" aria-hidden>
            {score === null ? (
              <span className="skel verdict__wait" />
            ) : (
              fmtScore(score)
            )}
            <small>/10</small>
          </div>
          <ScoreBar score={score} findings={findings} />
        </div>
      )}
      <div className="verdict__actions">{actions}</div>
    </header>
  );
}

function SendFacts({
  m,
  d,
  timing,
}: {
  m: MessageSummary;
  d?: MailReport["data"];
  timing: Timing;
}) {
  const atts = d?.attachments ?? [];
  const c = d?.content;
  const ip = d?.envelope.clientIp ?? m.clientIp ?? undefined;
  const rows: [string, string][] = [
    [
      t("Écrit le"),
      timing.writtenAt !== undefined ? fmtWhen(timing.writtenAt) : t("en-tête Date absent"),
    ],
    [
      t("Reçu le"),
      timing.receivedAt !== undefined ? fmtWhen(timing.receivedAt) : t("non indiqué"),
    ],
    ...(timing.importedAt !== undefined
      ? ([[t("Importé le"), fmtWhen(timing.importedAt)]] as [string, string][])
      : []),
    ...(ip
      ? ([
          [
            t("IP d'envoi"),
            d?.infrastructure?.private ? t("{ip} (locale)", { ip }) : ip,
          ],
        ] as [string, string][])
      : []),
    [
      t("Contenu"),
      !c
        ? t("non lu")
        : c.hasHtml && c.hasText
          ? t("HTML et texte")
          : c.hasHtml
            ? t("HTML seul")
            : c.hasText
              ? t("texte seul")
              : t("vide"),
    ],
    [
      t("Pièces jointes"),
      atts.length ? plural(atts.length, "pièce", "pièces") : t("aucune"),
    ],
    ...(d?.message.size
      ? ([[t("Taille"), fmtBytes(d.message.size)]] as [string, string][])
      : []),
  ];
  return (
    <dl className="mr-facts">
      {rows.map(([k, v]) => (
        <div key={k}>
          <dt>{k}</dt>
          <dd>{v}</dd>
        </div>
      ))}
    </dl>
  );
}

export interface MessageReportProps {
  message: MessageSummary;
  report: StoredReport | null | undefined;
  /** progress events of this message, when the parent follows the address stream */
  progress?: Record<string, StepState>;
  steps?: Record<string, string>;
  streamError?: string;
  /** the parent already follows the stream of the address */
  live?: boolean;
  siblings?: MessageSummary[];
  address?: AddressInfo;
  /** the share link of this message; undefined when the parent does not know it */
  share?: Share | null;
  /** read-only, opened by a share link: the token of that link */
  sharedToken?: string;
}

export function MessageReport({
  message,
  report,
  progress,
  steps,
  streamError,
  live,
  siblings,
  address: givenAddress,
  share,
  sharedToken,
}: MessageReportProps) {
  const readOnly = sharedToken !== undefined;
  const [params] = useSearchParams();
  const location = useLocation();
  const toast = useToast();
  const compareWith = params.get("comparer");
  const [override, setOverride] = useState<MailReport | null>(null);
  const [reanalyzing, setReanalyzing] = useState(false);
  const [reErr, setReErr] = useState<string | null>(null);
  const [axis, setAxis] = useState<Axis | null>(null);

  const pendingStatus =
    message.status === "received" || message.status === "analyzing";
  // without a parent stream, follow the address while this message is being analysed
  const own = useMailStream(
    !live && !readOnly && (reanalyzing || (pendingStatus && !isReport(report)))
      ? message.addressId
      : null,
  );
  const ownReport = own.state.reports[message.id];

  const candidates = [report, ownReport, override].filter(isReport);
  const shown =
    candidates.sort(
      (a, b) => Date.parse(b.measuredAt) - Date.parse(a.measuredAt),
    )[0] ?? null;
  const failed =
    streamError ??
    own.state.errors[message.id] ??
    (report && !isReport(report) ? report.error : undefined);
  const inProgress =
    reanalyzing ||
    (!shown && pendingStatus && !failed) ||
    (live && message.status === "analyzing");
  const prog = progress ?? own.state.progress[message.id];
  const stepLabels = Object.keys(steps ?? {}).length
    ? steps!
    : Object.keys(own.state.steps).length
      ? own.state.steps
      : DEFAULT_STEPS;
  const { address, messages } = useAddress(message, readOnly ? [] : siblings, givenAddress);
  const previous = usePrevious(message, messages, readOnly);

  useEffect(() => {
    // a shared report is not this browser's: it stays out of the recent searches
    if (shown && message.from && !readOnly)
      pushRecent({
        value: message.from,
        path: `/mail/message/${message.id}`,
        label: msg("Test de mail"),
      });
    // once per message
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [message.id, !!shown]);
  useEffect(() => setAxis(null), [message.id]);

  const [posting, setPosting] = useState(false);
  const reanalyze = () => {
    setReErr(null);
    setReanalyzing(true);
  };
  // the stream must be open before the request, to see every step of the new analysis
  useEffect(() => {
    if (!reanalyzing || posting) return;
    if (live || own.conn === "open") return setPosting(true);
    const timer = setTimeout(() => setPosting(true), 1500);
    return () => clearTimeout(timer);
  }, [reanalyzing, posting, live, own.conn]);
  useEffect(() => {
    if (!posting) return;
    let alive = true;
    post<{ report: StoredReport | null }>(
      `/api/mail/messages/${encodeURIComponent(message.id)}/reanalyze`,
    )
      .then((res) => {
        if (!alive) return;
        if (isReport(res.report)) setOverride(res.report);
        else setReErr(res.report?.error ?? t("L’analyse n’a rien rendu."));
      })
      .catch((e) => alive && setReErr(errorMessage(e)))
      .finally(() => {
        if (!alive) return;
        setPosting(false);
        setReanalyzing(false);
      });
    return () => {
      alive = false;
    };
  }, [posting, message.id]);

  const d = shown?.data;
  const timing = timingOf(message, d);
  const origin = typeof window !== "undefined" ? window.location.origin : "";
  const permalink = readOnly
    ? `${origin}/partage/${encodeURIComponent(sharedToken)}`
    : `${origin}/mail/message/${message.id}`;
  const rawUrl = readOnly
    ? `/api/shared/${encodeURIComponent(sharedToken)}/raw`
    : `/api/mail/messages/${encodeURIComponent(message.id)}/raw`;
  const subjectText = decodeWords(
    d?.message.subject ?? message.subject ?? undefined,
  )?.trim();
  const ind = shown ? indicatorsOfReport(shown) : undefined;
  const findings = shown?.findings ?? [];
  const passed = (shown?.passed ?? []).map((p) => ({
    ...p,
    detail: decodeWords(p.detail),
  }));

  // the verdict: from the two indicators when the report has them, else from the score
  let head:
    Headline | { tone: Tone; mood: string; main: string; rest?: string };
  if (inProgress)
    head = {
      tone: "pending",
      mood: shown ? t("Nouvelle analyse en cours") : t("Analyse en cours"),
      main: t("Analyse du message en cours."),
      rest: t("Les résultats arrivent au fur et à mesure."),
    };
  else if (!shown)
    head = failed
      ? {
          tone: "neutral",
          mood: t("Analyse impossible"),
          main: t("L’analyse de ce message a échoué."),
        }
      : {
          tone: "pending",
          mood: t("Chargement"),
          main: t("Lecture du compte rendu."),
        };
  else if (ind) head = headlineOf(findings, ind);
  else {
    const verdictTone = toneOf(shown.score, findings);
    const tone = verdictTone === "good" || verdictTone === "watch" || verdictTone === "bad" ? verdictTone : "neutral";
    head = {
      tone,
      mood: tone === "neutral" ? t("Non mesuré") : t(MOOD[tone]),
      main: verdictSentence(findings, passed),
    };
  }

  const sends = message.via === "upload" ? [] : numberSends(messages);
  const prevSend = previous && sends.find((s) => s.id === previous.id);
  const facts = [
    { label: t("De"), value: fromOf(message, shown), mono: true },
    {
      label: t("Objet"),
      value: subjectText ? t("«\u00a0{subject}\u00a0»", { subject: subjectText }) : t("(sans objet)"),
    },
    ...(d?.provider
      ? [
          {
            label: t("Fournisseur"),
            value: (d.provider.confidence ?? 1) < 0.5 ? t("{name} (probable)", { name: d.provider.name }) : d.provider.name,
          },
        ]
      : []),
    ...(timing.receivedAt !== undefined
      ? [{ label: t("Reçu"), value: t("reçu le {when}", { when: fmtWhen(timing.receivedAt) }) }]
      : []),
  ];

  const actions = readOnly ? (
    <>
      <Link className="btn" to="/mail">
        <MailCheck aria-hidden />
        {t("Tester un de vos messages")}
      </Link>
      <span className="mr-grow" />
      <span className="mr-iconset">
        <button
          type="button"
          className="btn btn--icon btn--ghost"
          aria-label={t("Copier le lien de partage")}
          title={t("Copier le lien de partage")}
          onClick={() =>
            copyText(permalink).then((ok) => ok && toast(t("Lien de partage copié")))
          }
        >
          <Copy aria-hidden />
        </button>
        <a
          className="btn btn--icon btn--ghost"
          href={rawUrl}
          download={`${message.id}.eml`}
          aria-label={t("Télécharger le .eml")}
          title={t("Télécharger le .eml")}
        >
          <Download aria-hidden />
        </a>
      </span>
    </>
  ) : (
    <>
      {message.via === "upload" ? (
        <Link className="btn btn--primary" to="/mail/analyse">
          <FilePlus2 aria-hidden />
          {t("Analyser un autre message")}
        </Link>
      ) : (
        <Pop
          label={t("Renvoyer un test")}
          className="btn btn--primary"
          trigger={
            <>
              <Send aria-hidden />
              {t("Renvoyer un test")}
            </>
          }
        >
          {(close) => (
            <ResendPanel address={address} following={!!live} close={close} />
          )}
        </Pop>
      )}
      {previous && !compareWith && (
        <Link
          className="btn"
          to={`/mail/message/${message.id}?comparer=${previous.id}`}
        >
          <GitCompareArrows aria-hidden />
          {prevSend
            ? t("Comparer à l’envoi {n}", { n: prevSend.n })
            : t("Comparer au précédent")}
        </Link>
      )}
      <ShareAction messageId={message.id} initial={share} />
      <span className="mr-grow" />
      <span className="mr-iconset">
        <button
          type="button"
          className="btn btn--icon btn--ghost"
          aria-label={t("Copier le lien du compte rendu")}
          title={t("Copier le lien du compte rendu")}
          onClick={() =>
            copyText(permalink).then(
              (ok) => ok && toast(t("Lien du compte rendu copié")),
            )
          }
        >
          <Copy aria-hidden />
        </button>
        <a
          className="btn btn--icon btn--ghost"
          href={rawUrl}
          download={`${message.id}.eml`}
          aria-label={t("Télécharger le .eml")}
          title={t("Télécharger le .eml")}
        >
          <Download aria-hidden />
        </a>
        <Pop
          label={t("Plus d’actions")}
          title={t("Plus d’actions")}
          className="btn btn--icon btn--ghost"
          align="end"
          trigger={<Ellipsis aria-hidden />}
        >
          {(close) => (
            <div className="mr-menu">
              <button
                type="button"
                className="mr-menu__item"
                disabled={reanalyzing || (inProgress && !shown)}
                onClick={() => {
                  close();
                  reanalyze();
                }}
              >
                <RotateCw aria-hidden />
                {t("Réanalyser ce message")}
              </button>
              <Link className="mr-menu__item" to="/mail" onClick={close}>
                <MailPlus aria-hidden />
                {t("Nouvelle adresse de test")}
              </Link>
              {message.via !== "upload" && (
                <Link
                  className="mr-menu__item"
                  to="/mail/analyse"
                  onClick={close}
                >
                  <FilePlus2 aria-hidden />
                  {t("Analyser un message reçu (.eml)")}
                </Link>
              )}
            </div>
          )}
        </Pop>
      </span>
    </>
  );

  const pick = (a: Axis | null) => {
    setAxis(a);
    const list = document.getElementById("mr-list");
    if (
      a &&
      list &&
      list.getBoundingClientRect().top > window.innerHeight * 0.75
    ) {
      const reduce = window.matchMedia?.(
        "(prefers-reduced-motion: reduce)",
      ).matches;
      list.scrollIntoView({
        behavior: reduce ? "auto" : "smooth",
        block: "start",
      });
    }
  };
  const listed = axis ? findings.filter((f) => f.axis === axis) : findings;
  const counts = {
    sender: findings.filter((f) => f.axis === "sender").length,
    message: findings.filter((f) => f.axis === "message").length,
  };
  const theirs = {
    sender: findings.filter((f) => f.axis === "sender" && f.impact === "advice" && f.outOfReach).length,
    message: findings.filter((f) => f.axis === "message" && f.impact === "advice" && f.outOfReach).length,
  };

  return (
    <div className="mail-report">
      {!readOnly && (
        <SendsBar
          current={message}
          messages={messages}
          address={address}
          following={!!live}
          timing={timing}
          hrefOf={(id) => (live ? `?message=${id}` : `/mail/message/${id}`)}
        />
      )}
      <MailVerdict
        tone={head.tone}
        mood={head.mood}
        main={head.main}
        rest={head.rest}
        facts={facts}
        score={
          inProgress ? null : shown ? shown.score : failed ? undefined : null
        }
        findings={inProgress ? [] : findings}
        actions={actions}
      />
      {compareWith && compareWith !== message.id && !readOnly && (
        <CompareSection
          currentId={message.id}
          otherId={compareWith}
          closeTo={location.pathname}
        />
      )}
      {reErr && (
        <Notice tone="error" title={t("Réanalyse impossible")}>
          {reErr}
        </Notice>
      )}
      {failed && !inProgress && (
        <Notice tone="error" title={t("L’analyse de ce message a échoué")}>
          {failed}.{" "}
          {readOnly
            ? t("Seul l’auteur du partage peut relancer l’analyse.")
            : t("Le message est conservé : relancez l’analyse avec « Réanalyser ce message », dans le menu du verdict.")}
        </Notice>
      )}
      {inProgress && (
        <AnalysisProgress
          steps={stepLabels}
          progress={prog}
          title={shown ? t("Nouvelle analyse en cours") : t("Analyse en cours")}
          cards={!shown}
        />
      )}
      {shown && (
        <div
          className={`mr-body${inProgress ? " mail-stale" : ""}`}
          aria-busy={inProgress || undefined}
        >
          {ind && (
            <IndicatorPair
              r={shown}
              ind={ind}
              picked={axis}
              onPick={pick}
              listId="mr-list"
              counts={counts}
              theirs={theirs}
            />
          )}
          <div className="mr-work">
            <div className="mr-work__main" id="mr-list">
              {ind && findings.length > 0 && (
                // the filter of the list, always in sight above it (user, 2026-11-14): the selected
                // choice is filled in blue, the counts are those of the rows below
                <div className="mr-listbar">
                  <span className="mr-listbar__t" id="mr-listbar-t">
                    {t("Afficher")}
                  </span>
                  <div className="segmented segmented--lab" role="group" aria-labelledby="mr-listbar-t">
                    {([null, "sender", "message"] as const).map((a) => (
                      <button
                        key={a ?? "all"}
                        type="button"
                        aria-pressed={axis === a}
                        aria-controls="mr-list"
                        onClick={() => setAxis(a)}
                      >
                        {a && <span className={`mr-listbar__dot mr-listbar__dot--${a}`} aria-hidden />}
                        {a === null ? t("Tous les points") : a === "sender" ? t("Expéditeur") : t("Message")}
                        <span className="mr-listbar__n">{a === null ? findings.length : counts[a]}</span>
                      </button>
                    ))}
                  </div>
                  <span className="visually-hidden" role="status">
                    {axis
                      ? tn(listed.length, "Liste filtrée : {n} point sur {total}", "Liste filtrée : {n} points sur {total}", { total: findings.length })
                      : ""}
                  </span>
                </div>
              )}
              <IssueList
                findings={listed}
                passed={axis ? undefined : passed}
                extra={(f) => <Measured f={f} r={shown} />}
                empty={
                  axis
                    ? t("Rien à reprendre de ce côté.")
                    : t("Rien à corriger dans ce message.")
                }
              />
            </div>
            <aside
              className="mr-side"
              aria-label={t("Parcours et faits de cet envoi")}
            >
              <section className="surface mr-card" aria-labelledby="mr-path-t">
                <h2 id="mr-path-t">{t("Parcours")}</h2>
                <PathCard
                  hops={shown.data.hops}
                  date={shown.data.message.date}
                  receivedAt={timing.receivedAt}
                />
              </section>
              <section className="surface mr-card" aria-labelledby="mr-send-t">
                <h2 id="mr-send-t">{t("Cet envoi")}</h2>
                <SendFacts m={message} d={shown.data} timing={timing} />
              </section>
            </aside>
          </div>
          <Preview r={shown} messageId={message.id} />
          <TechTabs
            r={shown}
            messageId={message.id}
            rawUrl={rawUrl}
            receivedBy={message.rcptTo?.[0]?.split("@")[1]}
          />
        </div>
      )}
      {!shown && !inProgress && !failed && (
        <div className="surface mr-skel" aria-busy="true">
          {[0, 1, 2].map((i) => (
            <div key={i}>
              <Skel w="40%" />
              <Skel w="10%" />
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
