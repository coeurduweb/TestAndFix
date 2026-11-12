// Home (Signal, warmed up 2026-11-11). The universal input first; then the two tools that repair a
// whole chain, put forward at the request of the user (« on ne met pas assez en avant l'outil de
// check de mail [...] Pareil pour la propagation sans cache réseau »): the mail test and the DNS
// propagation, each in its own large card; then entries by symptom; then every tool by family, each
// with the hue of its family. The recent measurements stay beside the input.
// The input is focused on load; its suggestion list opens only once something is typed.
import { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router';
import { ArrowRight, ChevronRight } from 'lucide-react';
import { get, post } from '../../lib/api';
import { toDomain } from '../../lib/detect';
import { fmtRelative, fmtScore, scoreBand } from '../../lib/format';
import { fmtCount } from '../dns/fmt';
import { msg, rich, t } from '../../lib/i18n';
import { useAuth } from '../../app/auth';
import { famClass, GROUPS, toolById, TOOLS } from '../../app/tools';
import { Omnibox } from '../../app/Omnibox';
import { Skel } from '../../components/ui';
import { MailPath } from '../../components/MailPath';
import { dots, GRID } from '../propagation/dots';
import './home.css';

interface HistoryItem {
  id: string;
  tool: string;
  input: string;
  at: string;
  score: number | null;
  summary: { addressId?: string; subject?: string } | null;
}

const EXAMPLES = [
  { label: 'github.com', path: '/domaine/github.com' },
  { label: '8.8.8.8', path: '/ip/8.8.8.8' },
  { label: 'MX gmail.com', path: '/dns/gmail.com?type=MX' },
  { label: 'http://github.com', path: '/redirections?url=http%3A%2F%2Fgithub.com' },
];

/** What a client says on the phone, and the tool that answers it. */
const SYMPTOMS: { text: string; tool: string; path?: string }[] = [
  { text: msg('Mes mails arrivent en spam'), tool: 'mail' },
  { text: msg('Mon site ne répond plus depuis le changement de DNS'), tool: 'propagation' },
  { text: msg('Un destinataire ne reçoit pas mes mails'), tool: 'domain' },
  { text: msg('Je ne reçois plus de mails'), tool: 'smtp' },
  { text: msg('Mon IP ou mon domaine est-il sur une liste noire ?'), tool: 'ip' },
  { text: msg('Ce lien reçu par mail est-il sûr ?'), tool: 'link' },
  { text: msg('Pourquoi ce message est-il arrivé là ?'), tool: 'mail-analyze' },
  { text: msg('Je configure les mails d’un nouveau domaine'), tool: 'gen-spf' },
];

function pathOf(item: HistoryItem): string {
  if (item.tool === 'mail') return `/mail/message/${item.id}`;
  const t = toolById(item.tool);
  if (!t) return '/historique';
  const [first, type] = item.input.split(' ');
  if (item.tool === 'link') return `/lien?url=${encodeURIComponent(item.input)}`;
  if (item.tool === 'redirects') return `/redirections?url=${encodeURIComponent(item.input)}`;
  if (t.routes.some((r) => r.includes(':'))) return `${t.path}/${encodeURIComponent(first)}${type ? `?type=${encodeURIComponent(type.toUpperCase())}` : ''}`;
  return t.path;
}

const label = (it: HistoryItem) => {
  const [first, type] = it.input.split(' ');
  return type ? `${first} · ${type.toUpperCase()}` : it.input || it.summary?.subject || t('sans objet');
};

function MailCard({ onStart, starting }: { onStart: () => void; starting: boolean }) {
  const mail = toolById('mail')!;
  const analyze = toolById('mail-analyze')!;
  const Icon = mail.icon;
  return (
    <article className="flag-card fam--mail" aria-labelledby="flag-mail-t">
      <div className="flag-card__head">
        <span className="ftile ftile--lg" aria-hidden>
          <Icon aria-hidden />
        </span>
        <div>
          <h2 className="flag-card__title" id="flag-mail-t">
            {t('Test de mail')}
          </h2>
          <p className="flag-card__desc">
            {t('Toute la chaîne d’un vrai message, du serveur d’envoi à la boîte de réception. Envoyez-le à l’adresse de test : le compte rendu arrive tout seul.')}
          </p>
        </div>
      </div>
      <MailPath />
      <div className="flag-card__actions">
        <button type="button" className="btn btn--primary" onClick={onStart} disabled={starting} aria-busy={starting || undefined}>
          {t('Obtenir une adresse de test')}
          <ArrowRight aria-hidden />
        </button>
        <Link to={analyze.path} className="flag-card__alt">
          {t('Message déjà reçu : analyser ses en-têtes')}
        </Link>
      </div>
    </article>
  );
}

function PropagationCard({ authenticated }: { authenticated: boolean }) {
  const tool = toolById('propagation')!;
  const Icon = tool.icon;
  const navigate = useNavigate();
  const [value, setValue] = useState('');
  const [error, setError] = useState(false);
  // the real reach of the last daily qualification, never a figure written by hand
  const [reach, setReach] = useState<{ total: number; countries: number } | null>(null);
  useEffect(() => {
    if (!authenticated) return;
    get<{ total: number; qualification: { countries: number } | null }>('/api/propagation/resolvers')
      .then((r) => r.qualification && r.total > 0 && setReach({ total: r.total, countries: r.qualification.countries }))
      .catch(() => setReach(null));
  }, [authenticated]);
  return (
    <article className="flag-card fam--dns" aria-labelledby="flag-prop-t">
      <div className="flag-card__head">
        <span className="ftile ftile--lg" aria-hidden>
          <Icon aria-hidden />
        </span>
        <div>
          <h2 className="flag-card__title" id="flag-prop-t">
            {t('Propagation DNS')}
          </h2>
          <p className="flag-card__desc">
            {t('Ce que voient les résolveurs du monde entier, face à la réponse des serveurs autoritaires. Aucun cache de notre côté : chaque mesure part de la racine.')}
          </p>
        </div>
      </div>
      <svg className="flag-map" viewBox={`0 0 ${GRID.W} ${GRID.H}`} preserveAspectRatio="xMidYMid meet" aria-hidden>
        <path d={dots()} />
      </svg>
      {reach && (
        <p className="flag-card__reach">
          {rich('<b>{total}</b> résolveurs qualifiés dans <b>{countries}</b> pays', { total: fmtCount(reach.total), countries: fmtCount(reach.countries) }, { b: (c) => <strong>{c}</strong> })}
        </p>
      )}
      <form
        className="flag-card__form"
        onSubmit={(e) => {
          e.preventDefault();
          const d = toDomain(value.trim());
          if (!d) return setError(true);
          navigate(`${tool.path}/${encodeURIComponent(d)}`);
        }}
      >
        <input
          aria-label={t('Nom à mesurer')}
          aria-invalid={error || undefined}
          aria-describedby={error ? 'flag-prop-err' : undefined}
          placeholder={t('exemple.fr')}
          value={value}
          onChange={(e) => {
            setValue(e.target.value);
            setError(false);
          }}
          spellCheck={false}
          autoCapitalize="off"
          autoComplete="off"
          inputMode="url"
        />
        <button type="submit" className="btn btn--primary">
          {t('Mesurer')}
          <ArrowRight aria-hidden />
        </button>
      </form>
      {error && (
        <p className="flag-card__error" id="flag-prop-err" role="alert">
          {t('Saisissez un nom de domaine, par exemple exemple.fr.')}
        </p>
      )}
    </article>
  );
}

export default function Home() {
  const { authenticated } = useAuth();
  const navigate = useNavigate();
  const [items, setItems] = useState<HistoryItem[] | null>(null);
  const [starting, setStarting] = useState(false);

  useEffect(() => {
    if (!authenticated) return setItems([]);
    get<{ items: HistoryItem[] }>('/api/history?limit=60')
      .then((r) => {
        // one line per measured object: the most recent of each tool + input
        const seen = new Set<string>();
        setItems(
          r.items
            .filter((it) => {
              const k = `${it.tool}|${it.input}`;
              if (seen.has(k)) return false;
              seen.add(k);
              return true;
            })
            .slice(0, 8),
        );
      })
      .catch(() => setItems([]));
  }, [authenticated]);

  const startMailTest = async () => {
    setStarting(true);
    try {
      const a = await post<{ id: string }>('/api/mail/addresses', {});
      navigate(`/mail/${a.id}`);
    } catch {
      navigate('/mail');
    } finally {
      setStarting(false);
    }
  };

  return (
    <div className="home">
      <div className="home-top">
        <section className="home-hero" aria-labelledby="home-t">
          <h1 className="home-hero__title" id="home-t">
            {t('Que voulez-vous vérifier ?')}
          </h1>
          <p className="home-hero__desc">{t("Un domaine, une IP, une URL, une adresse ou des en-têtes : TestAndFix reconnaît l'outil. Chaque mesure est faite maintenant, sans cache.")}</p>
          <div className="home-hero__input">
            <Omnibox size="lg" autoFocus />
          </div>
          <div className="chips home-hero__row" aria-label={t('Exemples')}>
            {EXAMPLES.map((e) => (
              <Link key={e.label} to={e.path} className="chip home-hero__ex">
                {e.label}
              </Link>
            ))}
          </div>
        </section>

        {authenticated && (
          <section className="home-recent-wrap" aria-labelledby="recent-t">
            <h2 className="home-h" id="recent-t">
              {t('Dernières mesures')}
              <Link to="/historique" className="home-more">
                {t("Tout l'historique")}
              </Link>
            </h2>
            {items === null ? (
              <ul className="surface home-recent" aria-busy="true">
                {[0, 1, 2, 3].map((i) => (
                  <li key={i} className="home-recent__item">
                    <Skel w="60%" />
                  </li>
                ))}
              </ul>
            ) : items.length === 0 ? (
              <p className="home-empty">{t("Aucune mesure pour l'instant : essayez un des exemples, ou partez d’un symptôme plus bas.")}</p>
            ) : (
              <ul className="surface home-recent">
                {items.map((it) => {
                  const tl = toolById(it.tool);
                  const Icon = tl?.icon;
                  const band = it.score === null ? null : scoreBand(it.score);
                  return (
                    <li key={it.id}>
                      <Link to={pathOf(it)} className={`home-recent__item ${famClass(tl?.group)}`}>
                        <span className="ftile ftile--sm" aria-hidden>
                          {Icon && <Icon aria-hidden />}
                        </span>
                        <span className="home-recent__text">
                          <span className="home-recent__obj">{label(it)}</span>
                          <span className="home-recent__meta">
                            {tl ? t(tl.title) : it.tool} · {fmtRelative(it.at)}
                          </span>
                        </span>
                        <span className={`home-recent__score ${band ? `is-${band}` : ''}`}>
                          {band && <span className={`dot dot--${band === 'ok' ? 'ok' : band === 'mid' ? 'warn' : 'out'}`} aria-hidden />}
                          {it.score === null ? '' : fmtScore(it.score)}
                        </span>
                      </Link>
                    </li>
                  );
                })}
              </ul>
            )}
          </section>
        )}
      </div>

      <div className="home-flags">
        <MailCard onStart={startMailTest} starting={starting} />
        <PropagationCard authenticated={authenticated} />
      </div>

      <section aria-labelledby="sym-t" className="home-sym">
        <h2 className="home-h2" id="sym-t">
          {t('Partir d’un symptôme')}
        </h2>
        <ul className="sym-list">
          {SYMPTOMS.map((s) => {
            const tool = toolById(s.tool)!;
            const Icon = tool.icon;
            return (
              <li key={s.text}>
                <Link to={s.path ?? tool.path} className={`sym ${famClass(tool.group)}`}>
                  <span className="ftile" aria-hidden>
                    <Icon aria-hidden />
                  </span>
                  <span className="sym__text">
                    <span className="sym__q">{t(s.text)}</span>
                    <span className="sym__tool">{t(tool.title)}</span>
                  </span>
                  <ChevronRight className="sym__go" aria-hidden />
                </Link>
              </li>
            );
          })}
        </ul>
      </section>

      <section aria-labelledby="tools-t" className="home-tools">
        <h2 className="home-h2" id="tools-t">
          {t('Tous les outils')}
        </h2>
        <div className="home-groups">
          {GROUPS.filter((g) => g.id !== 'outils').map((g) => (
            <div key={g.id} className={`home-group ${famClass(g.id)}`}>
              <h3 className="home-group__title">
                <span className="home-group__swatch" aria-hidden />
                {t(g.title)}
              </h3>
              <ul>
                {TOOLS.filter((tl) => tl.group === g.id).map((tl) => {
                  const Icon = tl.icon;
                  return (
                    <li key={tl.id}>
                      <Link to={tl.path} className="home-tool">
                        <span className="ftile ftile--sm" aria-hidden>
                          <Icon aria-hidden />
                        </span>
                        <span className="home-tool__text">
                          <span className="home-tool__title">{t(tl.title)}</span>
                          <span className="home-tool__desc">{t(tl.description)}</span>
                        </span>
                      </Link>
                    </li>
                  );
                })}
              </ul>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
