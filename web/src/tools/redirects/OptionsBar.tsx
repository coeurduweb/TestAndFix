// Compact options above the report: user agent, method, cookies, added headers.
// Every change rewrites the page URL, which re-runs the trace.
import { useEffect, useState, type ReactNode } from 'react';
import { Plus, Settings2, X } from 'lucide-react';
import { rich, t, tn } from '../../lib/i18n';
import { UAS, uaLabel, type TraceOptions } from './model';

export function OptionsBar({ value, onChange, withMethod = true }: { value: TraceOptions; onChange: (o: TraceOptions) => void; withMethod?: boolean }) {
  const [uaText, setUaText] = useState(value.uaText);
  const [rows, setRows] = useState<[string, string][]>(value.headers.length ? value.headers : [['', '']]);
  useEffect(() => setUaText(value.uaText), [value.uaText]);
  useEffect(() => setRows(value.headers.length ? value.headers : [['', '']]), [value.headers]);
  const set = (p: Partial<TraceOptions>) => onChange({ ...value, ...p });
  const applyHeaders = () => set({ headers: rows.filter(([k]) => k.trim()).map(([k, v]) => [k.trim(), v.trim()]) });
  const count = value.headers.length;

  return (
    <div className="rd-opts">
      <div className="rd-opt" role="group" aria-label={t('Agent utilisateur')}>
        <span className="rd-opt__label" aria-hidden>{t('Agent')}</span>
        <div className="segmented rd-seg">
          {UAS.map((u) => (
            <button key={u.id} type="button" aria-pressed={value.ua === u.id} title={t(u.long)} onClick={() => set({ ua: u.id })}>
              {t(u.label)}
            </button>
          ))}
        </div>
      </div>
      {value.ua === 'custom' && (
        <form
          className="rd-opt rd-opt--grow"
          onSubmit={(e) => {
            e.preventDefault();
            set({ uaText });
          }}
        >
          <label className="visually-hidden" htmlFor="rd-uat">{t('Agent utilisateur personnalisé')}</label>
          <input
            id="rd-uat"
            className="input input--mono rd-opt__input"
            value={uaText}
            placeholder="Mozilla/5.0 (compatible; MonRobot/1.0)"
            onChange={(e) => setUaText(e.target.value)}
            onBlur={() => uaText !== value.uaText && set({ uaText })}
          />
        </form>
      )}
      {withMethod && (
        <div className="rd-opt" role="group" aria-label={t('Méthode')}>
          <span className="rd-opt__label" aria-hidden>{t('Méthode')}</span>
          <div className="segmented rd-seg rd-seg--2">
            {(['GET', 'HEAD'] as const).map((m) => (
              <button key={m} type="button" className="mono" aria-pressed={value.method === m} onClick={() => set({ method: m })}>
                {m}
              </button>
            ))}
          </div>
        </div>
      )}
      <label className="rd-check">
        <input type="checkbox" checked={value.cookies} onChange={(e) => set({ cookies: e.target.checked })} />
        {t('Cookies conservés d’un saut à l’autre')}
      </label>
      <details className="rd-hdrs">
        <summary>{count ? t('En-têtes ajoutés ({n})', { n: count }) : t('En-têtes ajoutés')}</summary>
        <form
          className="rd-hdrs__form"
          onSubmit={(e) => {
            e.preventDefault();
            applyHeaders();
          }}
        >
          {rows.map(([k, v], i) => (
            <div className="rd-hdrs__row" key={i}>
              <input
                className="input input--mono"
                aria-label={t('Nom de l’en-tête {n}', { n: i + 1 })}
                placeholder="Accept-Language"
                value={k}
                onChange={(e) => setRows((r) => r.map((x, j) => (j === i ? [e.target.value, x[1]] : x)))}
              />
              <input
                className="input input--mono"
                aria-label={t('Valeur de l’en-tête {n}', { n: i + 1 })}
                placeholder="en-US"
                value={v}
                onChange={(e) => setRows((r) => r.map((x, j) => (j === i ? [x[0], e.target.value] : x)))}
              />
              <button type="button" className="btn btn--ghost btn--icon" aria-label={t('Retirer l’en-tête {n}', { n: i + 1 })} onClick={() => setRows((r) => (r.length > 1 ? r.filter((_, j) => j !== i) : [['', '']]))}>
                <X aria-hidden />
              </button>
            </div>
          ))}
          <div className="rd-hdrs__actions">
            <button type="button" className="btn btn--sm btn--ghost" onClick={() => setRows((r) => [...r, ['', '']])}>
              <Plus aria-hidden />
              {t('Ajouter un en-tête')}
            </button>
            <button type="submit" className="btn btn--sm">{t('Appliquer et relancer')}</button>
          </div>
          <p className="field__hint">{t('Ajoutés à chaque requête de la chaîne. Host, Connection et Content-Length restent gérés par l’outil.')}</p>
        </form>
      </details>
    </div>
  );
}

function sentLine(options: TraceOptions, withMethod: boolean, extra: number): ReactNode {
  const ua = options.ua === 'custom' ? t('agent personnalisé') : uaLabel(options.ua);
  const cookies = options.cookies ? t('cookies conservés') : t('sans cookies');
  const headers = tn(extra, '{n} en-tête ajouté', '{n} en-têtes ajoutés');
  const tags = { b: (c: ReactNode) => <strong>{c}</strong>, m: (c: ReactNode) => <strong className="mono">{c}</strong> };
  const vars = { ua, method: options.method, cookies, headers };
  if (withMethod) return extra > 0 ? rich('Envoyé comme <b>{ua}</b>, en <m>{method}</m>, {cookies}, {headers}.', vars, tags) : rich('Envoyé comme <b>{ua}</b>, en <m>{method}</m>, {cookies}.', vars, tags);
  return extra > 0 ? rich('Envoyé comme <b>{ua}</b>, {cookies}, {headers}.', vars, tags) : rich('Envoyé comme <b>{ua}</b>, {cookies}.', vars, tags);
}

/** One line saying how the requests are sent, with the options to change it, folded. */
export function OptionsLine({ options, onChange, withMethod = true }: { options: TraceOptions; onChange: (o: TraceOptions) => void; withMethod?: boolean }) {
  const [open, setOpen] = useState(false);
  const extra = options.headers.length;
  return (
    <div className="rd-optline">
      <p className="rd-optline__text">
        <Settings2 aria-hidden />
        <span>
          {sentLine(options, withMethod, extra)}
        </span>
        <button type="button" className="btn btn--sm btn--ghost" aria-expanded={open} onClick={() => setOpen((o) => !o)}>
          {open ? t('Fermer les options') : t('Changer')}
        </button>
      </p>
      {open && <OptionsBar value={options} onChange={onChange} withMethod={withMethod} />}
    </div>
  );
}

