// Landing of the Whois tool: one domain in the big input; a list pasted there, or typed in the
// list field below it, opens the table.
import { useState, type ClipboardEvent, type FormEvent, type ReactNode } from 'react';
import { useNavigate } from 'react-router';
import { ListPlus } from 'lucide-react';
import { ToolHero } from '../../components/ToolHero';
import { TOOLS } from '../../app/tools';
import { t, tn } from '../../lib/i18n';
import { BATCH_MAX, listPath, parseList } from './model';

export function WhoisHero({ children }: { children?: ReactNode }) {
  const navigate = useNavigate();
  const [list, setList] = useState('');
  const [error, setError] = useState<string | null>(null);
  const icon = TOOLS.find((x) => x.id === 'rdap')?.icon;

  /** Several names: open the table. Returns false to let the hero handle a single name. */
  const route = (raw: string): boolean => {
    const p = parseList(raw);
    if (p.domains.length < 2) return false;
    navigate(listPath(p.domains.slice(0, BATCH_MAX)));
    return true;
  };

  const submitList = (e: FormEvent) => {
    e.preventDefault();
    const p = parseList(list);
    if (!p.domains.length) {
      setError(t('Aucun nom de domaine reconnu. Mettez un domaine par ligne, par exemple exemple.fr.'));
      return;
    }
    setError(null);
    navigate(listPath(p.domains.slice(0, BATCH_MAX)));
  };
  const count = parseList(list).domains.length;

  return (
    <div className="wh-page">
      {children && <div className="stack dm-above-hero">{children}</div>}
      <div
        onPasteCapture={(e: ClipboardEvent<HTMLDivElement>) => {
          if ((e.target as HTMLElement).tagName !== 'INPUT') return;
          // a pasted list keeps its lines here: an <input> would glue them together
          const text = e.clipboardData.getData('text');
          if (/[\n,;]/.test(text.trim()) && route(text)) e.preventDefault();
        }}
        onSubmitCapture={(e: FormEvent<HTMLDivElement>) => {
          const input = (e.target as HTMLElement).querySelector('input');
          if (input && route(input.value)) {
            e.preventDefault();
            e.stopPropagation();
          }
        }}
      >
        <ToolHero
          icon={icon}
          title={t('Whois et RDAP')}
          desc={t('Le registre et le bureau d’enregistrement interrogés tous les deux, côte à côte, écarts signalés : dates, statuts EPP, bureau d’enregistrement, revendeur, contacts quand ils ne sont pas masqués, serveurs de noms.')}
          basePath="/whois"
          examples={['github.com', 'afnic.fr', 'wikipedia.org']}
        >
          <form className="wh-list surface" onSubmit={submitList} aria-labelledby="wh-list-t">
            <div className="wh-list__head">
              <ListPlus aria-hidden />
              <h2 id="wh-list-t" className="wh-list__title">
                {t('Plusieurs domaines')}
              </h2>
              <span className="muted wh-list__hint">{t('un par ligne, {max} au plus, tableau exportable', { max: BATCH_MAX })}</span>
            </div>
            <textarea
              aria-labelledby="wh-list-t"
              aria-describedby={error ? 'wh-list-err' : undefined}
              aria-invalid={error ? true : undefined}
              value={list}
              onChange={(e) => setList(e.target.value)}
              rows={4}
              spellCheck={false}
              autoCapitalize="off"
              autoComplete="off"
              placeholder={t('exemple.fr\nexemple.com\nexemple.org')}
            />
            {error && (
              <p className="hero__error" id="wh-list-err" role="alert">
                {error}
              </p>
            )}
            <div className="wh-list__foot">
              <span className="muted">{count > BATCH_MAX ? t('{count} domaines : seuls les {max} premiers seront mesurés', { count, max: BATCH_MAX }) : count ? tn(count, '{n} domaine', '{n} domaines') : ''}</span>
              <button type="submit" className="btn btn--sm">
                {t('Mesurer la liste')}
              </button>
            </div>
          </form>
        </ToolHero>
      </div>
    </div>
  );
}
