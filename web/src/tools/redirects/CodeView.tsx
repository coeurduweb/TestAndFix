// Source view of a body: line numbers, internal scroll, search with match navigation, wrap
// toggle, copy, and an optional rendered preview in a sandboxed iframe (no script, no request).
import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { ChevronDown, ChevronUp, Eye, EyeOff, Search, WrapText } from 'lucide-react';
import { CopyButton } from '../../components/ui';
import { t } from '../../lib/i18n';

const FIRST_LINES = 3000;

function highlight(line: string, q: string, base: number, current: number): ReactNode {
  if (!q) return line || ' ';
  const out: ReactNode[] = [];
  const low = line.toLowerCase();
  let i = 0;
  let n = 0;
  for (;;) {
    const at = low.indexOf(q, i);
    if (at < 0) break;
    if (at > i) out.push(line.slice(i, at));
    const id = base + n;
    out.push(
      <mark key={at} data-m={id} className={id === current ? 'rd-mark rd-mark--on' : 'rd-mark'}>
        {line.slice(at, at + q.length)}
      </mark>,
    );
    n++;
    i = at + q.length;
  }
  out.push(line.slice(i));
  return out.length > 1 ? out : line || ' ';
}

/** Inert copy of the HTML for the preview: scripts, frames, external styles, refresh and links removed. */
function inertHtml(html: string): string {
  const doc = new DOMParser().parseFromString(html, 'text/html');
  doc.querySelectorAll('script, noscript, iframe, frame, frameset, object, embed, link, base, meta[http-equiv], form, portal').forEach((n) => n.remove());
  doc.querySelectorAll('*').forEach((el) => {
    for (const a of [...el.attributes]) {
      if (/^on/i.test(a.name) || /href$/i.test(a.name) || a.name === 'srcset' || a.name === 'ping' || a.name === 'action' || a.name === 'formaction') el.removeAttribute(a.name);
      if ((a.name === 'src' || a.name === 'poster' || a.name === 'data') && !/^data:/i.test(a.value)) el.removeAttribute(a.name);
      if (a.name === 'style' && /url\s*\(/i.test(a.value)) el.setAttribute('style', a.value.replace(/url\s*\([^)]*\)/gi, 'none'));
    }
  });
  const csp = `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; font-src data:">`;
  // color-scheme light: the browser paints its own default white canvas, as for a real visit
  return `<!doctype html><html><head>${csp}<meta name="color-scheme" content="light">${doc.head.innerHTML}</head><body>${doc.body.innerHTML}</body></html>`;
}

export function CodeView({ text, isHtml, meta }: { text: string; isHtml: boolean; meta: ReactNode }) {
  const [q, setQ] = useState('');
  const [current, setCurrent] = useState(0);
  const [wrap, setWrap] = useState(true);
  const [all, setAll] = useState(false);
  const [preview, setPreview] = useState(false);
  const box = useRef<HTMLDivElement>(null);
  const lines = useMemo(() => text.split(/\r?\n/), [text]);
  const shown = all ? lines : lines.slice(0, FIRST_LINES);
  const needle = q.trim().toLowerCase();

  // match offsets per line, for numbering marks across lines
  const { starts, total } = useMemo(() => {
    const starts: number[] = [];
    let total = 0;
    for (const l of shown) {
      starts.push(total);
      if (!needle) continue;
      const low = l.toLowerCase();
      for (let i = low.indexOf(needle); i >= 0; i = low.indexOf(needle, i + needle.length)) total++;
    }
    return { starts, total };
  }, [shown, needle]);
  const hiddenMatches = useMemo(() => {
    if (!needle || all || lines.length <= FIRST_LINES) return 0;
    return lines.slice(FIRST_LINES).reduce((n, l) => n + (l.toLowerCase().split(needle).length - 1), 0);
  }, [lines, needle, all]);

  useEffect(() => setCurrent(0), [needle]);
  useEffect(() => {
    if (!needle || !total) return;
    const el = box.current?.querySelector<HTMLElement>(`mark[data-m="${current}"]`);
    if (el && box.current) {
      const top = el.offsetTop - box.current.clientHeight / 3;
      box.current.scrollTo({ top: Math.max(0, top), behavior: 'auto' });
    }
  }, [current, needle, total]);

  const step = (d: number) => total && setCurrent((c) => (c + d + total) % total);
  const srcDoc = useMemo(() => (preview && isHtml ? inertHtml(text) : ''), [preview, isHtml, text]);

  return (
    <div className="rd-code">
      <div className="rd-code__bar">
        <span className="rd-code__meta">{meta}</span>
        <div className="rd-code__tools">
          <label className="rd-search">
            <Search aria-hidden />
            <span className="visually-hidden">{t('Rechercher dans le corps')}</span>
            <input
              type="search"
              className="input input--mono"
              value={q}
              placeholder={t('Rechercher')}
              onChange={(e) => setQ(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') {
                  e.preventDefault();
                  step(e.shiftKey ? -1 : 1);
                }
              }}
            />
          </label>
          {needle && (
            <span className="rd-search__count mono" aria-live="polite">
              {total ? `${current + 1}/${total}` : '0'}
              {hiddenMatches > 0 && ` ${t('(+{n} plus bas)', { n: hiddenMatches })}`}
            </span>
          )}
          <button type="button" className="btn btn--ghost btn--icon" aria-label={t('Résultat précédent')} disabled={!total} onClick={() => step(-1)}>
            <ChevronUp aria-hidden />
          </button>
          <button type="button" className="btn btn--ghost btn--icon" aria-label={t('Résultat suivant')} disabled={!total} onClick={() => step(1)}>
            <ChevronDown aria-hidden />
          </button>
          <button type="button" className="btn btn--ghost btn--sm" aria-pressed={wrap} onClick={() => setWrap((w) => !w)}>
            <WrapText aria-hidden />
            {t('Retour à la ligne')}
          </button>
          <CopyButton text={text} label={t('Copier')} what={t('Corps copié')} />
          {isHtml && (
            <button type="button" className="btn btn--ghost btn--sm" aria-pressed={preview} onClick={() => setPreview((p) => !p)}>
              {preview ? <EyeOff aria-hidden /> : <Eye aria-hidden />}
              {preview ? t('Masquer l’aperçu') : t('Aperçu')}
            </button>
          )}
        </div>
      </div>
      {preview && isHtml && (
        <div className="rd-preview">
          <p className="rd-preview__note">{t('Aperçu sans script, sans image ni feuille de style externes, liens désactivés.')}</p>
          <iframe title={t('Aperçu rendu du corps HTML')} sandbox="" srcDoc={srcDoc} referrerPolicy="no-referrer" />
        </div>
      )}
      <div ref={box} className={`rd-code__scroll ${wrap ? 'rd-code__scroll--wrap' : ''}`} tabIndex={0} role="region" aria-label={t('Code source du corps')}>
        <ol className="rd-lines">
          {shown.map((l, i) => (
            <li key={i}>
              <span className="rd-ln" aria-hidden>
                {i + 1}
              </span>
              <code>{highlight(l, needle, starts[i], current)}</code>
            </li>
          ))}
        </ol>
      </div>
      {!all && lines.length > FIRST_LINES && (
        <button type="button" className="btn btn--sm rd-code__more" onClick={() => setAll(true)}>
          {t('Afficher les {n} lignes', { n: lines.length })}
        </button>
      )}
    </div>
  );
}
