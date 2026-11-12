import { useEffect, useRef, useState, type ReactNode } from 'react';
import { NavLink, useLocation, useNavigate } from 'react-router';
import { BookLock, ChevronDown, Lock, LogOut, Menu, Moon, Sun, SunMoon, X } from 'lucide-react';
import { famClass, GROUPS, SHARED_REPORT, TOOLS, toolAt, type Group } from './tools';
import { Omnibox } from './Omnibox';
import { useAuth } from './auth';
import { setPendingFiles } from '../lib/pending';
import { chooseLang, currentLang, LANG_NAMES, LANGS, msg, t, type Lang } from '../lib/i18n';

type Theme = 'auto' | 'light' | 'dark';

function useTheme(): [Theme, (next: Theme) => void] {
  const [theme, setTheme] = useState<Theme>(() => {
    try {
      return (localStorage.getItem('check:theme') as Theme) || 'auto';
    } catch {
      return 'auto';
    }
  });
  useEffect(() => {
    const root = document.documentElement;
    if (theme === 'auto') root.removeAttribute('data-theme');
    else root.setAttribute('data-theme', theme);
    try {
      localStorage.setItem('check:theme', theme);
    } catch {
      /* ignore */
    }
  }, [theme]);
  return [theme, setTheme];
}

function useGlobalDrop() {
  const navigate = useNavigate();
  const [active, setActive] = useState(false);
  useEffect(() => {
    let depth = 0;
    const hasFiles = (e: DragEvent) => Array.from(e.dataTransfer?.types ?? []).includes('Files');
    const enter = (e: DragEvent) => {
      if (!hasFiles(e)) return;
      depth++;
      setActive(true);
    };
    const leave = () => {
      depth = Math.max(0, depth - 1);
      if (!depth) setActive(false);
    };
    const over = (e: DragEvent) => {
      if (hasFiles(e)) e.preventDefault();
    };
    const drop = (e: DragEvent) => {
      if (!hasFiles(e)) return;
      // a page that handles drops itself marks its zone
      if ((e.target as HTMLElement)?.closest('[data-own-drop]')) {
        depth = 0;
        setActive(false);
        return;
      }
      e.preventDefault();
      depth = 0;
      setActive(false);
      const files = Array.from(e.dataTransfer?.files ?? []);
      if (!files.length) return;
      setPendingFiles(files);
      const isEml = files.every((f) => /\.(eml|msg|txt)$/i.test(f.name) || f.type === 'message/rfc822');
      navigate(isEml ? '/mail/analyse' : '/rapports-dmarc');
    };
    window.addEventListener('dragenter', enter);
    window.addEventListener('dragleave', leave);
    window.addEventListener('dragover', over);
    window.addEventListener('drop', drop);
    return () => {
      window.removeEventListener('dragenter', enter);
      window.removeEventListener('dragleave', leave);
      window.removeEventListener('dragover', over);
      window.removeEventListener('drop', drop);
    };
  }, [navigate]);
  return active;
}

/** true below the menu breakpoint (60rem), where the group menus fold into one sheet */
function useNarrow(): boolean {
  const q = '(max-width: 60rem)';
  const [narrow, setNarrow] = useState(() => typeof window !== 'undefined' && window.matchMedia(q).matches);
  useEffect(() => {
    const m = window.matchMedia(q);
    const on = () => setNarrow(m.matches);
    m.addEventListener('change', on);
    return () => m.removeEventListener('change', on);
  }, []);
  return narrow;
}

/** Top navigation: five menus. "Plus" gathers reports, generators and the utilities. */
const MENUS: { id: string; title: string; groups: Group[] }[] = [
  { id: 'mail', title: msg('Mail'), groups: ['mail'] },
  { id: 'domaine', title: msg('Domaine'), groups: ['domaine'] },
  { id: 'dns', title: msg('DNS'), groups: ['dns'] },
  { id: 'reputation', title: msg('Réputation'), groups: ['reputation'] },
  { id: 'plus', title: msg('Plus'), groups: ['rapports', 'generateurs', 'outils'] },
];

function ToolLinks({ groups, authenticated, withTitles, skip }: { groups: Group[]; authenticated: boolean; withTitles?: boolean; skip?: string }) {
  return (
    <>
      {groups.map((gid) => (
        <div className="menu__group" key={gid}>
          {withTitles && <div className="menu__title">{t(GROUPS.find((g) => g.id === gid)?.title ?? '')}</div>}
          {TOOLS.filter((m) => m.group === gid && m.id !== skip).map((m) => {
            const Icon = m.icon;
            return (
              <NavLink key={m.id} to={m.path} className={`menu__link ${famClass(m.group)}`} end={m.path === '/mail'}>
                <span className={`ftile ${famClass(m.group)}`} aria-hidden>
                  <Icon aria-hidden />
                </span>
                <span>
                  <span className="menu__name">
                    {t(m.group === 'generateurs' ? m.title : m.nav)}
                    {!m.public && !authenticated && <Lock className="menu__lock" aria-label={t('mot de passe requis')} />}
                  </span>
                  <span className="menu__desc">{t(m.description)}</span>
                </span>
              </NavLink>
            );
          })}
        </div>
      ))}
    </>
  );
}

/** Language of the interface: a native select, each language named in itself. Choosing reloads the page (chooseLang). */
function LangSwitch() {
  return (
    <select className="lang-select" aria-label={t('Langue')} value={currentLang()} onChange={(e) => chooseLang(e.target.value as Lang)}>
      {LANGS.map((l) => (
        <option key={l} value={l} lang={l}>
          {LANG_NAMES[l]}
        </option>
      ))}
    </select>
  );
}

export function Shell({ children }: { children: ReactNode }) {
  const { authenticated, logout } = useAuth();
  const [open, setOpen] = useState<string | null>(null);
  const [theme, setTheme] = useTheme();
  const location = useLocation();
  const dropping = useGlobalDrop();
  const narrow = useNarrow();
  const navRef = useRef<HTMLElement>(null);

  useEffect(() => setOpen(null), [location.pathname]);
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        const btn = document.querySelector<HTMLElement>(`[data-menu="${open}"]`);
        setOpen(null);
        btn?.focus();
      }
    };
    const onDown = (e: PointerEvent) => {
      if (!navRef.current?.contains(e.target as Node)) setOpen(null);
    };
    window.addEventListener('keydown', onKey);
    window.addEventListener('pointerdown', onDown);
    return () => {
      window.removeEventListener('keydown', onKey);
      window.removeEventListener('pointerdown', onDown);
    };
  }, [open]);
  // move focus to the main region on route change (screen readers), but never on the first load
  // and never away from a field that already has it (autoFocus inputs, a user already typing)
  const firstRoute = useRef(true);
  useEffect(() => {
    if (firstRoute.current) {
      firstRoute.current = false;
      return;
    }
    const active = document.activeElement as HTMLElement | null;
    const typing = active?.matches('input, textarea, select, [contenteditable="true"]');
    if (!typing) document.getElementById('main')?.focus({ preventScroll: true });
    window.scrollTo(0, 0);
  }, [location.pathname]);

  const nextTheme: Record<Theme, Theme> = { auto: 'light', light: 'dark', dark: 'auto' };
  const ThemeIcon = theme === 'auto' ? SunMoon : theme === 'light' ? Sun : Moon;
  const themeLabel = { auto: t('Thème : système'), light: t('Thème : clair'), dark: t('Thème : sombre') }[theme];
  const here = location.pathname.startsWith(SHARED_REPORT.path + '/') ? SHARED_REPORT : toolAt(location.pathname);
  const currentMenu = MENUS.find((m) => m.groups.includes(here?.group as Group))?.id;
  // the family of the page tints the ambient light and the tool head (--fam on <html>)
  useEffect(() => {
    const root = document.documentElement;
    if (here) root.dataset.fam = here.group;
    else delete root.dataset.fam;
  }, [here]);

  return (
    <div className="shell dropzone" data-active={dropping}>
      <a className="skip-link" href="#main">
        {t('Aller au contenu')}
      </a>
      <header className="topbar">
        <NavLink to="/" className="brand">
          <span className="brand__mark" aria-hidden>
            <span className="brand__dot" />
          </span>
          <span className="brand__name">TestAndFix</span>
          <span className="visually-hidden">{t(', accueil')}</span>
        </NavLink>
        <nav className="topnav" aria-label={t('Outils')} ref={navRef}>
          {narrow ? (
            <>
              <button type="button" className="topnav__btn" data-menu="all" aria-expanded={open === 'all'} aria-controls="menu-all" onClick={() => setOpen(open === 'all' ? null : 'all')}>
                {open === 'all' ? <X aria-hidden /> : <Menu aria-hidden />}
                <span className="visually-hidden">{t('Outils')}</span>
              </button>
              {open === 'all' && (
                <div className="menu menu--sheet" id="menu-all">
                  {/* the notebook first on a phone: the top bar has no room for its own entry */}
                  {authenticated && (
                    <div className="menu__group">
                      <NavLink to="/carnet" className="menu__link fam--outils">
                        <span className="ftile" aria-hidden>
                          <BookLock aria-hidden />
                        </span>
                        <span>
                          <span className="menu__name">{t('Mon carnet')}</span>
                          <span className="menu__desc">{t('Vos données ne sont visibles que d’ici et de vos appareils reliés.')}</span>
                        </span>
                      </NavLink>
                    </div>
                  )}
                  <ToolLinks groups={GROUPS.map((g) => g.id)} authenticated={authenticated} withTitles skip={authenticated ? 'carnet' : undefined} />
                  <div className="menu__group menu__lang">
                    <span className="menu__title" aria-hidden>
                      {t('Langue')}
                    </span>
                    <LangSwitch />
                  </div>
                </div>
              )}
            </>
          ) : (
            MENUS.map((m) => (
              <div className="topnav__item" key={m.id}>
                <button
                  type="button"
                  className="topnav__btn"
                  data-menu={m.id}
                  data-current={currentMenu === m.id || undefined}
                  aria-expanded={open === m.id}
                  aria-controls={`menu-${m.id}`}
                  onClick={() => setOpen(open === m.id ? null : m.id)}
                >
                  {t(m.title)}
                  <ChevronDown aria-hidden />
                </button>
                {open === m.id && (
                  <div className={`menu${m.groups.length > 1 ? ' menu--wide' : ''}`} id={`menu-${m.id}`}>
                    <ToolLinks groups={m.groups} authenticated={authenticated} withTitles={m.groups.length > 1} />
                  </div>
                )}
              </div>
            ))
          )}
        </nav>
        {/* the home page has its own big input: no second one in the top bar */}
        <div className="topbar__search">{location.pathname !== '/' && <Omnibox />}</div>
        <div className="topbar__tools">
          {authenticated && !narrow && (
            <NavLink to="/carnet" className="btn btn--ghost topbar__carnet" title={t('Mon carnet : vos données, visibles seulement d’ici et de vos appareils reliés')}>
              <BookLock aria-hidden />
              <span>{t('Mon carnet')}</span>
            </NavLink>
          )}
          {!narrow && <LangSwitch />}
          <button type="button" className="btn btn--icon btn--ghost" aria-label={t('{label}. Changer', { label: themeLabel })} title={themeLabel} onClick={() => setTheme(nextTheme[theme])}>
            <ThemeIcon aria-hidden />
          </button>
          {authenticated && (
            <button type="button" className="btn btn--icon btn--ghost" aria-label={t('Se déconnecter')} title={t('Se déconnecter')} onClick={() => logout()}>
              <LogOut aria-hidden />
            </button>
          )}
        </div>
      </header>
      <main id="main" className="content" tabIndex={-1} style={{ outline: 'none' }}>
        {children}
      </main>
      {dropping && <div className="dropzone__hint">{t('Déposez un .eml ou des rapports DMARC')}</div>}
    </div>
  );
}
