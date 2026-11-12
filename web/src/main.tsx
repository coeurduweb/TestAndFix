import { lazy, StrictMode, Suspense, type ComponentType } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter, Route, Routes } from 'react-router';
import '@fontsource-variable/mona-sans/wdth.css';
import '@fontsource-variable/jetbrains-mono';
import './styles/tokens.css';
import './styles/base.css';
import './styles/components.css';
import './styles/signal.css';
import { AuthProvider, useAuth } from './app/auth';
import { Shell } from './app/Shell';
import { LoginPanel } from './app/Login';
import { SHARED_REPORT, TOOLS, type ToolMeta } from './app/tools';
import { ToastProvider, Empty, Skel } from './components/ui';
import Home from './tools/home/Page';
import { initI18n, t } from './lib/i18n';

const pages = import.meta.glob<{ default: ComponentType }>('./tools/*/Page.tsx');
// One lazy component per tool, created once: recreating it on each render suspends navigation forever.
const lazyCache = new Map<string, ComponentType | null>();
const lazyPage = (id: string) => {
  if (!lazyCache.has(id)) {
    const loader = pages[`./tools/${id}/Page.tsx`];
    lazyCache.set(id, loader ? lazy(loader) : null);
  }
  return lazyCache.get(id)!;
};

function Loading() {
  return (
    <div className="stack" aria-busy="true" aria-label={t('Chargement')}>
      <Skel w="40%" />
      <Skel w="70%" />
      <Skel w="55%" />
    </div>
  );
}

function ToolRoute({ tool }: { tool: ToolMeta }) {
  const { authenticated, loading } = useAuth();
  const Page = lazyPage(tool.id);
  if (!tool.public && loading) return <Loading />;
  if (!tool.public && !authenticated) return <LoginPanel title={t(tool.title)} />;
  if (!Page)
    return (
      <Empty title={t(tool.title)}>
        {t('Cet outil arrive bientôt.')}
      </Empty>
    );
  return (
    <Suspense fallback={<Loading />}>
      <Page />
    </Suspense>
  );
}

function App() {
  return (
    <Shell>
      <Routes>
        <Route path="/" element={<Home />} />
        {[...TOOLS, SHARED_REPORT].flatMap((tool) => tool.routes.map((r) => <Route key={r} path={r} element={<ToolRoute tool={tool} />} />))}
        <Route path="*" element={<Empty title={t('Page introuvable')}>{t('Utilisez la saisie en haut de page : collez un domaine, une IP ou une URL.')}</Empty>} />
      </Routes>
    </Shell>
  );
}

// the language and its catalog before the first render (i18n.tsx)
void initI18n().then(() =>
  createRoot(document.getElementById('root')!).render(
    <StrictMode>
      <BrowserRouter>
        <AuthProvider>
          <ToastProvider>
            <App />
          </ToastProvider>
        </AuthProvider>
      </BrowserRouter>
    </StrictMode>,
  ),
);
