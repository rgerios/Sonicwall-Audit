import { lazy, Suspense, useCallback, useEffect, useRef, useState } from 'react';
import { CommandPalette } from './components/CommandPalette.tsx';
import { ErrorBoundary } from './components/ErrorBoundary.tsx';
import { LoginView } from './components/LoginView.tsx';
import { NotificationToastStack } from './components/NotificationToastStack.tsx';
import { Sidebar } from './components/Sidebar.tsx';
import { TopBar } from './components/TopBar.tsx';
import type { ActiveSection, AuditOverview, AuthStatus, FirewallVendor } from './types.ts';
import { setSelectedSiteId, vendorApiUrl } from './utils/vendorApi.ts';

const AccountPasswordModal = lazy(() =>
  import('./components/AccountPasswordModal.tsx').then((m) => ({ default: m.AccountPasswordModal }))
);
const AiAnalystView = lazy(() =>
  import('./components/AiAnalystView.tsx').then((m) => ({ default: m.AiAnalystView }))
);
const ConnectLinuxView = lazy(() =>
  import('./components/ConnectLinuxView.tsx').then((m) => ({ default: m.ConnectLinuxView }))
);
const OverviewView = lazy(() =>
  import('./components/OverviewView.tsx').then((m) => ({ default: m.OverviewView }))
);
const ReportsView = lazy(() =>
  import('./components/ReportsView.tsx').then((m) => ({ default: m.ReportsView }))
);
const SyslogView = lazy(() =>
  import('./components/SyslogView.tsx').then((m) => ({ default: m.SyslogView }))
);
const UnusedNatsView = lazy(() =>
  import('./components/UnusedNatsView.tsx').then((m) => ({ default: m.UnusedNatsView }))
);
const UnusedRulesView = lazy(() =>
  import('./components/UnusedRulesView.tsx').then((m) => ({ default: m.UnusedRulesView }))
);

function ViewFallback() {
  return (
    <div className="space-y-4 animate-pulse">
      <div className="h-8 w-56 bg-slate-200/70 rounded" />
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="h-28 bg-white border border-[var(--fw-border)] rounded-xl" />
        <div className="h-28 bg-white border border-[var(--fw-border)] rounded-xl" />
        <div className="h-28 bg-white border border-[var(--fw-border)] rounded-xl" />
        <div className="h-28 bg-white border border-[var(--fw-border)] rounded-xl" />
      </div>
      <div className="h-72 bg-white border border-[var(--fw-border)] rounded-xl" />
    </div>
  );
}

const VENDOR_STORAGE_KEY = 'fwaudit:active-vendor';
const COLOR_MODE_STORAGE_KEY = 'fwaudit:color-mode';
const TOAST_POPUPS_STORAGE_KEY = 'fwaudit:toast-popups';

function readInitialVendor(): FirewallVendor {
  try {
    const saved = localStorage.getItem(VENDOR_STORAGE_KEY);
    return saved === 'fortigate' ? 'fortigate' : 'sonicwall';
  } catch {
    return 'sonicwall';
  }
}

function readInitialColorMode(): 'light' | 'dark' {
  try {
    return localStorage.getItem(COLOR_MODE_STORAGE_KEY) === 'dark' ? 'dark' : 'light';
  } catch {
    return 'light';
  }
}

function readInitialToastPopups(): boolean {
  try {
    // Desligado por padrão: os popups cobriam o conteúdo; quem já ativou mantém a escolha
    return localStorage.getItem(TOAST_POPUPS_STORAGE_KEY) === 'true';
  } catch {
    return false;
  }
}

export default function App() {
  const [activeVendor, setActiveVendor] = useState<FirewallVendor>(readInitialVendor);
  const [colorMode, setColorMode] = useState<'light' | 'dark'>(readInitialColorMode);
  const [toastPopupsEnabled, setToastPopupsEnabled] = useState<boolean>(readInitialToastPopups);
  const [auth, setAuth] = useState<AuthStatus | null>(null);
  const [authChecking, setAuthChecking] = useState(true);
  const [showPasswordModal, setShowPasswordModal] = useState(false);

  const [activeSection, setActiveSection] = useState<ActiveSection>('overview');
  const [overview, setOverview] = useState<AuditOverview | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadingSample, setLoadingSample] = useState(false);
  const [refreshToken, setRefreshToken] = useState(0);
  const [pendingAiPrompt, setPendingAiPrompt] = useState<string | null>(null);
  const [pendingSyslogQuery, setPendingSyslogQuery] = useState<string | null>(null);
  const [openAlertConfigSignal, setOpenAlertConfigSignal] = useState(0);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setPaletteOpen((open) => !open);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  useEffect(() => {
    document.documentElement.setAttribute('data-vendor', activeVendor);
    try {
      localStorage.setItem(VENDOR_STORAGE_KEY, activeVendor);
    } catch {
      // ignore storage quota errors
    }
  }, [activeVendor]);

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', colorMode);
    try {
      localStorage.setItem(COLOR_MODE_STORAGE_KEY, colorMode);
    } catch {
      // ignore storage quota errors
    }
  }, [colorMode]);

  useEffect(() => {
    try {
      localStorage.setItem(TOAST_POPUPS_STORAGE_KEY, String(toastPopupsEnabled));
    } catch {
      // ignore storage quota errors
    }
  }, [toastPopupsEnabled]);

  const fetchAuthStatus = useCallback(async () => {
    try {
      const res = await fetch('/api/auth/status');
      if (res.ok) {
        const data = (await res.json()) as AuthStatus;
        setAuth(data);
      }
    } finally {
      setAuthChecking(false);
    }
  }, []);

  useEffect(() => {
    void fetchAuthStatus();
  }, [fetchAuthStatus]);

  const overviewAbortRef = useRef<AbortController | null>(null);

  const fetchOverview = useCallback(async () => {
    if (!auth?.authenticated) return;
    overviewAbortRef.current?.abort();
    const controller = new AbortController();
    overviewAbortRef.current = controller;
    try {
      const res = await fetch(vendorApiUrl(activeVendor, '/overview'), {
        signal: controller.signal,
      });
      if (res.status === 401) {
        setAuth((prev) => (prev ? { ...prev, authenticated: false, username: null } : prev));
        return;
      }
      if (res.ok) {
        const data = (await res.json()) as AuditOverview;
        if (data.activeSite?.id) setSelectedSiteId(activeVendor, data.activeSite.id);
        setOverview(data);
      }
    } catch (err) {
      if (err instanceof DOMException && err.name === 'AbortError') return;
    } finally {
      if (overviewAbortRef.current === controller) {
        setLoading(false);
      }
    }
  }, [auth?.authenticated, activeVendor]);

  useEffect(() => {
    return () => {
      overviewAbortRef.current?.abort();
    };
  }, []);

  useEffect(() => {
    if (auth?.authenticated) {
      void fetchOverview();
    }
  }, [auth?.authenticated, fetchOverview, refreshToken]);

  useEffect(() => {
    if (!auth?.authenticated) return;
    // Com o receptor UDP ativo a tela acompanha quase em tempo real; sem ele, ainda assim
    // atualiza periodicamente para refletir alertas e a sincronização automática.
    const interval = setInterval(
      () => {
        if (document.visibilityState === 'visible') void fetchOverview();
      },
      overview?.udpStatus.running ? 5000 : 20000
    );
    return () => clearInterval(interval);
  }, [auth?.authenticated, overview?.udpStatus.running, fetchOverview]);

  // Toda resposta com overview define também o firewall desta aba (criação, exclusão, troca)
  const applyOverview = useCallback(
    (next: AuditOverview) => {
      if (next.activeSite?.id) setSelectedSiteId(activeVendor, next.activeSite.id);
      setOverview(next);
    },
    [activeVendor]
  );

  const handleDataChanged = useCallback(() => {
    setRefreshToken((n) => n + 1);
  }, []);

  const handleSelectVendor = (nextVendor: FirewallVendor) => {
    if (nextVendor === activeVendor) return;
    setOverview(null);
    setLoading(true);
    setPendingAiPrompt(null);
    setPendingSyslogQuery(null);
    setActiveVendor(nextVendor);
    setRefreshToken((n) => n + 1);
  };

  const handleAuthenticated = (username: string) => {
    setAuth({ authenticated: true, needsSetup: false, username });
    setLoading(true);
    setRefreshToken((n) => n + 1);
  };

  const handleLogout = async () => {
    await fetch('/api/auth/logout', { method: 'POST' });
    setOverview(null);
    setAuth((prev) => (prev ? { ...prev, authenticated: false, username: null } : prev));
  };

  const handleSelectSite = async (siteId: string) => {
    setSelectedSiteId(activeVendor, siteId);
    const res = await fetch(vendorApiUrl(activeVendor, `/sites/${siteId}/select`), {
      method: 'POST',
    });
    if (res.ok) {
      const data = await res.json();
      if (data.overview) applyOverview(data.overview);
      setRefreshToken((n) => n + 1);
    }
  };

  const handleLoadSample = async () => {
    setLoadingSample(true);
    try {
      const res = await fetch(vendorApiUrl(activeVendor, '/sample/load'), { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        if (data.overview) applyOverview(data.overview);
        setRefreshToken((n) => n + 1);
      }
    } finally {
      setLoadingSample(false);
    }
  };

  const handleAnalyzeEventWithAi = (prompt: string) => {
    setPendingAiPrompt(prompt);
    setActiveSection('ai');
  };

  const handleInvestigateSyslog = (query: string) => {
    setPendingSyslogQuery(query);
    setActiveSection('syslogs');
  };

  const handleOpenAlertConfig = () => {
    setActiveSection('overview');
    setOpenAlertConfigSignal((n) => n + 1);
  };

  if (authChecking) {
    return (
      <div className="min-h-screen bg-[var(--fw-bg)] flex items-center justify-center p-6">
        <div className="w-full max-w-md h-64 bg-white border border-[var(--fw-border)] rounded-lg animate-pulse" />
      </div>
    );
  }

  if (!auth?.authenticated) {
    return (
      <LoginView
        needsSetup={auth?.needsSetup ?? false}
        onAuthenticated={handleAuthenticated}
      />
    );
  }

  return (
    <div className="min-h-screen bg-[var(--fw-bg)] text-[var(--fw-text)] flex transition-colors">
      <Sidebar
        vendor={activeVendor}
        onSelectVendor={handleSelectVendor}
        activeSection={activeSection}
        onSelectSection={(section) => {
          setActiveSection(section);
          setMenuOpen(false);
        }}
        mobileOpen={menuOpen}
        overview={overview}
        authUsername={auth.username}
        onSelectSite={(siteId) => void handleSelectSite(siteId)}
        onOpenPasswordModal={() => setShowPasswordModal(true)}
        onLogout={() => void handleLogout()}
      />

      {menuOpen && (
        <button
          type="button"
          aria-label="Fechar menu"
          onClick={() => setMenuOpen(false)}
          className="fixed inset-0 z-40 bg-black/40 lg:hidden"
        />
      )}

      <div className="flex-1 flex flex-col min-w-0">
        <TopBar
          vendor={activeVendor}
          activeSection={activeSection}
          activeSiteName={overview?.activeSite?.name}
          overview={overview}
          onLoadSample={() => void handleLoadSample()}
          onGoToConnect={() => setActiveSection('connect')}
          onOpenAlertConfig={handleOpenAlertConfig}
          onInvestigateSyslog={handleInvestigateSyslog}
          loadingSample={loadingSample}
          onOpenPalette={() => setPaletteOpen(true)}
          onToggleMenu={() => setMenuOpen((open) => !open)}
          menuOpen={menuOpen}
          toastPopupsEnabled={toastPopupsEnabled}
          onToggleToastPopups={() => setToastPopupsEnabled((v) => !v)}
          colorMode={colorMode}
          onToggleColorMode={() => setColorMode((m) => (m === 'dark' ? 'light' : 'dark'))}
        />

        <main className="flex-1 p-3 sm:p-6 max-w-[1440px] w-full mx-auto min-w-0">
          <ErrorBoundary resetKey={`${activeVendor}:${activeSection}`}>
            <Suspense fallback={<ViewFallback />}>
              {activeSection === 'overview' && (
                <OverviewView
                  vendor={activeVendor}
                  overview={overview}
                  loading={loading}
                  onNavigate={setActiveSection}
                  onLoadSample={() => void handleLoadSample()}
                  onOverviewUpdated={applyOverview}
                  onInvestigateSyslog={handleInvestigateSyslog}
                  onAnalyzeWithAi={handleAnalyzeEventWithAi}
                  openAlertConfigSignal={openAlertConfigSignal}
                />
              )}

              {activeSection === 'syslogs' && (
                <SyslogView
                  vendor={activeVendor}
                  refreshToken={refreshToken}
                  onDataChanged={handleDataChanged}
                  onAnalyzeEvent={handleAnalyzeEventWithAi}
                  pendingQuery={pendingSyslogQuery}
                  onConsumePendingQuery={() => setPendingSyslogQuery(null)}
                />
              )}

              {activeSection === 'rules' && (
                <UnusedRulesView
                  vendor={activeVendor}
                  refreshToken={refreshToken}
                  onGoToConnect={() => setActiveSection('connect')}
                />
              )}

              {activeSection === 'nats' && (
                <UnusedNatsView
                  vendor={activeVendor}
                  refreshToken={refreshToken}
                  onGoToConnect={() => setActiveSection('connect')}
                />
              )}

              {activeSection === 'reports' && (
                <ReportsView
                  vendor={activeVendor}
                  refreshToken={refreshToken}
                  onGoToConnect={() => setActiveSection('connect')}
                  onLoadSample={() => void handleLoadSample()}
                />
              )}

              {activeSection === 'ai' && (
                <AiAnalystView
                  vendor={activeVendor}
                  overview={overview}
                  pendingPrompt={pendingAiPrompt}
                  onConsumePendingPrompt={() => setPendingAiPrompt(null)}
                />
              )}

              {activeSection === 'connect' && (
                <ConnectLinuxView
                  vendor={activeVendor}
                  overview={overview}
                  onDataChanged={handleDataChanged}
                  onOverviewUpdated={applyOverview}
                />
              )}
            </Suspense>
          </ErrorBoundary>
        </main>

        <footer className="px-6 pb-4 pt-0 flex justify-end">
          <span
            title={`FW Audit v.${__APP_VERSION__}`}
            className="text-[11px] font-mono text-[var(--fw-text-subtle)] bg-white/80 border border-[var(--fw-border)] rounded px-2 py-0.5 select-all"
          >
            v.{__APP_VERSION__}
          </span>
        </footer>
      </div>

      <CommandPalette
        open={paletteOpen}
        onClose={() => setPaletteOpen(false)}
        vendor={activeVendor}
        overview={overview}
        colorMode={colorMode}
        onNavigate={setActiveSection}
        onSelectVendor={handleSelectVendor}
        onSelectSite={(siteId) => void handleSelectSite(siteId)}
        onInvestigate={handleInvestigateSyslog}
        onToggleColorMode={() => setColorMode((m) => (m === 'dark' ? 'light' : 'dark'))}
        onToggleToastPopups={() => setToastPopupsEnabled((v) => !v)}
        onLoadSample={() => void handleLoadSample()}
        onRefresh={handleDataChanged}
        onOpenAlertConfig={handleOpenAlertConfig}
        onOpenPasswordModal={() => setShowPasswordModal(true)}
        onLogout={() => void handleLogout()}
      />

      {showPasswordModal && auth.username && (
        <Suspense fallback={null}>
          <AccountPasswordModal
            username={auth.username}
            onClose={() => setShowPasswordModal(false)}
          />
        </Suspense>
      )}

      {toastPopupsEnabled && (
        <NotificationToastStack
          vendor={activeVendor}
          overview={overview}
          onViewAlerts={handleOpenAlertConfig}
          onInvestigateSyslog={handleInvestigateSyslog}
          onAnalyzeWithAi={handleAnalyzeEventWithAi}
        />
      )}
    </div>
  );
}
