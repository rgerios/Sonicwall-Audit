import { useCallback, useEffect, useState } from 'react';
import { AccountPasswordModal } from './components/AccountPasswordModal.tsx';
import { AiAnalystView } from './components/AiAnalystView.tsx';
import { ConnectLinuxView } from './components/ConnectLinuxView.tsx';
import { LoginView } from './components/LoginView.tsx';
import { OverviewView } from './components/OverviewView.tsx';
import { ReportsView } from './components/ReportsView.tsx';
import { Sidebar } from './components/Sidebar.tsx';
import { SyslogView } from './components/SyslogView.tsx';
import { TopBar } from './components/TopBar.tsx';
import { UnusedNatsView } from './components/UnusedNatsView.tsx';
import { UnusedRulesView } from './components/UnusedRulesView.tsx';
import type { ActiveSection, AuditOverview, AuthStatus, FirewallVendor } from './types.ts';
import { vendorApiUrl } from './utils/vendorApi.ts';

const VENDOR_STORAGE_KEY = 'fwaudit:active-vendor';

function readInitialVendor(): FirewallVendor {
  try {
    const saved = localStorage.getItem(VENDOR_STORAGE_KEY);
    return saved === 'fortigate' ? 'fortigate' : 'sonicwall';
  } catch {
    return 'sonicwall';
  }
}

export default function App() {
  const [activeVendor, setActiveVendor] = useState<FirewallVendor>(readInitialVendor);
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

  useEffect(() => {
    document.documentElement.setAttribute('data-vendor', activeVendor);
    try {
      localStorage.setItem(VENDOR_STORAGE_KEY, activeVendor);
    } catch {
      // ignore storage quota errors
    }
  }, [activeVendor]);

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

  const fetchOverview = useCallback(async () => {
    if (!auth?.authenticated) return;
    try {
      const res = await fetch(vendorApiUrl(activeVendor, '/overview'));
      if (res.status === 401) {
        setAuth((prev) => (prev ? { ...prev, authenticated: false, username: null } : prev));
        return;
      }
      if (res.ok) {
        const data = (await res.json()) as AuditOverview;
        setOverview(data);
      }
    } finally {
      setLoading(false);
    }
  }, [auth?.authenticated, activeVendor]);

  useEffect(() => {
    if (auth?.authenticated) {
      void fetchOverview();
    }
  }, [auth?.authenticated, fetchOverview, refreshToken]);

  useEffect(() => {
    if (!auth?.authenticated || !overview?.udpStatus.running) return;
    const interval = setInterval(() => {
      void fetchOverview();
    }, 3500);
    return () => clearInterval(interval);
  }, [auth?.authenticated, overview?.udpStatus.running, fetchOverview]);

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
    const res = await fetch(vendorApiUrl(activeVendor, `/sites/${siteId}/select`), {
      method: 'POST',
    });
    if (res.ok) {
      const data = await res.json();
      if (data.overview) setOverview(data.overview);
      setRefreshToken((n) => n + 1);
    }
  };

  const handleLoadSample = async () => {
    setLoadingSample(true);
    try {
      const res = await fetch(vendorApiUrl(activeVendor, '/sample/load'), { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        if (data.overview) setOverview(data.overview);
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
        onSelectSection={setActiveSection}
        overview={overview}
        authUsername={auth.username}
        onSelectSite={(siteId) => void handleSelectSite(siteId)}
        onOpenPasswordModal={() => setShowPasswordModal(true)}
        onLogout={() => void handleLogout()}
      />

      <div className="flex-1 flex flex-col min-w-0">
        <TopBar
          vendor={activeVendor}
          activeSection={activeSection}
          activeSiteName={overview?.activeSite?.name}
          onLoadSample={() => void handleLoadSample()}
          onGoToConnect={() => setActiveSection('connect')}
          loadingSample={loadingSample}
        />

        <main className="flex-1 p-6 max-w-[1440px] w-full mx-auto">
          {activeSection === 'overview' && (
            <OverviewView
              vendor={activeVendor}
              overview={overview}
              loading={loading}
              onNavigate={setActiveSection}
              onLoadSample={() => void handleLoadSample()}
              onOverviewUpdated={setOverview}
              onInvestigateSyslog={handleInvestigateSyslog}
              onAnalyzeWithAi={handleAnalyzeEventWithAi}
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
              onOverviewUpdated={setOverview}
            />
          )}
        </main>
      </div>

      {showPasswordModal && auth.username && (
        <AccountPasswordModal
          username={auth.username}
          onClose={() => setShowPasswordModal(false)}
        />
      )}
    </div>
  );
}
