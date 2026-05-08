// frontend/src/router.tsx
// Page router — maps route IDs to lazy-loaded page components
// WHY: Each page is a substantial component. Lazy loading prevents loading
// all 13 pages upfront. Suspense shows loading screen during chunk download.

import React, { Suspense } from 'react';
import { LoadingScreen } from './components/common/LoadingScreen';
import { ErrorBoundary } from './components/common/ErrorBoundary';

// ─── Lazy Page Imports ────────────────────────────────────────────────────────

const OverviewPage = React.lazy(() => import('./pages/OverviewPage'));
const ThreatsPage = React.lazy(() => import('./pages/ThreatsPage'));
const ImmunityPage = React.lazy(() => import('./pages/ImmunityPage'));
const BattlegroundPage = React.lazy(() => import('./pages/BattlegroundPage'));
const MeshPage = React.lazy(() => import('./pages/MeshPage'));
const ScannerPage = React.lazy(() => import('./pages/ScannerPage'));
const CompliancePage = React.lazy(() => import('./pages/CompliancePage'));
const CopilotPage = React.lazy(() => import('./pages/CopilotPage'));
const AnalyticsPage = React.lazy(() => import('./pages/AnalyticsPage'));
const SettingsPage = React.lazy(() => import('./pages/SettingsPage'));

// ─── Route Map ────────────────────────────────────────────────────────────────

const routeMap: Record<string, React.LazyExoticComponent<React.ComponentType>> = {
  overview: OverviewPage,
  threats: ThreatsPage,
  immunity: ImmunityPage,
  battleground: BattlegroundPage,
  mesh: MeshPage,
  scanner: ScannerPage,
  compliance: CompliancePage,
  copilot: CopilotPage,
  analytics: AnalyticsPage,
  settings: SettingsPage,
};

// ─── Router Component ─────────────────────────────────────────────────────────

interface PageRouterProps {
  activeRoute: string;
  onNavigate: (route: string) => void;
}

export function PageRouter({ activeRoute, onNavigate }: PageRouterProps) {
  const renderPage = () => {
    switch (activeRoute) {
      case 'overview': return <OverviewPage onNavigate={onNavigate} />;
      case 'threats': return <ThreatsPage />;
      case 'immunity': return <ImmunityPage />;
      case 'battleground': return <BattlegroundPage />;
      case 'mesh': return <MeshPage />;
      case 'scanner': return <ScannerPage />;
      case 'compliance': return <CompliancePage />;
      case 'copilot': return <CopilotPage />;
      case 'analytics': return <AnalyticsPage />;
      case 'settings': return <SettingsPage />;
      default:
        return (
          <div className="flex items-center justify-center h-full">
            <p className="text-sm" style={{ color: 'var(--text-muted)' }}>
              Page "{activeRoute}" not found
            </p>
          </div>
        );
    }
  };

  return (
    <ErrorBoundary resetKey={activeRoute}>
      <Suspense
        fallback={
          <div className="flex items-center justify-center h-64">
            <div className="flex flex-col items-center gap-3">
              <div className="w-8 h-8 border-2 rounded-full animate-spin" style={{ borderColor: 'var(--color-immune)', borderTopColor: 'transparent' }} />
              <span className="text-xs" style={{ color: 'var(--text-muted)' }}>Loading...</span>
            </div>
          </div>
        }
      >
        {renderPage()}
      </Suspense>
    </ErrorBoundary>
  );
}

export default PageRouter;
