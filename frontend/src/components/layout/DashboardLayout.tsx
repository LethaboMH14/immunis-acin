// frontend/src/components/layout/DashboardLayout.tsx
// Main dashboard layout — sidebar + topbar + content + overlays
// WHY: The structural shell. Every page renders inside this layout.
// Manages navigation state, command palette, toasts, and error boundaries.

import React, { useState, useCallback, useMemo } from 'react';
import { Sidebar } from './Sidebar';
import { TopBar } from './TopBar';
import { ToastContainer } from '../common/Toast';
import { CommandPalette } from '../common/CommandPalette';
import { ErrorBoundary } from '../common/ErrorBoundary';
import { useToast } from '../../hooks/useToast';
import { useCommandPalette } from '../../hooks/useCommandPalette';
import { useImmunisShortcuts } from '../../hooks/useKeyboardShortcuts';
import { useImmunis } from '../../hooks/useImmunis';
import { useTheme } from '../../providers/ThemeProvider';
import type { CommandItem } from '../../hooks/useCommandPalette';

// ─── Types ────────────────────────────────────────────────────────────────────

interface DashboardLayoutProps {
  children: (activeRoute: string, navigate: (route: string) => void) => React.ReactNode;
}

// ─── Component ────────────────────────────────────────────────────────────────

export function DashboardLayout({ children }: DashboardLayoutProps) {
  const [activeRoute, setActiveRoute] = useState('overview');
  const { toggleTheme } = useTheme();
  const { toasts, removeToast } = useToast();
  const { threats, antibodies, immunityScore } = useImmunis();

  // ─── Command Palette Items ──────────────────────────────────────────────

  const commandItems: CommandItem[] = useMemo(
    () => [
      // ─── Navigation ─────────────────────────────────────────────
      { id: 'nav-overview', label: 'Overview Dashboard', category: 'Navigation', action: () => setActiveRoute('overview'), keywords: ['home', 'dashboard', 'main', 'landing', 'immunity', 'gauge'] },
      { id: 'nav-threats', label: 'Threat Intelligence', category: 'Navigation', action: () => setActiveRoute('threats'), keywords: ['incidents', 'attacks', 'phishing', 'bec', 'malware', 'submit', 'analyze'] },
      { id: 'nav-immunity', label: 'Immune Library', category: 'Navigation', action: () => setActiveRoute('immunity'), keywords: ['antibodies', 'defenses', 'rules', 'detection', 'z3', 'verification'] },
      { id: 'nav-battleground', label: 'Adversarial Battleground', category: 'Navigation', action: () => setActiveRoute('battleground'), keywords: ['red', 'blue', 'arena', 'wgan', 'coevolution', 'arms race', 'honeypot', 'deception'] },
      { id: 'nav-mesh', label: 'Mesh Network', category: 'Navigation', action: () => setActiveRoute('mesh'), keywords: ['p2p', 'nodes', 'broadcast', 'gossip', 'dilithium', 'ed25519', 'stix', 'taxii', 'quantum'] },
      { id: 'nav-scanner', label: 'Vulnerability Scanner', category: 'Navigation', action: () => setActiveRoute('scanner'), keywords: ['sast', 'dast', 'infrastructure', 'cis', 'owasp', 'vulnerabilities', 'audit'] },
      { id: 'nav-compliance', label: 'Compliance Engine', category: 'Navigation', action: () => setActiveRoute('compliance'), keywords: ['popia', 'nist', 'gdpr', 'mitre', 'cybercrimes', 'frameworks', 'controls', 'reports', 'audit'] },
      { id: 'nav-copilot', label: 'Security Copilot', category: 'Navigation', action: () => setActiveRoute('copilot'), keywords: ['ai', 'chat', 'help', 'explain', 'fix', 'remediation', 'assistant'] },
      { id: 'nav-analytics', label: 'Analytics & Math Engines', category: 'Navigation', action: () => setActiveRoute('analytics'), keywords: ['charts', 'metrics', 'reports', 'kde', 'gpd', 'sir', 'stackelberg', 'pid', 'markowitz', 'actuarial', 'risk', 'r0', 'cvar', 'var'] },
      { id: 'nav-settings', label: 'Settings', category: 'Navigation', action: () => setActiveRoute('settings'), keywords: ['config', 'preferences', 'theme', 'density', 'notifications', 'account', 'role'] },

      // ─── Actions ────────────────────────────────────────────────
      { id: 'action-theme', label: 'Toggle Theme (Dark/Light)', category: 'Actions', action: toggleTheme, shortcut: '⌘⇧T', keywords: ['dark', 'light', 'midnight', 'twilight', 'overcast', 'mode', 'appearance'] },
      { id: 'action-submit', label: 'Submit New Threat', category: 'Actions', action: () => setActiveRoute('threats'), keywords: ['analyze', 'new', 'paste', 'email', 'phishing'] },
      { id: 'action-scan-all', label: 'Run All Vulnerability Scans', category: 'Actions', action: () => setActiveRoute('scanner'), keywords: ['sast', 'dast', 'audit', 'security'] },
      { id: 'action-compliance', label: 'Run Compliance Assessment', category: 'Actions', action: () => setActiveRoute('compliance'), keywords: ['assess', 'posture', 'popia', 'nist'] },
      { id: 'action-report-popia', label: 'Generate POPIA S22 Report', category: 'Actions', action: () => setActiveRoute('compliance'), keywords: ['popia', 'section 22', 'breach', 'notification', 'regulator'] },
      { id: 'action-report-gdpr', label: 'Generate GDPR Art.33 Report', category: 'Actions', action: () => setActiveRoute('compliance'), keywords: ['gdpr', 'article 33', 'supervisory', 'authority'] },

      // ─── Features ───────────────────────────────────────────────
      { id: 'feat-honeypot', label: 'Honeypot Sandbox', category: 'Features', action: () => setActiveRoute('battleground'), keywords: ['honeypot', 'deception', 'trap', 'rl', 'reinforcement', 'sandbox', 'capture'] },
      { id: 'feat-canary', label: 'Canary Tokens', category: 'Features', action: () => setActiveRoute('battleground'), keywords: ['canary', 'tokens', 'tripwire', 'hmac', 'detection'] },
      { id: 'feat-taf', label: 'Threat Actor Fingerprinting', category: 'Features', action: () => setActiveRoute('analytics'), keywords: ['taf', 'fingerprint', 'dbscan', 'clustering', 'psychographic', 'mercenary', 'hacktivist'] },
      { id: 'feat-epidemiological', label: 'Epidemiological Model (SIR)', category: 'Features', action: () => setActiveRoute('analytics'), keywords: ['sir', 'r0', 'herd immunity', 'susceptible', 'infected', 'recovered', 'propagation'] },
      { id: 'feat-actuarial', label: 'Actuarial Risk Engine', category: 'Features', action: () => setActiveRoute('analytics'), keywords: ['gpd', 'cvar', 'var', 'expected loss', 'risk', 'financial', 'actuarial', 'pareto'] },
      { id: 'feat-game-theory', label: 'Game Theory (Stackelberg)', category: 'Features', action: () => setActiveRoute('analytics'), keywords: ['stackelberg', 'origami', 'eraser', 'deterrence', 'equilibrium', 'game theory', 'defense allocation'] },
      { id: 'feat-portfolio', label: 'Markowitz Portfolio', category: 'Features', action: () => setActiveRoute('analytics'), keywords: ['markowitz', 'portfolio', 'sharpe', 'efficient frontier', 'allocation', 'budget'] },
      { id: 'feat-z3', label: 'Z3 Formal Verification', category: 'Features', action: () => setActiveRoute('immunity'), keywords: ['z3', 'formal', 'verification', 'proof', 'theorem', 'soundness', 'correctness'] },
      { id: 'feat-multilingual', label: 'Multilingual Detection (40+)', category: 'Features', action: () => setActiveRoute('threats'), keywords: ['multilingual', 'language', 'zulu', 'sesotho', 'xhosa', 'arabic', 'mandarin', 'afrikaans', 'translation'] },

      // ─── Agents ─────────────────────────────────────────────────
      { id: 'agent-1', label: 'Agent 1: Incident Analyst', category: 'Agents', action: () => setActiveRoute('threats'), keywords: ['agent 1', 'analyst', 'fingerprint', 'labse', 'classification'] },
      { id: 'agent-2', label: 'Agent 2: Antibody Synthesiser', category: 'Agents', action: () => setActiveRoute('immunity'), keywords: ['agent 2', 'synthesiser', 'antibody', 'detection rule'] },
      { id: 'agent-4', label: 'Agent 4: Red Agent', category: 'Agents', action: () => setActiveRoute('battleground'), keywords: ['agent 4', 'red', 'adversarial', 'evasion', 'attack'] },
      { id: 'agent-5', label: 'Agent 5: Blue Defender', category: 'Agents', action: () => setActiveRoute('battleground'), keywords: ['agent 5', 'blue', 'variant', 'recogniser', 'defense'] },
      { id: 'agent-8', label: 'Agent 8: Visual Analyst', category: 'Agents', action: () => setActiveRoute('threats'), keywords: ['agent 8', 'visual', 'qr', 'deepfake', 'document', 'image', 'steganography'] },
      { id: 'agent-12', label: 'Agent 12: Arbiter', category: 'Agents', action: () => setActiveRoute('battleground'), keywords: ['agent 12', 'arbiter', 'judge', 'promotion', 'battleground'] },
    ],
    [toggleTheme]
  );

  const commandPalette = useCommandPalette(commandItems);

  // ─── Keyboard Shortcuts ─────────────────────────────────────────────────

  useImmunisShortcuts({
    onCommandPalette: commandPalette.toggle,
    onThemeToggle: toggleTheme,
    onSearch: commandPalette.open,
    onNewThreat: () => setActiveRoute('threats'),
    onEscape: commandPalette.close,
    onNavigateOverview: () => setActiveRoute('overview'),
    onNavigateThreats: () => setActiveRoute('threats'),
    onNavigateScanner: () => setActiveRoute('scanner'),
    onNavigateMesh: () => setActiveRoute('mesh'),
  });

  // ─── Navigation Handler ─────────────────────────────────────────────────

  const handleNavigate = useCallback((route: string) => {
    setActiveRoute(route);
  }, []);

  // ─── Render ─────────────────────────────────────────────────────────────

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-[var(--bg-primary)]">
      {/* Sidebar */}
      <Sidebar
        activeRoute={activeRoute}
        onNavigate={handleNavigate}
        threatCount={threats.length}
        antibodyCount={antibodies.length}
      />

      {/* Main content area */}
      <div className="flex flex-col flex-1 min-w-0 overflow-hidden">
        {/* Top bar */}
        <TopBar
          title={activeRoute}
          onSearchClick={commandPalette.open}
          immunityScore={immunityScore}
        />

        {/* Page content */}
        <main className="flex-1 overflow-y-auto">
          <ErrorBoundary
            resetKey={activeRoute}
            onError={(error) => {
              console.error(`[Layout] Page error on ${activeRoute}:`, error);
            }}
          >
            <div className="p-6">
              {children(activeRoute, handleNavigate)}
            </div>
          </ErrorBoundary>
        </main>
      </div>

      {/* Overlays */}
      <CommandPalette
        isOpen={commandPalette.isOpen}
        query={commandPalette.query}
        results={commandPalette.results}
        flatResults={commandPalette.flatResults}
        selectedIndex={commandPalette.selectedIndex}
        onClose={commandPalette.close}
        onQueryChange={commandPalette.setQuery}
        onSelectNext={commandPalette.selectNext}
        onSelectPrevious={commandPalette.selectPrevious}
        onExecuteSelected={commandPalette.executeSelected}
        onExecuteItem={commandPalette.executeItem}
      />

      <ToastContainer toasts={toasts} onDismiss={removeToast} />
    </div>
  );
}

export type { DashboardLayoutProps };
export default DashboardLayout;
