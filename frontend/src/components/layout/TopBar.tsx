// frontend/src/components/layout/TopBar.tsx
// Top bar — page title, search, status indicators, user controls
// WHY: Persistent context bar. Shows where you are, system health at a glance,
// and quick access to search/theme/notifications without navigating away.

import React from 'react';
import { useWebSocket } from '../../providers/WebSocketProvider';
import { useTheme } from '../../providers/ThemeProvider';
import { useAuth } from '../../providers/AuthProvider';
import { Badge } from '../common/Badge';

// ─── Types ────────────────────────────────────────────────────────────────────

interface TopBarProps {
  title: string;
  subtitle?: string;
  onSearchClick: () => void;
  immunityScore?: number;
  notificationCount?: number;
}

// ─── Route Labels ─────────────────────────────────────────────────────────────

const routeLabels: Record<string, string> = {
  overview: 'Overview',
  threats: 'Threat Intelligence',
  immunity: 'Immune Library',
  battleground: 'Battleground',
  mesh: 'Mesh Network',
  scanner: 'Vulnerability Scanner',
  compliance: 'Compliance',
  copilot: 'Security Copilot',
  analytics: 'Analytics',
  settings: 'Settings',
  profile: 'Profile',
};

// ─── Component ────────────────────────────────────────────────────────────────

export function TopBar({
  title,
  subtitle,
  onSearchClick,
  immunityScore = 0,
  notificationCount = 0,
}: TopBarProps) {
  const { status } = useWebSocket();
  const { theme, toggleTheme, isDark } = useTheme();
  const { user } = useAuth();

  const connectionColor = {
    connected: 'bg-emerald-400',
    connecting: 'bg-amber-400 animate-pulse',
    disconnected: 'bg-red-400',
    error: 'bg-red-400',
  }[status];

  const connectionLabel = {
    connected: 'Connected',
    connecting: 'Connecting...',
    disconnected: 'Disconnected',
    error: 'Error',
  }[status];

  return (
    <header className="h-14 flex items-center justify-between px-6 border-b border-[var(--border-subtle)] bg-[var(--bg-secondary)] flex-shrink-0">
      {/* Left: Title */}
      <div className="flex items-center gap-4">
        <div>
          <h1 className="text-base font-semibold text-[var(--text-primary)]">
            {routeLabels[title] || title}
          </h1>
          {subtitle && (
            <p className="text-xs text-[var(--text-muted)]">{subtitle}</p>
          )}
        </div>

        {/* Immunity score pill */}
        {immunityScore > 0 && (
          <div className="hidden md:flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-[var(--color-immune)]/10">
            <div className="w-2 h-2 rounded-full bg-[var(--color-immune)]" />
            <span className="text-xs font-mono font-semibold text-[var(--color-immune)]">
              {immunityScore}
            </span>
          </div>
        )}
      </div>

      {/* Right: Actions */}
      <div className="flex items-center gap-2">
        {/* Search */}
        <button
          onClick={onSearchClick}
          className="flex items-center gap-2 h-8 px-3 rounded-lg bg-[var(--bg-tertiary)] border border-[var(--border-subtle)] text-[var(--text-muted)] hover:text-[var(--text-secondary)] hover:border-[var(--border-primary)] transition-colors"
        >
          <svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.5">
            <circle cx="6" cy="6" r="4" />
            <path d="M9.5 9.5L13 13" strokeLinecap="round" />
          </svg>
          <span className="hidden sm:inline text-xs">Search</span>
          <kbd className="hidden md:inline-flex items-center px-1 py-0.5 rounded text-[9px] font-mono bg-[var(--bg-primary)] border border-[var(--border-subtle)]">
            ⌘K
          </kbd>
        </button>

        {/* Connection status */}
        <div
          className="flex items-center gap-1.5 px-2 py-1 rounded-md"
          title={connectionLabel}
        >
          <span className={`w-1.5 h-1.5 rounded-full ${connectionColor}`} />
          <span className="hidden lg:inline text-[10px] text-[var(--text-muted)]">
            {connectionLabel}
          </span>
        </div>

        {/* Theme toggle */}
        <button
          onClick={() => {
            console.log('[TopBar] Toggle theme, current:', theme);
            toggleTheme();
          }}
          className="p-2 rounded-lg transition-colors"
          style={{
            color: 'var(--text-muted)',
          }}
          onMouseEnter={(e) => { e.currentTarget.style.color = 'var(--text-primary)'; e.currentTarget.style.background = 'var(--bg-tertiary)'; }}
          onMouseLeave={(e) => { e.currentTarget.style.color = 'var(--text-muted)'; e.currentTarget.style.background = 'transparent'; }}
          aria-label={`Switch theme (current: ${theme})`}
          title={`Current: ${theme}. Click to switch.`}
        >
          {isDark ? (
            <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
              <path d="M8 1a.75.75 0 0 1 .75.75v1.5a.75.75 0 0 1-1.5 0v-1.5A.75.75 0 0 1 8 1ZM5.255 3.515a.75.75 0 0 0-1.06-1.06l-1.06 1.06a.75.75 0 0 0 1.06 1.06l1.06-1.06Zm5.49-1.06a.75.75 0 0 0-1.06 1.06l1.06 1.06a.75.75 0 1 0 1.06-1.06l-1.06-1.06ZM8 5a3 3 0 1 0 0 6 3 3 0 0 0 0-6ZM1 8a.75.75 0 0 1 .75-.75h1.5a.75.75 0 0 1 0 1.5h-1.5A.75.75 0 0 1 1 8Zm11 0a.75.75 0 0 1 .75-.75h1.5a.75.75 0 0 1 0 1.5h-1.5A.75.75 0 0 1 12 8Zm-7.745 3.485a.75.75 0 0 0-1.06 1.06l1.06 1.06a.75.75 0 0 0 1.06-1.06l-1.06-1.06Zm7.49 1.06a.75.75 0 0 1-1.06 0l-1.06-1.06a.75.75 0 0 1 1.06-1.06l1.06 1.06a.75.75 0 0 1 0 1.06ZM8 12a.75.75 0 0 1 .75.75v1.5a.75.75 0 0 1-1.5 0v-1.5A.75.75 0 0 1 8 12Z" />
            </svg>
          ) : (
            <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
              <path d="M14.438 10.148c.19-.425-.321-.787-.748-.601A5.5 5.5 0 0 1 6.453 2.31c.186-.427-.176-.938-.6-.748a6.501 6.501 0 1 0 8.585 8.586Z" />
            </svg>
          )}
        </button>

        {/* Notifications */}
        <button
          className="relative p-2 rounded-lg text-[var(--text-muted)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-tertiary)] transition-colors"
          aria-label={`${notificationCount} notifications`}
        >
          <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
            <path d="M8 1.5A3.5 3.5 0 0 0 4.5 5v2.947c0 .346-.102.683-.294.97l-1.703 2.556a.018.018 0 0 0 .015.027h10.964a.018.018 0 0 0 .015-.027l-1.703-2.556a1.75 1.75 0 0 1-.294-.97V5A3.5 3.5 0 0 0 8 1.5ZM6 13a2 2 0 1 0 4 0H6Z" />
          </svg>
          {notificationCount > 0 && (
            <span className="absolute -top-0.5 -right-0.5 w-4 h-4 rounded-full bg-[var(--color-threat)] text-white text-[9px] font-bold flex items-center justify-center">
              {notificationCount > 9 ? '9+' : notificationCount}
            </span>
          )}
        </button>

        {/* User avatar */}
        {user && (
          <button className="flex items-center gap-2 pl-2 ml-1 border-l border-[var(--border-subtle)]">
            <div className="w-7 h-7 rounded-full bg-[var(--color-immune)]/20 flex items-center justify-center text-xs font-bold text-[var(--color-immune)]">
              {user.name.charAt(0)}
            </div>
            <span className="hidden lg:block text-xs font-medium text-[var(--text-secondary)]">
              {user.name.split(' ')[0]}
            </span>
          </button>
        )}
      </div>
    </header>
  );
}

export type { TopBarProps };
export default TopBar;
