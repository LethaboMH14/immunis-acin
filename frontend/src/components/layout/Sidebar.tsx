// frontend/src/components/layout/Sidebar.tsx
// Main sidebar navigation — collapsible, animated, 11 sections
// WHY: Level 1 navigation. Always visible. Must communicate system state
// at a glance (active threats via badge counts) while staying out of the way.

import React, { useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { useLocalStorage } from '../../hooks/useLocalStorage';
import { useAuth } from '../../providers/AuthProvider';

// ─── Types ────────────────────────────────────────────────────────────────────

interface NavItem {
  id: string;
  label: string;
  icon: React.ReactNode;
  badge?: number;
  section: 'main' | 'bottom';
}

interface SidebarProps {
  activeRoute: string;
  onNavigate: (route: string) => void;
  threatCount?: number;
  antibodyCount?: number;
  scanIssues?: number;
}

// ─── Icons (inline SVGs for zero dependencies) ───────────────────────────────

const icons = {
  overview: (
    <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <rect x="3" y="3" width="6" height="6" rx="1" />
      <rect x="11" y="3" width="6" height="6" rx="1" />
      <rect x="3" y="11" width="6" height="6" rx="1" />
      <rect x="11" y="11" width="6" height="6" rx="1" />
    </svg>
  ),
  threats: (
    <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M10 2L2 7v6c0 4.4 3.4 8.5 8 9.5 4.6-1 8-5.1 8-9.5V7l-8-5Z" />
      <path d="M10 7v4M10 14h.01" />
    </svg>
  ),
  immunity: (
    <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="10" cy="10" r="7" />
      <path d="M7 10h6M10 7v6" />
    </svg>
  ),
  battleground: (
    <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M4 4l12 12M16 4L4 16" />
      <circle cx="10" cy="10" r="3" />
    </svg>
  ),
  mesh: (
    <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="10" cy="4" r="2" />
      <circle cx="4" cy="14" r="2" />
      <circle cx="16" cy="14" r="2" />
      <path d="M10 6v4M8 12l-2.5 1M12 12l2.5 1" />
    </svg>
  ),
  scanner: (
    <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="8.5" cy="8.5" r="5.5" />
      <path d="M13 13l4.5 4.5" />
    </svg>
  ),
  compliance: (
    <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <rect x="4" y="3" width="12" height="14" rx="2" />
      <path d="M8 8h4M8 11h3" />
      <path d="M7 15l2 2 4-4" />
    </svg>
  ),
  copilot: (
    <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M4 14l4-8 4 8" />
      <path d="M5.5 11h5" />
      <circle cx="15" cy="8" r="3" />
      <path d="M15 11v3" />
    </svg>
  ),
  analytics: (
    <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M4 16V8M8 16V4M12 16v-5M16 16V9" />
    </svg>
  ),
  settings: (
    <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="10" cy="10" r="3" />
      <path d="M10 2v2M10 16v2M3.5 5l1.5 1M15 14l1.5 1M2 10h2M16 10h2M3.5 15l1.5-1M15 6l1.5-1" />
    </svg>
  ),
  profile: (
    <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="10" cy="7" r="3" />
      <path d="M4 17c0-3.3 2.7-6 6-6s6 2.7 6 6" />
    </svg>
  ),
};

// ─── Component ────────────────────────────────────────────────────────────────

export function Sidebar({
  activeRoute,
  onNavigate,
  threatCount = 0,
  antibodyCount = 0,
  scanIssues = 0,
}: SidebarProps) {
  const [isCollapsed, setIsCollapsed] = useLocalStorage('immunis-sidebar-collapsed', false);
  const { user } = useAuth();

  const navItems: NavItem[] = [
    { id: 'overview', label: 'Overview', icon: icons.overview, section: 'main' },
    { id: 'threats', label: 'Threats', icon: icons.threats, badge: threatCount || undefined, section: 'main' },
    { id: 'immunity', label: 'Immunity', icon: icons.immunity, badge: antibodyCount || undefined, section: 'main' },
    { id: 'battleground', label: 'Battleground', icon: icons.battleground, section: 'main' },
    { id: 'mesh', label: 'Mesh Network', icon: icons.mesh, section: 'main' },
    { id: 'scanner', label: 'Scanner', icon: icons.scanner, badge: scanIssues || undefined, section: 'main' },
    { id: 'compliance', label: 'Compliance', icon: icons.compliance, section: 'main' },
    { id: 'copilot', label: 'Copilot', icon: icons.copilot, section: 'main' },
    { id: 'analytics', label: 'Analytics', icon: icons.analytics, section: 'main' },
    { id: 'settings', label: 'Settings', icon: icons.settings, section: 'bottom' },
    { id: 'profile', label: 'Profile', icon: icons.profile, section: 'bottom' },
  ];

  const mainItems = navItems.filter((i) => i.section === 'main');
  const bottomItems = navItems.filter((i) => i.section === 'bottom');

  const toggleCollapse = useCallback(() => {
    setIsCollapsed((prev) => !prev);
  }, [setIsCollapsed]);

  const renderItem = (item: NavItem) => {
    const isActive = activeRoute === item.id;

    return (
      <button
        key={item.id}
        onClick={() => onNavigate(item.id)}
        title={isCollapsed ? item.label : undefined}
        className={[
          'w-full flex items-center gap-3 px-3 py-2 rounded-lg transition-all duration-150 group relative',
          'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-immune)] focus-visible:ring-inset',
          isActive
            ? 'bg-[var(--color-immune)]/10 text-[var(--color-immune)]'
            : 'text-[var(--text-muted)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-tertiary)]',
        ].join(' ')}
      >
        {/* Active indicator */}
        {isActive && (
          <motion.div
            layoutId="sidebar-active"
            className="absolute left-0 top-1/2 -translate-y-1/2 w-0.5 h-5 rounded-r bg-[var(--color-immune)]"
            transition={{ type: 'spring', stiffness: 400, damping: 30 }}
          />
        )}

        {/* Icon */}
        <span className="flex-shrink-0 w-5 h-5">{item.icon}</span>

        {/* Label */}
        <AnimatePresence>
          {!isCollapsed && (
            <motion.span
              initial={{ opacity: 0, width: 0 }}
              animate={{ opacity: 1, width: 'auto' }}
              exit={{ opacity: 0, width: 0 }}
              transition={{ duration: 0.15 }}
              className="text-sm font-medium truncate"
            >
              {item.label}
            </motion.span>
          )}
        </AnimatePresence>

        {/* Badge */}
        {item.badge !== undefined && item.badge > 0 && (
          <span
            className={[
              'flex-shrink-0 inline-flex items-center justify-center rounded-full text-[10px] font-bold',
              isCollapsed ? 'absolute top-0.5 right-0.5 w-4 h-4' : 'ml-auto min-w-[20px] h-5 px-1',
              isActive
                ? 'bg-[var(--color-immune)] text-[#0A0E1A]'
                : 'bg-[var(--color-threat)]/20 text-[var(--color-threat)]',
            ].join(' ')}
          >
            {item.badge > 99 ? '99+' : item.badge}
          </span>
        )}
      </button>
    );
  };

  return (
    <motion.aside
      animate={{ width: isCollapsed ? 64 : 240 }}
      transition={{ type: 'spring', stiffness: 300, damping: 30 }}
      className="flex flex-col h-full bg-[var(--sidebar-bg,var(--bg-secondary))] border-r border-[var(--border-primary)] flex-shrink-0 overflow-hidden"
    >
      {/* Logo + collapse toggle */}
      <div className="flex items-center justify-between px-3 py-4 border-b border-[var(--border-subtle)]">
        <div className="flex items-center gap-2.5 overflow-hidden">
          {/* Shield icon */}
          <div className="flex-shrink-0 w-8 h-8 rounded-lg bg-[var(--color-immune)]/10 flex items-center justify-center">
            <svg width="18" height="20" viewBox="0 0 18 20" fill="none" className="text-[var(--color-immune)]">
              <path d="M9 1L1 5v6c0 5.5 3.4 10.7 8 12 4.6-1.3 8-6.5 8-12V5L9 1Z" stroke="currentColor" strokeWidth="1.5" fill="currentColor" fillOpacity="0.1" />
              <path d="M6 10h6M9 7v6" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
            </svg>
          </div>
          <AnimatePresence>
            {!isCollapsed && (
              <motion.span
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="text-sm font-bold text-[var(--text-primary)] tracking-wider"
              >
                IMMUNIS
              </motion.span>
            )}
          </AnimatePresence>
        </div>

        <button
          onClick={toggleCollapse}
          className="flex-shrink-0 p-1 rounded-md text-[var(--text-muted)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-tertiary)] transition-colors"
          aria-label={isCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        >
          <motion.svg
            width="16"
            height="16"
            viewBox="0 0 16 16"
            fill="none"
            stroke="currentColor"
            strokeWidth="1.5"
            strokeLinecap="round"
            animate={{ rotate: isCollapsed ? 180 : 0 }}
            transition={{ duration: 0.2 }}
          >
            <path d="M10 4L6 8l4 4" />
          </motion.svg>
        </button>
      </div>

      {/* Main navigation */}
      <nav className="flex-1 overflow-y-auto py-2 px-2 space-y-0.5">
        {mainItems.map(renderItem)}
      </nav>

      {/* Bottom section */}
      <div className="border-t border-[var(--border-subtle)] py-2 px-2 space-y-0.5">
        {bottomItems.map(renderItem)}

        {/* User info */}
        {user && !isCollapsed && (
          <div className="flex items-center gap-2.5 px-3 py-2 mt-1">
            <div className="w-7 h-7 rounded-full bg-[var(--color-immune)]/20 flex items-center justify-center text-xs font-bold text-[var(--color-immune)]">
              {user.name.charAt(0)}
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-xs font-medium text-[var(--text-primary)] truncate">
                {user.name}
              </p>
              <p className="text-[10px] text-[var(--text-muted)] truncate">
                {user.role.replace('_', ' ')}
              </p>
            </div>
          </div>
        )}
      </div>
    </motion.aside>
  );
}

export type { SidebarProps };
export default Sidebar;
