// frontend/src/components/common/Tabs.tsx
// Tabs — underline + pill styles, animated indicator, keyboard nav
// WHY: Layer 2 navigation. Threats page has tabs for feed/timeline/details.
// Response layer has SOC/IR/CISO/IT/Finance/Auditor tabs. Scanner has
// SAST/DAST/Infra/Copilot tabs. Consistent tab behavior everywhere.

import React, { useRef, useCallback } from 'react';
import { motion } from 'framer-motion';

// ─── Types ────────────────────────────────────────────────────────────────────

interface Tab {
  id: string;
  label: string;
  icon?: React.ReactNode;
  count?: number;
  disabled?: boolean;
}

interface TabsProps {
  tabs: Tab[];
  activeTab: string;
  onTabChange: (tabId: string) => void;
  variant?: 'underline' | 'pill';
  size?: 'sm' | 'md';
  className?: string;
}

// ─── Component ────────────────────────────────────────────────────────────────

export function Tabs({
  tabs,
  activeTab,
  onTabChange,
  variant = 'underline',
  size = 'md',
  className = '',
}: TabsProps) {
  const tabRefs = useRef<Map<string, HTMLButtonElement>>(new Map());

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      const enabledTabs = tabs.filter((t) => !t.disabled);
      const currentIdx = enabledTabs.findIndex((t) => t.id === activeTab);

      let nextIdx = -1;

      if (e.key === 'ArrowRight' || e.key === 'ArrowDown') {
        e.preventDefault();
        nextIdx = (currentIdx + 1) % enabledTabs.length;
      } else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') {
        e.preventDefault();
        nextIdx = (currentIdx - 1 + enabledTabs.length) % enabledTabs.length;
      } else if (e.key === 'Home') {
        e.preventDefault();
        nextIdx = 0;
      } else if (e.key === 'End') {
        e.preventDefault();
        nextIdx = enabledTabs.length - 1;
      }

      if (nextIdx >= 0) {
        const nextTab = enabledTabs[nextIdx];
        onTabChange(nextTab.id);
        tabRefs.current.get(nextTab.id)?.focus();
      }
    },
    [tabs, activeTab, onTabChange]
  );

  const sizeClasses = size === 'sm' ? 'text-xs py-1.5 px-2.5' : 'text-sm py-2 px-3';

  if (variant === 'pill') {
    return (
      <div
        role="tablist"
        className={[
          'inline-flex items-center gap-1 p-1 rounded-lg bg-[var(--bg-tertiary)]',
          className,
        ].join(' ')}
        onKeyDown={handleKeyDown}
      >
        {tabs.map((tab) => {
          const isActive = tab.id === activeTab;
          return (
            <button
              key={tab.id}
              ref={(el) => {
                if (el) tabRefs.current.set(tab.id, el);
              }}
              role="tab"
              aria-selected={isActive}
              aria-disabled={tab.disabled}
              tabIndex={isActive ? 0 : -1}
              disabled={tab.disabled}
              onClick={() => !tab.disabled && onTabChange(tab.id)}
              className={[
                'relative inline-flex items-center gap-1.5 rounded-md font-medium transition-colors',
                sizeClasses,
                'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-immune)]',
                'disabled:opacity-40 disabled:cursor-not-allowed',
                isActive
                  ? 'text-[var(--text-primary)]'
                  : 'text-[var(--text-muted)] hover:text-[var(--text-secondary)]',
              ].join(' ')}
            >
              {isActive && (
                <motion.div
                  layoutId="pill-indicator"
                  className="absolute inset-0 rounded-md bg-[var(--bg-secondary)] shadow-sm"
                  transition={{ type: 'spring', stiffness: 400, damping: 30 }}
                />
              )}
              <span className="relative z-10 flex items-center gap-1.5">
                {tab.icon}
                {tab.label}
                {tab.count !== undefined && (
                  <span
                    className={[
                      'inline-flex items-center justify-center min-w-[18px] h-[18px] px-1 rounded-full text-[10px] font-semibold',
                      isActive
                        ? 'bg-[var(--color-immune)]/20 text-[var(--color-immune)]'
                        : 'bg-[var(--bg-primary)] text-[var(--text-muted)]',
                    ].join(' ')}
                  >
                    {tab.count}
                  </span>
                )}
              </span>
            </button>
          );
        })}
      </div>
    );
  }

  // Underline variant (default)
  return (
    <div
      role="tablist"
      className={[
        'flex items-center gap-0 border-b border-[var(--border-subtle)]',
        className,
      ].join(' ')}
      onKeyDown={handleKeyDown}
    >
      {tabs.map((tab) => {
        const isActive = tab.id === activeTab;
        return (
          <button
            key={tab.id}
            ref={(el) => {
              if (el) tabRefs.current.set(tab.id, el);
            }}
            role="tab"
            aria-selected={isActive}
            aria-disabled={tab.disabled}
            tabIndex={isActive ? 0 : -1}
            disabled={tab.disabled}
            onClick={() => !tab.disabled && onTabChange(tab.id)}
            className={[
              'relative inline-flex items-center gap-1.5 font-medium transition-colors border-b-2 -mb-px',
              sizeClasses,
              'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-immune)] focus-visible:ring-inset',
              'disabled:opacity-40 disabled:cursor-not-allowed',
              isActive
                ? 'text-[var(--color-immune)] border-[var(--color-immune)]'
                : 'text-[var(--text-muted)] border-transparent hover:text-[var(--text-secondary)] hover:border-[var(--border-primary)]',
            ].join(' ')}
          >
            {tab.icon}
            {tab.label}
            {tab.count !== undefined && (
              <span
                className={[
                  'inline-flex items-center justify-center min-w-[18px] h-[18px] px-1 rounded-full text-[10px] font-semibold',
                  isActive
                    ? 'bg-[var(--color-immune)]/20 text-[var(--color-immune)]'
                    : 'bg-[var(--bg-tertiary)] text-[var(--text-muted)]',
                ].join(' ')}
              >
                {tab.count}
              </span>
            )}
          </button>
        );
      })}
    </div>
  );
}

export type { TabsProps, Tab };
export default Tabs;
