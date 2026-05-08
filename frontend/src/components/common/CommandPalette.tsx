// frontend/src/components/common/CommandPalette.tsx
// Command palette — Cmd+K power user interface
// WHY: SOC analysts need to navigate, search, and execute actions without
// leaving the keyboard. This is the fastest way to do anything in IMMUNIS.

import React, { useEffect, useRef } from 'react';
import { createPortal } from 'react-dom';
import { motion, AnimatePresence } from 'framer-motion';
import type { CommandItem } from '../../hooks/useCommandPalette';

// ─── Types ────────────────────────────────────────────────────────────────────

interface CommandGroup {
  category: string;
  items: CommandItem[];
}

interface CommandPaletteProps {
  isOpen: boolean;
  query: string;
  results: CommandGroup[];
  flatResults: CommandItem[];
  selectedIndex: number;
  onClose: () => void;
  onQueryChange: (query: string) => void;
  onSelectNext: () => void;
  onSelectPrevious: () => void;
  onExecuteSelected: () => void;
  onExecuteItem: (item: CommandItem) => void;
}

// ─── Animation ────────────────────────────────────────────────────────────────

const overlayVariants = {
  hidden: { opacity: 0 },
  visible: { opacity: 1, transition: { duration: 0.15 } },
  exit: { opacity: 0, transition: { duration: 0.1 } },
};

const paletteVariants = {
  hidden: { opacity: 0, scale: 0.95, y: -20 },
  visible: {
    opacity: 1,
    scale: 1,
    y: 0,
    transition: { type: 'spring', stiffness: 400, damping: 30 },
  },
  exit: {
    opacity: 0,
    scale: 0.95,
    y: -10,
    transition: { duration: 0.1 },
  },
};

// ─── Component ────────────────────────────────────────────────────────────────

export function CommandPalette({
  isOpen,
  query,
  results,
  flatResults,
  selectedIndex,
  onClose,
  onQueryChange,
  onSelectNext,
  onSelectPrevious,
  onExecuteSelected,
  onExecuteItem,
}: CommandPaletteProps) {
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  // Focus input when opened
  useEffect(() => {
    if (isOpen) {
      setTimeout(() => inputRef.current?.focus(), 50);
    }
  }, [isOpen]);

  // Scroll selected item into view
  useEffect(() => {
    if (!listRef.current) return;
    const selected = listRef.current.querySelector('[data-selected="true"]');
    selected?.scrollIntoView({ block: 'nearest' });
  }, [selectedIndex]);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    switch (e.key) {
      case 'ArrowDown':
        e.preventDefault();
        onSelectNext();
        break;
      case 'ArrowUp':
        e.preventDefault();
        onSelectPrevious();
        break;
      case 'Enter':
        e.preventDefault();
        onExecuteSelected();
        break;
      case 'Escape':
        e.preventDefault();
        onClose();
        break;
    }
  };

  // Track flat index across groups
  let flatIdx = 0;

  return createPortal(
    <AnimatePresence>
      {isOpen && (
        <motion.div
          variants={overlayVariants}
          initial="hidden"
          animate="visible"
          exit="exit"
          onClick={onClose}
          className="fixed inset-0 z-[80] flex items-start justify-center pt-[20vh] bg-black/50 backdrop-blur-sm"
        >
          <motion.div
            variants={paletteVariants}
            initial="hidden"
            animate="visible"
            exit="exit"
            onClick={(e) => e.stopPropagation()}
            onKeyDown={handleKeyDown}
            className="w-full max-w-lg rounded-xl overflow-hidden bg-[var(--bg-secondary)] border border-[var(--border-primary)] shadow-[var(--shadow-xl)]"
          >
            {/* Search input */}
            <div className="flex items-center gap-3 px-4 py-3 border-b border-[var(--border-subtle)]">
              <svg
                width="18"
                height="18"
                viewBox="0 0 18 18"
                fill="none"
                className="text-[var(--text-muted)] flex-shrink-0"
              >
                <circle cx="8" cy="8" r="5.5" stroke="currentColor" strokeWidth="1.5" />
                <path d="M12 12l4 4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
              </svg>
              <input
                ref={inputRef}
                type="text"
                value={query}
                onChange={(e) => onQueryChange(e.target.value)}
                placeholder="Type a command or search..."
                className="flex-1 bg-transparent text-sm text-[var(--text-primary)] placeholder:text-[var(--text-muted)] outline-none"
              />
              <kbd className="hidden sm:inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-mono text-[var(--text-muted)] bg-[var(--bg-tertiary)] border border-[var(--border-subtle)]">
                ESC
              </kbd>
            </div>

            {/* Results */}
            <div
              ref={listRef}
              className="max-h-80 overflow-y-auto py-2"
            >
              {results.length === 0 ? (
                <div className="px-4 py-8 text-center">
                  <p className="text-sm text-[var(--text-muted)]">
                    No results found
                  </p>
                </div>
              ) : (
                results.map((group) => (
                  <div key={group.category}>
                    {/* Category header */}
                    <div className="px-4 py-1.5">
                      <span className="text-[10px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">
                        {group.category}
                      </span>
                    </div>

                    {/* Items */}
                    {group.items.map((item) => {
                      const isSelected = flatIdx === selectedIndex;
                      const currentIdx = flatIdx;
                      flatIdx++;

                      return (
                        <button
                          key={item.id}
                          data-selected={isSelected}
                          onClick={() => onExecuteItem(item)}
                          onMouseEnter={() => {
                            // Update selection on hover — handled by parent
                          }}
                          className={[
                            'w-full flex items-center gap-3 px-4 py-2 text-left transition-colors',
                            isSelected
                              ? 'bg-[var(--color-immune)]/10 text-[var(--text-primary)]'
                              : 'text-[var(--text-secondary)] hover:bg-[var(--bg-tertiary)]',
                          ].join(' ')}
                        >
                          {/* Icon */}
                          {item.icon && (
                            <span className="flex-shrink-0 text-[var(--text-muted)]">
                              {item.icon}
                            </span>
                          )}

                          {/* Label + description */}
                          <div className="flex-1 min-w-0">
                            <p className="text-sm font-medium truncate">
                              {item.label}
                            </p>
                            {item.description && (
                              <p className="text-xs text-[var(--text-muted)] truncate">
                                {item.description}
                              </p>
                            )}
                          </div>

                          {/* Shortcut */}
                          {item.shortcut && (
                            <kbd className="flex-shrink-0 px-1.5 py-0.5 rounded text-[10px] font-mono text-[var(--text-muted)] bg-[var(--bg-tertiary)] border border-[var(--border-subtle)]">
                              {item.shortcut}
                            </kbd>
                          )}
                        </button>
                      );
                    })}
                  </div>
                ))
              )}
            </div>

            {/* Footer */}
            <div className="flex items-center gap-4 px-4 py-2 border-t border-[var(--border-subtle)] text-[10px] text-[var(--text-muted)]">
              <span className="flex items-center gap-1">
                <kbd className="px-1 py-0.5 rounded bg-[var(--bg-tertiary)] border border-[var(--border-subtle)]">↑↓</kbd>
                Navigate
              </span>
              <span className="flex items-center gap-1">
                <kbd className="px-1 py-0.5 rounded bg-[var(--bg-tertiary)] border border-[var(--border-subtle)]">↵</kbd>
                Execute
              </span>
              <span className="flex items-center gap-1">
                <kbd className="px-1 py-0.5 rounded bg-[var(--bg-tertiary)] border border-[var(--border-subtle)]">esc</kbd>
                Close
              </span>
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>,
    document.body
  );
}

export type { CommandPaletteProps };
export default CommandPalette;
