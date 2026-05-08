// frontend/src/hooks/useCommandPalette.ts
// Command palette state — search, filter, navigate, execute
// WHY: Cmd+K is the power user's best friend. SOC analysts need to jump
// between pages, run scans, submit threats, toggle settings — all without
// touching the mouse. This hook manages the entire interaction.

import { useState, useCallback, useMemo, useRef, useEffect } from 'react';

// ─── Types ────────────────────────────────────────────────────────────────────

export interface CommandItem {
  id: string;
  label: string;
  description?: string;
  icon?: string;
  shortcut?: string;
  category: string;
  action: () => void;
  keywords?: string[];
}

interface CommandGroup {
  category: string;
  items: CommandItem[];
}

interface UseCommandPaletteReturn {
  isOpen: boolean;
  query: string;
  results: CommandGroup[];
  flatResults: CommandItem[];
  selectedIndex: number;
  open: () => void;
  close: () => void;
  toggle: () => void;
  setQuery: (query: string) => void;
  selectNext: () => void;
  selectPrevious: () => void;
  executeSelected: () => void;
  executeItem: (item: CommandItem) => void;
}

// ─── Fuzzy Match ──────────────────────────────────────────────────────────────

function fuzzyMatch(text: string, query: string): boolean {
  if (!query) return true;
  const lowerText = text.toLowerCase();
  const lowerQuery = query.toLowerCase();

  // Simple substring match first
  if (lowerText.includes(lowerQuery)) return true;

  // Character-by-character fuzzy match
  let queryIdx = 0;
  for (let i = 0; i < lowerText.length && queryIdx < lowerQuery.length; i++) {
    if (lowerText[i] === lowerQuery[queryIdx]) {
      queryIdx++;
    }
  }
  return queryIdx === lowerQuery.length;
}

function matchScore(text: string, query: string): number {
  if (!query) return 0;
  const lowerText = text.toLowerCase();
  const lowerQuery = query.toLowerCase();

  // Exact match = highest score
  if (lowerText === lowerQuery) return 100;
  // Starts with = high score
  if (lowerText.startsWith(lowerQuery)) return 80;
  // Contains = medium score
  if (lowerText.includes(lowerQuery)) return 60;
  // Fuzzy match = low score
  return 30;
}

// ─── Hook ─────────────────────────────────────────────────────────────────────

export function useCommandPalette(items: CommandItem[]): UseCommandPaletteReturn {
  const [isOpen, setIsOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [selectedIndex, setSelectedIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement | null>(null);

  // Filter and sort items by query
  const flatResults = useMemo(() => {
    if (!query.trim()) return items;

    return items
      .filter((item) => {
        const searchText = [
          item.label,
          item.description ?? '',
          ...(item.keywords ?? []),
        ].join(' ');
        return fuzzyMatch(searchText, query);
      })
      .sort((a, b) => {
        const scoreA = matchScore(a.label, query);
        const scoreB = matchScore(b.label, query);
        return scoreB - scoreA;
      });
  }, [items, query]);

  // Group results by category
  const results = useMemo(() => {
    const groups = new Map<string, CommandItem[]>();

    for (const item of flatResults) {
      if (!groups.has(item.category)) {
        groups.set(item.category, []);
      }
      groups.get(item.category)!.push(item);
    }

    return Array.from(groups.entries()).map(
      ([category, groupItems]): CommandGroup => ({
        category,
        items: groupItems,
      })
    );
  }, [flatResults]);

  // Reset selection when results change
  useEffect(() => {
    setSelectedIndex(0);
  }, [flatResults.length, query]);

  const open = useCallback(() => {
    setIsOpen(true);
    setQuery('');
    setSelectedIndex(0);
  }, []);

  const close = useCallback(() => {
    setIsOpen(false);
    setQuery('');
    setSelectedIndex(0);
  }, []);

  const toggle = useCallback(() => {
    if (isOpen) {
      close();
    } else {
      open();
    }
  }, [isOpen, open, close]);

  const selectNext = useCallback(() => {
    setSelectedIndex((prev) =>
      prev < flatResults.length - 1 ? prev + 1 : 0
    );
  }, [flatResults.length]);

  const selectPrevious = useCallback(() => {
    setSelectedIndex((prev) =>
      prev > 0 ? prev - 1 : flatResults.length - 1
    );
  }, [flatResults.length]);

  const executeItem = useCallback(
    (item: CommandItem) => {
      item.action();
      close();
    },
    [close]
  );

  const executeSelected = useCallback(() => {
    if (flatResults[selectedIndex]) {
      executeItem(flatResults[selectedIndex]);
    }
  }, [flatResults, selectedIndex, executeItem]);

  return {
    isOpen,
    query,
    results,
    flatResults,
    selectedIndex,
    open,
    close,
    toggle,
    setQuery,
    selectNext,
    selectPrevious,
    executeSelected,
    executeItem,
  };
}

export default useCommandPalette;
