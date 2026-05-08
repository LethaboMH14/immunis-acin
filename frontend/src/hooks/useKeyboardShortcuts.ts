// frontend/src/hooks/useKeyboardShortcuts.ts
// Keyboard shortcut hook — global hotkeys with modifier key support
// WHY: Power users (SOC analysts) need keyboard-driven workflows.
// Cmd+K for command palette, Cmd+Shift+T for theme, etc.

import { useEffect, useCallback, useRef } from 'react';

// ─── Types ────────────────────────────────────────────────────────────────────

interface ShortcutDefinition {
  key: string;
  ctrl?: boolean;
  shift?: boolean;
  alt?: boolean;
  meta?: boolean;
  handler: () => void;
  description?: string;
  /** If true, fires even when focused on input/textarea */
  global?: boolean;
}

type ShortcutMap = Record<string, ShortcutDefinition>;

// ─── Helpers ──────────────────────────────────────────────────────────────────

const isMac = typeof navigator !== 'undefined' && /Mac|iPod|iPhone|iPad/.test(navigator.platform);

function isInputElement(target: EventTarget | null): boolean {
  if (!target || !(target instanceof HTMLElement)) return false;
  const tagName = target.tagName.toLowerCase();
  if (tagName === 'input' || tagName === 'textarea' || tagName === 'select') return true;
  if (target.isContentEditable) return true;
  return false;
}

function matchesShortcut(event: KeyboardEvent, shortcut: ShortcutDefinition): boolean {
  // Normalize: "ctrl" means Cmd on Mac, Ctrl on Windows
  const wantsCtrl = shortcut.ctrl ?? false;
  const wantsShift = shortcut.shift ?? false;
  const wantsAlt = shortcut.alt ?? false;
  const wantsMeta = shortcut.meta ?? false;

  const ctrlPressed = isMac ? event.metaKey : event.ctrlKey;
  const shiftPressed = event.shiftKey;
  const altPressed = event.altKey;
  const metaPressed = isMac ? event.ctrlKey : event.metaKey;

  if (wantsCtrl !== ctrlPressed) return false;
  if (wantsShift !== shiftPressed) return false;
  if (wantsAlt !== altPressed) return false;
  if (wantsMeta !== metaPressed) return false;

  return event.key.toLowerCase() === shortcut.key.toLowerCase();
}

// ─── Hook ─────────────────────────────────────────────────────────────────────

export function useKeyboardShortcuts(shortcuts: ShortcutMap): void {
  const shortcutsRef = useRef(shortcuts);
  shortcutsRef.current = shortcuts;

  const handleKeyDown = useCallback((event: KeyboardEvent) => {
    const entries = Object.values(shortcutsRef.current);

    for (const shortcut of entries) {
      if (matchesShortcut(event, shortcut)) {
        // Skip if focused on input and shortcut is not global
        if (!shortcut.global && isInputElement(event.target)) {
          continue;
        }

        event.preventDefault();
        event.stopPropagation();
        shortcut.handler();
        return;
      }
    }
  }, []);

  useEffect(() => {
    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [handleKeyDown]);
}

// ─── Preset Shortcuts Factory ─────────────────────────────────────────────────

interface PresetHandlers {
  onCommandPalette?: () => void;
  onThemeToggle?: () => void;
  onSearch?: () => void;
  onNewThreat?: () => void;
  onHelp?: () => void;
  onEscape?: () => void;
  onNavigateOverview?: () => void;
  onNavigateThreats?: () => void;
  onNavigateScanner?: () => void;
  onNavigateMesh?: () => void;
}

export function useImmunisShortcuts(handlers: PresetHandlers): void {
  useKeyboardShortcuts({
    commandPalette: {
      key: 'k',
      ctrl: true,
      handler: handlers.onCommandPalette ?? (() => {}),
      description: 'Open command palette',
      global: true,
    },
    themeToggle: {
      key: 't',
      ctrl: true,
      shift: true,
      handler: handlers.onThemeToggle ?? (() => {}),
      description: 'Toggle theme',
      global: true,
    },
    search: {
      key: '/',
      ctrl: false,
      handler: handlers.onSearch ?? (() => {}),
      description: 'Focus search',
    },
    newThreat: {
      key: 'n',
      ctrl: true,
      handler: handlers.onNewThreat ?? (() => {}),
      description: 'Submit new threat',
    },
    help: {
      key: '?',
      ctrl: false,
      shift: true,
      handler: handlers.onHelp ?? (() => {}),
      description: 'Show help',
    },
    escape: {
      key: 'Escape',
      handler: handlers.onEscape ?? (() => {}),
      description: 'Close panel / cancel',
      global: true,
    },
    navOverview: {
      key: '1',
      ctrl: true,
      handler: handlers.onNavigateOverview ?? (() => {}),
      description: 'Go to Overview',
      global: true,
    },
    navThreats: {
      key: '2',
      ctrl: true,
      handler: handlers.onNavigateThreats ?? (() => {}),
      description: 'Go to Threats',
      global: true,
    },
    navScanner: {
      key: '3',
      ctrl: true,
      handler: handlers.onNavigateScanner ?? (() => {}),
      description: 'Go to Scanner',
      global: true,
    },
    navMesh: {
      key: '4',
      ctrl: true,
      handler: handlers.onNavigateMesh ?? (() => {}),
      description: 'Go to Mesh',
      global: true,
    },
  });
}

export default useKeyboardShortcuts;
