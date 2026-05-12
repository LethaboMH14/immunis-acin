// frontend/src/providers/ThemeProvider.tsx
// Theme and density management for IMMUNIS ACIN
// WHY: Components read CSS custom properties from active theme.
// This provider toggles data-theme on <html> so correct CSS activates.

import {
  createContext,
  useContext,
  useEffect,
  useState,
  useCallback,
  type ReactNode,
} from 'react';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type ThemeMode = 'midnight' | 'twilight' | 'overcast';
export type DensityMode = 'compact' | 'comfortable' | 'spacious';

interface ThemeContextValue {
  /** Current active theme */
  theme: ThemeMode;
  /** Switch theme */
  setTheme: (theme: ThemeMode) => void;
  /** Cycle to next theme */
  cycleTheme: () => void;
  /** Toggle theme */
  toggleTheme: () => void;
  /** Current density mode */
  density: DensityMode;
  /** Switch density */
  setDensity: (density: DensityMode) => void;
  /** Whether current theme is dark (midnight or twilight) */
  isDark: boolean;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const THEME_STORAGE_KEY = 'immunis-theme';
const DENSITY_STORAGE_KEY = 'immunis-density';
const THEME_ORDER: ThemeMode[] = ['midnight', 'twilight', 'overcast'];
const VALID_THEMES = new Set<string>(THEME_ORDER);
const VALID_DENSITIES = new Set<string>(['compact', 'comfortable', 'spacious']);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function getSystemPreference(): ThemeMode {
  if (typeof window === 'undefined') return 'midnight';
  return window.matchMedia('(prefers-color-scheme: light)').matches
    ? 'overcast'
    : 'midnight';
}

function getStoredTheme(): ThemeMode | null {
  try {
    const stored = localStorage.getItem(THEME_STORAGE_KEY);
    if (stored && VALID_THEMES.has(stored)) return stored as ThemeMode;
  } catch {
    // localStorage unavailable (SSR, privacy mode)
  }
  return null;
}

function getStoredDensity(): DensityMode {
  try {
    const stored = localStorage.getItem(DENSITY_STORAGE_KEY);
    if (stored && VALID_DENSITIES.has(stored)) return stored as DensityMode;
  } catch {
    // localStorage unavailable
  }
  return 'comfortable';
}

function applyTheme(theme: ThemeMode): void {
  document.documentElement.setAttribute('data-theme', theme);
  // Also set color-scheme for native elements (scrollbars, inputs)
  document.documentElement.style.colorScheme =
    theme === 'overcast' ? 'light' : 'dark';
}

function applyDensity(density: DensityMode): void {
  document.documentElement.setAttribute('data-density', density);
}

// ---------------------------------------------------------------------------
// Context
// ---------------------------------------------------------------------------

const ThemeContext = createContext<ThemeContextValue | null>(null);

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

interface ThemeProviderProps {
  children: ReactNode;
  /** Override initial theme (useful for testing) */
  defaultTheme?: ThemeMode;
  /** Override initial density (useful for testing) */
  defaultDensity?: DensityMode;
}

export function ThemeProvider({
  children,
  defaultTheme,
  defaultDensity,
}: ThemeProviderProps) {
  const [theme, setThemeState] = useState<ThemeMode>(
    () => defaultTheme ?? getStoredTheme() ?? getSystemPreference()
  );

  const [density, setDensityState] = useState<DensityMode>(
    () => defaultDensity ?? getStoredDensity()
  );

  // Apply theme to DOM on mount and change
  useEffect(() => {
    applyTheme(theme);
    try {
      localStorage.setItem(THEME_STORAGE_KEY, theme);
    } catch {
      // Silently fail if localStorage unavailable
    }
  }, [theme]);

  // Apply density to DOM on mount and change
  useEffect(() => {
    applyDensity(density);
    try {
      localStorage.setItem(DENSITY_STORAGE_KEY, density);
    } catch {
      // Silently fail
    }
  }, [density]);

  // Listen for system preference changes
  useEffect(() => {
    const mq = window.matchMedia('(prefers-color-scheme: light)');
    const handler = () => {
      // Only auto-switch if user hasn't explicitly chosen
      if (!getStoredTheme()) {
        setThemeState(getSystemPreference());
      }
    };
    mq.addEventListener('change', handler);
    return () => mq.removeEventListener('change', handler);
  }, []);

  const setTheme = useCallback((t: ThemeMode) => {
    setThemeState(t);
  }, []);

  const cycleTheme = useCallback(() => {
    setThemeState((current) => {
      const idx = THEME_ORDER.indexOf(current);
      return THEME_ORDER[(idx + 1) % THEME_ORDER.length];
    });
  }, []);

  const toggleTheme = useCallback(() => {
    const themes: ThemeMode[] = ['midnight', 'twilight', 'overcast'];
    const currentIndex = themes.indexOf(theme);
    const nextIndex = (currentIndex + 1) % themes.length;
    setTheme(themes[nextIndex]);
  }, [theme, setTheme]);

  const setDensity = useCallback((d: DensityMode) => {
    setDensityState(d);
  }, []);

  const isDark = theme === 'midnight' || theme === 'twilight';

  return (
    <ThemeContext.Provider
      value={{ theme, setTheme, cycleTheme, toggleTheme, density, setDensity, isDark }}
    >
      {children}
    </ThemeContext.Provider>
  );
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

export function useTheme(): ThemeContextValue {
  const ctx = useContext(ThemeContext);
  if (!ctx) {
    throw new Error('useTheme must be used within a ThemeProvider');
  }
  return ctx;
}
