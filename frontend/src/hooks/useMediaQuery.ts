// frontend/src/hooks/useMediaQuery.ts
// Media query hook — responsive breakpoints + accessibility preferences
// WHY: Components need to adapt layout (sidebar collapse, grid columns)
// and respect user preferences (reduced motion, dark mode).

import { useState, useEffect } from 'react';
import { BREAKPOINTS } from '../utils/constants';

export function useMediaQuery(query: string): boolean {
  const [matches, setMatches] = useState<boolean>(() => {
    if (typeof window === 'undefined') return false;
    return window.matchMedia(query).matches;
  });

  useEffect(() => {
    if (typeof window === 'undefined') return;

    const mediaQuery = window.matchMedia(query);
    setMatches(mediaQuery.matches);

    const handler = (event: MediaQueryListEvent) => {
      setMatches(event.matches);
    };

    mediaQuery.addEventListener('change', handler);
    return () => mediaQuery.removeEventListener('change', handler);
  }, [query]);

  return matches;
}

// ─── Convenience Hooks ────────────────────────────────────────────────────────

export function useIsMobile(): boolean {
  return !useMediaQuery(`(min-width: ${BREAKPOINTS.sm}px)`);
}

export function useIsTablet(): boolean {
  const aboveSm = useMediaQuery(`(min-width: ${BREAKPOINTS.sm}px)`);
  const belowLg = !useMediaQuery(`(min-width: ${BREAKPOINTS.lg}px)`);
  return aboveSm && belowLg;
}

export function useIsDesktop(): boolean {
  return useMediaQuery(`(min-width: ${BREAKPOINTS.lg}px)`);
}

export function usePrefersDarkMode(): boolean {
  return useMediaQuery('(prefers-color-scheme: dark)');
}

export function usePrefersReducedMotion(): boolean {
  return useMediaQuery('(prefers-reduced-motion: reduce)');
}

export default useMediaQuery;
