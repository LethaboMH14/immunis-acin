// frontend/src/hooks/index.ts
// Barrel export for all hooks

export { useLocalStorage } from './useLocalStorage';
export { useMediaQuery, useIsMobile, useIsTablet, useIsDesktop, usePrefersDarkMode, usePrefersReducedMotion } from './useMediaQuery';
export { useKeyboardShortcuts, useImmunisShortcuts } from './useKeyboardShortcuts';
export { useToast } from './useToast';
export type { Toast, ToastType } from './useToast';
export { useApi, useMutation, useHealthCheck } from './useApi';
export { useCommandPalette } from './useCommandPalette';
export type { CommandItem } from './useCommandPalette';
export { useImmunis } from './useImmunis';
