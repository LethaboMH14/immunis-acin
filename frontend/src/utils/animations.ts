// frontend/src/utils/animations.ts
// Framer Motion animation presets
// WHY: Consistent animation across all components.

// ─── Transitions ──────────────────────────────────────────────────────────────

export const transitions = {
  fast: { duration: 0.15, ease: 'easeOut' },
  base: { duration: 0.2, ease: 'easeOut' },
  smooth: { duration: 0.3, ease: 'easeInOut' },
  slow: { duration: 0.5, ease: 'easeInOut' },
  spring: { type: 'spring' as const, stiffness: 300, damping: 25 },
};

// ─── Card ─────────────────────────────────────────────────────────────────────

export const cardVariants = {
  hidden: { opacity: 0, y: 8 },
  visible: { opacity: 1, y: 0, transition: transitions.base },
  exit: { opacity: 0, y: -8, transition: transitions.fast },
  hover: { y: -2, transition: transitions.fast },
  tap: { scale: 0.98, transition: transitions.fast },
};

// ─── Modal ────────────────────────────────────────────────────────────────────

export const modalOverlayVariants = {
  hidden: { opacity: 0 },
  visible: { opacity: 1, transition: { duration: 0.2 } },
  exit: { opacity: 0, transition: { duration: 0.15 } },
};

export const modalContentVariants = {
  hidden: { opacity: 0, scale: 0.95, y: 10 },
  visible: {
    opacity: 1,
    scale: 1,
    y: 0,
    transition: { type: 'spring', stiffness: 300, damping: 25 },
  },
  exit: { opacity: 0, scale: 0.95, y: 10, transition: { duration: 0.15 } },
};

// ─── Toast ────────────────────────────────────────────────────────────────────

export const toastVariants = {
  hidden: { opacity: 0, x: 50, scale: 0.95 },
  visible: {
    opacity: 1,
    x: 0,
    scale: 1,
    transition: { type: 'spring', stiffness: 400, damping: 25 },
  },
  exit: { opacity: 0, x: 50, scale: 0.95, transition: { duration: 0.2 } },
};

// ─── Slide Panel ──────────────────────────────────────────────────────────────

export const slidePanelVariants = {
  hidden: { x: '100%' },
  visible: {
    x: 0,
    transition: { type: 'spring', stiffness: 300, damping: 30 },
  },
  exit: {
    x: '100%',
    transition: { type: 'spring', stiffness: 300, damping: 30 },
  },
};

// ─── Command Palette ──────────────────────────────────────────────────────────

export const commandPaletteVariants = {
  hidden: { opacity: 0, scale: 0.95, y: -20 },
  visible: {
    opacity: 1,
    scale: 1,
    y: 0,
    transition: { type: 'spring', stiffness: 400, damping: 30 },
  },
  exit: { opacity: 0, scale: 0.95, y: -10, transition: { duration: 0.1 } },
};

// ─── Hover / Tap ──────────────────────────────────────────────────────────────

export const hoverLift = { y: -1 };
export const tapScale = { scale: 0.97 };

// ─── Page ─────────────────────────────────────────────────────────────────────

export const pageVariants = {
  hidden: { opacity: 0, y: 8 },
  visible: {
    opacity: 1,
    y: 0,
    transition: { duration: 0.3, staggerChildren: 0.06 },
  },
  exit: { opacity: 0, y: -8, transition: { duration: 0.2 } },
};

// ─── List Stagger ─────────────────────────────────────────────────────────────

export const listContainerVariants = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: { staggerChildren: 0.05 },
  },
};

export const listItemVariants = {
  hidden: { opacity: 0, x: -10 },
  visible: { opacity: 1, x: 0, transition: transitions.base },
};
