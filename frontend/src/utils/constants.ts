// frontend/src/utils/constants.ts
// Configuration constants — single source of truth
// WHY: Magic strings scattered across 80+ components is unmaintainable.

// ─── API ──────────────────────────────────────────────────────────────────────

export const API_BASE_URL = import.meta.env.VITE_API_URL || '';
export const WS_URL = import.meta.env.VITE_WS_URL || `ws://${window.location.host}/ws`;

// ─── Timing ───────────────────────────────────────────────────────────────────

export const TIMING = {
  WS_RECONNECT_BASE: 1000,
  TOAST_DURATION: 5000,
  HEALTH_POLL: 30000,
  DEBOUNCE: 300,
  SEARCH_DEBOUNCE: 200,
};

// ─── Breakpoints ──────────────────────────────────────────────────────────────

export const BREAKPOINTS = {
  sm: 640,
  md: 768,
  lg: 1024,
  xl: 1280,
  '2xl': 1536,
};

// ─── Routes ───────────────────────────────────────────────────────────────────

export const ROUTES = {
  OVERVIEW: 'overview',
  THREATS: 'threats',
  IMMUNITY: 'immunity',
  BATTLEGROUND: 'battleground',
  MESH: 'mesh',
  SCANNER: 'scanner',
  COMPLIANCE: 'compliance',
  COPILOT: 'copilot',
  ANALYTICS: 'analytics',
  SETTINGS: 'settings',
  PROFILE: 'profile',
};

// ─── API Endpoints ────────────────────────────────────────────────────────────

export const ENDPOINTS = {
  HEALTH: '/api/health',
  THREATS: '/api/threats',
  EVOLUTION_TIMELINE: '/api/evolution/timeline',
  EVOLUTION_SUMMARY: '/api/evolution/summary',
  BATTLEGROUND_HISTORY: '/api/battleground/history',
  RISK_PORTFOLIO: '/api/risk/portfolio',
  RISK_ALLOCATION: '/api/risk/allocation',
  EPIDEMIOLOGICAL: '/api/epidemiological',
  SCANNER_STATIC: '/api/scanner/static',
  SCANNER_DYNAMIC: '/api/scanner/dynamic',
  SCANNER_INFRA: '/api/scanner/infra',
  SCANNER_RESULTS: '/api/scanner/results',
  COMPLIANCE_POSTURE: '/api/compliance/posture',
  COMPLIANCE_ASSESS: '/api/compliance/assess',
  COMPLIANCE_REPORT: '/api/compliance/report',
  COMPLIANCE_REPORTS: '/api/compliance/reports',
  COPILOT_CHAT: '/api/copilot/chat',
  COPILOT_EXPLAIN: '/api/copilot/explain',
  COPILOT_FIX: '/api/copilot/fix',
  COPILOT_PLAN: '/api/copilot/plan',
};

// ─── Keyboard Shortcuts ───────────────────────────────────────────────────────

export const KEYBOARD_SHORTCUTS = {
  COMMAND_PALETTE: { key: 'k', ctrl: true, label: '⌘K' },
  THEME_TOGGLE: { key: 't', ctrl: true, shift: true, label: '⌘⇧T' },
  SEARCH: { key: '/', label: '/' },
  NEW_THREAT: { key: 'n', ctrl: true, label: '⌘N' },
  HELP: { key: '?', shift: true, label: '?' },
};
