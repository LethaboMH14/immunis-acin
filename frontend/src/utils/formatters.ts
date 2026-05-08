// frontend/src/utils/formatters.ts
// Formatting utilities — dates, numbers, currency, severity
// WHY: Consistency. "R2,400,000" vs "R2.4M" vs "2400000" — one source of truth.

// ─── Date/Time ────────────────────────────────────────────────────────────────

export function formatDate(input: string | Date | undefined): string {
  if (!input) return '—';
  const date = typeof input === 'string' ? new Date(input) : input;
  if (isNaN(date.getTime())) return '—';
  return date.toLocaleDateString('en-ZA', { year: 'numeric', month: 'short', day: 'numeric' });
}

export function formatTime(input: string | Date | undefined): string {
  if (!input) return '—';
  const date = typeof input === 'string' ? new Date(input) : input;
  if (isNaN(date.getTime())) return '—';
  return date.toLocaleTimeString('en-ZA', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

export function formatDateTime(input: string | Date | undefined): string {
  if (!input) return '—';
  const date = typeof input === 'string' ? new Date(input) : input;
  if (isNaN(date.getTime())) return '—';
  return `${formatDate(date)} ${formatTime(date)}`;
}

export function formatRelativeTime(input: string | Date | undefined): string {
  if (!input) return '—';
  const date = typeof input === 'string' ? new Date(input) : input;
  if (isNaN(date.getTime())) return '—';

  const now = Date.now();
  const diff = now - date.getTime();
  const seconds = Math.floor(diff / 1000);

  if (seconds < 5) return 'just now';
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 7) return `${days}d ago`;
  return formatDate(date);
}

// ─── Duration ─────────────────────────────────────────────────────────────────

export function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  const seconds = ms / 1000;
  if (seconds < 60) return `${seconds.toFixed(1)}s`;
  const minutes = Math.floor(seconds / 60);
  const remainingSeconds = Math.floor(seconds % 60);
  return `${minutes}m ${remainingSeconds}s`;
}

export function formatDurationSeconds(totalSeconds: number): string {
  if (totalSeconds < 60) return `${totalSeconds}s`;
  if (totalSeconds < 3600) {
    const m = Math.floor(totalSeconds / 60);
    const s = Math.floor(totalSeconds % 60);
    return `${m}m ${s}s`;
  }
  const h = Math.floor(totalSeconds / 3600);
  const m = Math.floor((totalSeconds % 3600) / 60);
  return `${h}h ${m}m`;
}

// ─── Numbers ──────────────────────────────────────────────────────────────────

export function formatNumber(value: number): string {
  return value.toLocaleString('en-ZA');
}

export function formatCompact(value: number): string {
  if (value >= 1_000_000_000) return `${(value / 1_000_000_000).toFixed(1)}B`;
  if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(1)}M`;
  if (value >= 1_000) return `${(value / 1_000).toFixed(1)}K`;
  return String(value);
}

export function formatPercent(value: number, decimals = 1): string {
  return `${(value * 100).toFixed(decimals)}%`;
}

export function formatScore(value: number): string {
  return Math.round(value).toString();
}

// ─── Currency ─────────────────────────────────────────────────────────────────

export function formatZAR(value: number): string {
  if (value >= 1_000_000) return `R${(value / 1_000_000).toFixed(1)}M`;
  if (value >= 1_000) return `R${(value / 1_000).toFixed(0)}K`;
  return `R${value.toFixed(0)}`;
}

// ─── Language ─────────────────────────────────────────────────────────────────

const LANGUAGE_NAMES: Record<string, string> = {
  en: 'English',
  zu: 'isiZulu',
  xh: 'isiXhosa',
  st: 'Sesotho',
  tn: 'Setswana',
  nso: 'Sepedi',
  af: 'Afrikaans',
  ts: 'Xitsonga',
  ve: 'Tshivenda',
  nr: 'isiNdebele',
  ss: 'siSwati',
  ar: 'Arabic',
  zh: 'Chinese',
  hi: 'Hindi',
  ru: 'Russian',
  fr: 'French',
  es: 'Spanish',
  de: 'German',
  ja: 'Japanese',
  ko: 'Korean',
  pt: 'Portuguese',
  sw: 'Kiswahili',
  ha: 'Hausa',
  yo: 'Yoruba',
  ig: 'Igbo',
  am: 'Amharic',
  unknown: 'Unknown',
};

export function formatLanguage(code: string): string {
  return LANGUAGE_NAMES[code?.toLowerCase()] || code?.toUpperCase() || 'Unknown';
}

// ─── Severity ─────────────────────────────────────────────────────────────────

export function formatSeverity(severity: string): string {
  return severity?.charAt(0).toUpperCase() + severity?.slice(1).toLowerCase() || 'Unknown';
}

export function formatClassification(classification: string): string {
  return classification?.charAt(0).toUpperCase() + classification?.slice(1).toLowerCase() || 'Unknown';
}
