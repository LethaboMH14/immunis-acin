// frontend/src/components/common/Breadcrumbs.tsx
// Breadcrumb navigation — location awareness in deep navigation
// WHY: When a user drills into Threats → Incident → Antibody → Verification,
// they need to know where they are and how to get back.

import React from 'react';

// ─── Types ────────────────────────────────────────────────────────────────────

interface BreadcrumbItem {
  label: string;
  href?: string;
  onClick?: () => void;
}

interface BreadcrumbsProps {
  items: BreadcrumbItem[];
  maxItems?: number;
  className?: string;
}

// ─── Chevron ──────────────────────────────────────────────────────────────────

function Chevron() {
  return (
    <svg
      width="14"
      height="14"
      viewBox="0 0 14 14"
      fill="currentColor"
      className="text-[var(--text-muted)] flex-shrink-0"
    >
      <path d="M5.22 3.22a.75.75 0 0 1 1.06 0l3.25 3.25a.75.75 0 0 1 0 1.06l-3.25 3.25a.75.75 0 0 1-1.06-1.06L7.94 7 5.22 4.28a.75.75 0 0 1 0-1.06Z" />
    </svg>
  );
}

// ─── Component ────────────────────────────────────────────────────────────────

export function Breadcrumbs({
  items,
  maxItems = 4,
  className = '',
}: BreadcrumbsProps) {
  let displayItems = items;

  // Truncate if too many items
  if (items.length > maxItems) {
    const first = items[0];
    const last = items.slice(-(maxItems - 1));
    displayItems = [
      first,
      { label: '...' },
      ...last,
    ];
  }

  return (
    <nav
      aria-label="Breadcrumb"
      className={`flex items-center gap-1 ${className}`}
    >
      <ol className="flex items-center gap-1">
        {displayItems.map((item, index) => {
          const isLast = index === displayItems.length - 1;
          const isEllipsis = item.label === '...';
          const isClickable = !isLast && !isEllipsis && (item.href || item.onClick);

          return (
            <li key={index} className="flex items-center gap-1">
              {index > 0 && <Chevron />}
              {isClickable ? (
                <button
                  onClick={item.onClick}
                  className="text-xs text-[var(--text-muted)] hover:text-[var(--text-primary)] transition-colors truncate max-w-[120px]"
                >
                  {item.label}
                </button>
              ) : (
                <span
                  className={[
                    'text-xs truncate max-w-[160px]',
                    isLast
                      ? 'font-medium text-[var(--text-primary)]'
                      : 'text-[var(--text-muted)]',
                  ].join(' ')}
                  aria-current={isLast ? 'page' : undefined}
                >
                  {item.label}
                </span>
              )}
            </li>
          );
        })}
      </ol>
    </nav>
  );
}

export type { BreadcrumbsProps, BreadcrumbItem };
export default Breadcrumbs;
