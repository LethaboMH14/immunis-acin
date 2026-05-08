// frontend/src/components/common/Select.tsx
// Themed select dropdown — native select with design-system styling
// WHY: Role switcher, audience selector, framework picker, scan config.
// Native select for accessibility and mobile support.

import React from 'react';

// ─── Types ────────────────────────────────────────────────────────────────────

interface SelectOption {
  value: string;
  label: string;
  disabled?: boolean;
}

interface SelectProps extends Omit<React.SelectHTMLAttributes<HTMLSelectElement>, 'size'> {
  label?: string;
  helperText?: string;
  error?: string;
  options: SelectOption[];
  placeholder?: string;
  selectSize?: 'sm' | 'md' | 'lg';
}

// ─── Styles ───────────────────────────────────────────────────────────────────

const sizeStyles = {
  sm: 'h-8 text-xs px-2.5',
  md: 'h-10 text-sm px-3',
  lg: 'h-12 text-base px-4',
};

// ─── Component ────────────────────────────────────────────────────────────────

const Select = React.forwardRef<HTMLSelectElement, SelectProps>(
  (
    {
      label,
      helperText,
      error,
      options,
      placeholder,
      selectSize = 'md',
      className = '',
      ...props
    },
    ref
  ) => {
    const hasError = !!error;

    return (
      <div className="flex flex-col gap-1.5">
        {label && (
          <label className="text-xs font-medium text-[var(--text-secondary)]">
            {label}
          </label>
        )}
        <div className="relative">
          <select
            ref={ref}
            className={[
              'w-full rounded-lg appearance-none cursor-pointer',
              'bg-[var(--bg-tertiary)] border border-[var(--border-primary)]',
              'text-[var(--text-primary)]',
              'transition-all duration-150 pr-10',
              'focus:outline-none focus:ring-2 focus:ring-[var(--color-immune)] focus:border-transparent',
              'disabled:opacity-50 disabled:cursor-not-allowed',
              sizeStyles[selectSize],
              hasError
                ? 'border-[var(--color-threat)] focus:ring-[var(--color-threat)]'
                : '',
              className,
            ]
              .filter(Boolean)
              .join(' ')}
            {...props}
          >
            {placeholder && (
              <option value="" disabled>
                {placeholder}
              </option>
            )}
            {options.map((opt) => (
              <option key={opt.value} value={opt.value} disabled={opt.disabled}>
                {opt.label}
              </option>
            ))}
          </select>
          {/* Chevron icon */}
          <svg
            className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[var(--text-muted)] pointer-events-none"
            viewBox="0 0 16 16"
            fill="currentColor"
          >
            <path d="M4.22 6.22a.75.75 0 0 1 1.06 0L8 8.94l2.72-2.72a.75.75 0 1 1 1.06 1.06l-3.25 3.25a.75.75 0 0 1-1.06 0L4.22 7.28a.75.75 0 0 1 0-1.06Z" />
          </svg>
        </div>
        {(error || helperText) && (
          <p
            className={`text-xs ${
              hasError ? 'text-[var(--color-threat)]' : 'text-[var(--text-muted)]'
            }`}
          >
            {error || helperText}
          </p>
        )}
      </div>
    );
  }
);

Select.displayName = 'Select';

export { Select };
export type { SelectProps, SelectOption };
export default Select;
