// frontend/src/components/common/Input.tsx
// Text input + textarea — label, error, icons, clearable, auto-resize
// WHY: Threat submission, search, command palette, copilot chat, scanner
// config — all need consistent, accessible text input.

import React, { useRef, useEffect, useCallback } from 'react';

// ─── Types ────────────────────────────────────────────────────────────────────

interface InputProps extends Omit<React.InputHTMLAttributes<HTMLInputElement>, 'size'> {
  label?: string;
  helperText?: string;
  error?: string;
  iconLeft?: React.ReactNode;
  iconRight?: React.ReactNode;
  clearable?: boolean;
  onClear?: () => void;
  inputSize?: 'sm' | 'md' | 'lg';
}

interface TextAreaProps extends React.TextareaHTMLAttributes<HTMLTextAreaElement> {
  label?: string;
  helperText?: string;
  error?: string;
  autoResize?: boolean;
  maxRows?: number;
}

// ─── Size Styles ──────────────────────────────────────────────────────────────

const sizeStyles = {
  sm: 'h-8 text-xs px-2.5',
  md: 'h-10 text-sm px-3',
  lg: 'h-12 text-base px-4',
};

// ─── Base Classes ─────────────────────────────────────────────────────────────

const baseInputClasses = [
  'w-full rounded-lg',
  'bg-[var(--bg-tertiary)] border border-[var(--border-primary)]',
  'text-[var(--text-primary)] placeholder:text-[var(--text-muted)]',
  'transition-all duration-150',
  'focus:outline-none focus:ring-2 focus:ring-[var(--color-immune)] focus:border-transparent',
  'disabled:opacity-50 disabled:cursor-not-allowed',
].join(' ');

// ─── Input Component ──────────────────────────────────────────────────────────

const Input = React.forwardRef<HTMLInputElement, InputProps>(
  (
    {
      label,
      helperText,
      error,
      iconLeft,
      iconRight,
      clearable,
      onClear,
      inputSize = 'md',
      className = '',
      value,
      ...props
    },
    ref
  ) => {
    const hasError = !!error;
    const showClear = clearable && value && String(value).length > 0;

    return (
      <div className="flex flex-col gap-1.5">
        {label && (
          <label className="text-xs font-medium text-[var(--text-secondary)]">
            {label}
          </label>
        )}
        <div className="relative">
          {iconLeft && (
            <span className="absolute left-3 top-1/2 -translate-y-1/2 text-[var(--text-muted)]">
              {iconLeft}
            </span>
          )}
          <input
            ref={ref}
            value={value}
            className={[
              baseInputClasses,
              sizeStyles[inputSize],
              iconLeft ? 'pl-9' : '',
              iconRight || showClear ? 'pr-9' : '',
              hasError
                ? 'border-[var(--color-threat)] focus:ring-[var(--color-threat)]'
                : '',
              className,
            ]
              .filter(Boolean)
              .join(' ')}
            {...props}
          />
          {showClear && (
            <button
              type="button"
              onClick={onClear}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-[var(--text-muted)] hover:text-[var(--text-primary)] transition-colors"
              aria-label="Clear input"
            >
              <svg width="14" height="14" viewBox="0 0 14 14" fill="currentColor">
                <path d="M4.17 4.17a.75.75 0 0 1 1.06 0L7 5.94l1.77-1.77a.75.75 0 1 1 1.06 1.06L8.06 7l1.77 1.77a.75.75 0 1 1-1.06 1.06L7 8.06l-1.77 1.77a.75.75 0 0 1-1.06-1.06L5.94 7 4.17 5.23a.75.75 0 0 1 0-1.06Z" />
              </svg>
            </button>
          )}
          {iconRight && !showClear && (
            <span className="absolute right-3 top-1/2 -translate-y-1/2 text-[var(--text-muted)]">
              {iconRight}
            </span>
          )}
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

Input.displayName = 'Input';

// ─── TextArea Component ───────────────────────────────────────────────────────

const TextArea = React.forwardRef<HTMLTextAreaElement, TextAreaProps>(
  (
    {
      label,
      helperText,
      error,
      autoResize = false,
      maxRows = 10,
      className = '',
      ...props
    },
    ref
  ) => {
    const internalRef = useRef<HTMLTextAreaElement | null>(null);
    const hasError = !!error;

    const resize = useCallback(() => {
      const el = internalRef.current;
      if (!el || !autoResize) return;

      el.style.height = 'auto';
      const lineHeight = parseInt(getComputedStyle(el).lineHeight) || 20;
      const maxHeight = lineHeight * maxRows;
      el.style.height = `${Math.min(el.scrollHeight, maxHeight)}px`;
    }, [autoResize, maxRows]);

    useEffect(() => {
      resize();
    }, [props.value, resize]);

    return (
      <div className="flex flex-col gap-1.5">
        {label && (
          <label className="text-xs font-medium text-[var(--text-secondary)]">
            {label}
          </label>
        )}
        <textarea
          ref={(el) => {
            internalRef.current = el;
            if (typeof ref === 'function') ref(el);
            else if (ref) ref.current = el;
          }}
          onInput={resize}
          className={[
            baseInputClasses,
            'min-h-[80px] py-2.5 px-3 text-sm resize-none',
            hasError
              ? 'border-[var(--color-threat)] focus:ring-[var(--color-threat)]'
              : '',
            className,
          ]
            .filter(Boolean)
            .join(' ')}
          {...props}
        />
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

TextArea.displayName = 'TextArea';

export { Input, TextArea };
export type { InputProps, TextAreaProps };
export default Input;
