// frontend/src/components/common/ErrorBoundary.tsx
// Error boundary — catches render errors, shows recovery UI
// WHY: A single broken component should not crash the entire dashboard.
// SOC analysts cannot afford downtime. Graceful degradation is mandatory.

import React from 'react';
import { Button } from './Button';

// ─── Types ────────────────────────────────────────────────────────────────────

interface ErrorBoundaryProps {
  children: React.ReactNode;
  fallback?: React.ReactNode;
  onError?: (error: Error, errorInfo: React.ErrorInfo) => void;
  resetKey?: string | number;
}

interface ErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
  errorInfo: React.ErrorInfo | null;
}

// ─── Component ────────────────────────────────────────────────────────────────

export class ErrorBoundary extends React.Component<
  ErrorBoundaryProps,
  ErrorBoundaryState
> {
  constructor(props: ErrorBoundaryProps) {
    super(props);
    this.state = {
      hasError: false,
      error: null,
      errorInfo: null,
    };
  }

  static getDerivedStateFromError(error: Error): Partial<ErrorBoundaryState> {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo): void {
    this.setState({ errorInfo });

    // Log error
    console.error('[ErrorBoundary] Caught error:', error);
    console.error('[ErrorBoundary] Component stack:', errorInfo.componentStack);

    // Notify parent
    this.props.onError?.(error, errorInfo);
  }

  componentDidUpdate(prevProps: ErrorBoundaryProps): void {
    // Reset when resetKey changes
    if (
      this.state.hasError &&
      prevProps.resetKey !== this.props.resetKey
    ) {
      this.setState({
        hasError: false,
        error: null,
        errorInfo: null,
      });
    }
  }

  handleReset = (): void => {
    this.setState({
      hasError: false,
      error: null,
      errorInfo: null,
    });
  };

  render(): React.ReactNode {
    if (this.state.hasError) {
      // Custom fallback
      if (this.props.fallback) {
        return this.props.fallback;
      }

      // Default error UI
      return (
        <div className="flex flex-col items-center justify-center p-8 rounded-xl bg-[var(--bg-secondary)] border border-[var(--border-primary)]">
          {/* Error icon */}
          <div className="w-12 h-12 rounded-full bg-red-500/10 flex items-center justify-center mb-4">
            <svg
              width="24"
              height="24"
              viewBox="0 0 24 24"
              fill="none"
              className="text-red-400"
            >
              <path
                d="M12 9v4m0 4h.01M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </svg>
          </div>

          <h3 className="text-sm font-semibold text-[var(--text-primary)] mb-1">
            Component Error
          </h3>
          <p className="text-xs text-[var(--text-muted)] text-center max-w-sm mb-4">
            {this.state.error?.message || 'An unexpected error occurred in this component.'}
          </p>

          {/* Stack trace in development */}
          {import.meta.env.DEV && this.state.errorInfo?.componentStack && (
            <pre className="w-full max-h-32 overflow-auto p-3 mb-4 rounded-lg bg-[var(--bg-tertiary)] text-[10px] font-mono text-[var(--text-muted)] whitespace-pre-wrap">
              {this.state.errorInfo.componentStack}
            </pre>
          )}

          <Button variant="outline" size="sm" onClick={this.handleReset}>
            Try Again
          </Button>
        </div>
      );
    }

    return this.props.children;
  }
}

export default ErrorBoundary;
