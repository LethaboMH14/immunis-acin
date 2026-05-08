// frontend/src/utils/api.ts
// Typed API client — fetch wrapper with retry, timeout, auth, error handling
// WHY: 50+ API endpoints × many components = thousands of fetch calls.
// One client, one error handler, one retry policy.

// ─── Constants ────────────────────────────────────────────────────────────────

const API_BASE_URL = import.meta.env.VITE_API_URL || '';
const DEFAULT_TIMEOUT = 30000;
const DEFAULT_RETRIES = 2;

// ─── Error Class ──────────────────────────────────────────────────────────────

export class ApiError extends Error {
  status: number;
  detail: string;
  code?: string;

  constructor(status: number, message: string, detail?: string, code?: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.detail = detail || message;
    this.code = code;
  }
}

// ─── Types ────────────────────────────────────────────────────────────────────

interface RequestOptions {
  headers?: Record<string, string>;
  timeout?: number;
  retries?: number;
  params?: Record<string, string | number | boolean | undefined>;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function buildUrl(endpoint: string, params?: Record<string, string | number | boolean | undefined>): string {
  const url = `${API_BASE_URL}${endpoint}`;
  if (!params) return url;

  const searchParams = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined) {
      searchParams.set(key, String(value));
    }
  }
  const qs = searchParams.toString();
  return qs ? `${url}?${qs}` : url;
}

async function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ─── Core Fetch ───────────────────────────────────────────────────────────────

let authToken: string | null = null;

export function setAuthToken(token: string | null): void {
  authToken = token;
}

async function request<T>(
  method: string,
  endpoint: string,
  body?: unknown,
  options: RequestOptions = {}
): Promise<T> {
  const { headers = {}, timeout = DEFAULT_TIMEOUT, retries = DEFAULT_RETRIES, params } = options;

  const url = buildUrl(endpoint, params);

  const requestHeaders: Record<string, string> = {
    'Content-Type': 'application/json',
    ...headers,
  };

  if (authToken) {
    requestHeaders['Authorization'] = `Bearer ${authToken}`;
  }

  let lastError: Error | null = null;

  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), timeout);

      const response = await fetch(url, {
        method,
        headers: requestHeaders,
        body: body !== undefined ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        let errorDetail = '';
        let errorCode: string | undefined;

        try {
          const errorBody = await response.json();
          errorDetail = errorBody.detail || errorBody.message || '';
          errorCode = errorBody.code;
        } catch {
          errorDetail = await response.text().catch(() => '');
        }

        const error = new ApiError(
          response.status,
          `HTTP ${response.status}: ${response.statusText}`,
          errorDetail,
          errorCode
        );

        // Don't retry 4xx errors (client errors)
        if (response.status >= 400 && response.status < 500 && response.status !== 429) {
          throw error;
        }

        lastError = error;
      } else {
        // Success
        const contentType = response.headers.get('content-type');
        if (contentType && contentType.includes('application/json')) {
          return (await response.json()) as T;
        }
        // Return empty object for non-JSON responses
        return {} as T;
      }
    } catch (err) {
      if (err instanceof ApiError) {
        // Already an ApiError from non-retryable status
        if (err.status >= 400 && err.status < 500 && err.status !== 429) {
          throw err;
        }
        lastError = err;
      } else if (err instanceof DOMException && err.name === 'AbortError') {
        lastError = new ApiError(0, 'Request timeout', `Request to ${endpoint} timed out after ${timeout}ms`);
      } else {
        lastError = err instanceof Error ? err : new Error(String(err));
      }
    }

    // Wait before retry (exponential backoff)
    if (attempt < retries) {
      await sleep(Math.min(1000 * Math.pow(2, attempt), 10000));
    }
  }

  throw lastError || new ApiError(0, 'Unknown error');
}

// ─── Public API ───────────────────────────────────────────────────────────────

export const api = {
  get<T>(endpoint: string, options?: RequestOptions): Promise<T> {
    return request<T>('GET', endpoint, undefined, options);
  },

  post<T>(endpoint: string, body?: unknown, options?: RequestOptions): Promise<T> {
    return request<T>('POST', endpoint, body, options);
  },

  put<T>(endpoint: string, body?: unknown, options?: RequestOptions): Promise<T> {
    return request<T>('PUT', endpoint, body, options);
  },

  patch<T>(endpoint: string, body?: unknown, options?: RequestOptions): Promise<T> {
    return request<T>('PATCH', endpoint, body, options);
  },

  delete<T>(endpoint: string, options?: RequestOptions): Promise<T> {
    return request<T>('DELETE', endpoint, undefined, options);
  },
};

// ─── Error Helpers ────────────────────────────────────────────────────────────

export function getErrorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.detail && error.detail !== error.message) {
      return error.detail;
    }
    switch (error.status) {
      case 0: return 'Network error — check your connection';
      case 401: return 'Authentication required';
      case 403: return 'Access denied';
      case 404: return 'Resource not found';
      case 429: return 'Too many requests — please wait';
      case 500: return 'Server error — please try again';
      case 502: return 'Backend unavailable';
      case 503: return 'Service temporarily unavailable';
      default: return error.message;
    }
  }
  if (error instanceof Error) return error.message;
  return 'An unexpected error occurred';
}

export default api;
