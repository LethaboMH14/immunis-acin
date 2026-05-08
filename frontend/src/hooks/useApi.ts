// frontend/src/hooks/useApi.ts
// Data fetching hook — typed queries and mutations with loading/error states
// WHY: Every page fetches data. This hook eliminates boilerplate and ensures
// consistent loading states, error handling, and auth token injection.

import { useState, useEffect, useCallback, useRef } from 'react';
import { api, ApiError } from '../utils/api';

// ─── Types ────────────────────────────────────────────────────────────────────

interface UseApiOptions {
  /** Fetch immediately on mount */
  immediate?: boolean;
  /** Refetch interval in ms (0 = disabled) */
  pollInterval?: number;
  /** Dependencies that trigger refetch */
  deps?: unknown[];
}

interface UseApiReturn<T> {
  data: T | null;
  error: ApiError | null;
  isLoading: boolean;
  isError: boolean;
  fetch: () => Promise<T | null>;
  reset: () => void;
}

interface UseMutationReturn<TInput, TOutput> {
  data: TOutput | null;
  error: ApiError | null;
  isLoading: boolean;
  isError: boolean;
  mutate: (input: TInput) => Promise<TOutput | null>;
  reset: () => void;
}

// ─── Query Hook ───────────────────────────────────────────────────────────────

export function useApi<T>(
  endpoint: string,
  options: UseApiOptions = {}
): UseApiReturn<T> {
  const { immediate = true, pollInterval = 0, deps = [] } = options;

  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [isLoading, setIsLoading] = useState(immediate);

  const mountedRef = useRef(true);
  const pollTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const fetchData = useCallback(async (): Promise<T | null> => {
    setIsLoading(true);
    setError(null);

    try {
      const result = await api.get<T>(endpoint);
      if (mountedRef.current) {
        setData(result);
        setIsLoading(false);
      }
      return result;
    } catch (err) {
      if (mountedRef.current) {
        const apiError =
          err instanceof ApiError
            ? err
            : new ApiError(0, 'Network error', String(err));
        setError(apiError);
        setIsLoading(false);
      }
      return null;
    }
  }, [endpoint]);

  const reset = useCallback(() => {
    setData(null);
    setError(null);
    setIsLoading(false);
  }, []);

  // Initial fetch
  useEffect(() => {
    mountedRef.current = true;

    if (immediate) {
      fetchData();
    }

    return () => {
      mountedRef.current = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [immediate, endpoint, ...deps]);

  // Polling
  useEffect(() => {
    if (pollInterval > 0) {
      pollTimerRef.current = setInterval(fetchData, pollInterval);
    }

    return () => {
      if (pollTimerRef.current) {
        clearInterval(pollTimerRef.current);
      }
    };
  }, [pollInterval, fetchData]);

  return {
    data,
    error,
    isLoading,
    isError: !!error,
    fetch: fetchData,
    reset,
  };
}

// ─── Mutation Hook ────────────────────────────────────────────────────────────

export function useMutation<TInput = unknown, TOutput = unknown>(
  endpoint: string,
  method: 'POST' | 'PUT' | 'PATCH' | 'DELETE' = 'POST'
): UseMutationReturn<TInput, TOutput> {
  const [data, setData] = useState<TOutput | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  const mountedRef = useRef(true);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  const mutate = useCallback(
    async (input: TInput): Promise<TOutput | null> => {
      setIsLoading(true);
      setError(null);

      try {
        let result: TOutput;

        switch (method) {
          case 'POST':
            result = await api.post<TOutput>(endpoint, input);
            break;
          case 'PUT':
            result = await api.put<TOutput>(endpoint, input);
            break;
          case 'PATCH':
            result = await api.patch<TOutput>(endpoint, input);
            break;
          case 'DELETE':
            result = await api.delete<TOutput>(endpoint);
            break;
          default:
            throw new Error(`Unsupported method: ${method}`);
        }

        if (mountedRef.current) {
          setData(result);
          setIsLoading(false);
        }
        return result;
      } catch (err) {
        if (mountedRef.current) {
          const apiError =
            err instanceof ApiError
              ? err
              : new ApiError(0, 'Network error', String(err));
          setError(apiError);
          setIsLoading(false);
        }
        return null;
      }
    },
    [endpoint, method]
  );

  const reset = useCallback(() => {
    setData(null);
    setError(null);
    setIsLoading(false);
  }, []);

  return {
    data,
    error,
    isLoading,
    isError: !!error,
    mutate,
    reset,
  };
}

// ─── Health Check Hook ────────────────────────────────────────────────────────

export function useHealthCheck(pollInterval = 30000) {
  return useApi<{
    status: string;
    immunity_score: number;
    threats_processed: number;
    antibodies_active: number;
    mesh_nodes: number;
    uptime: number;
  }>('/api/health', { immediate: true, pollInterval });
}

export default useApi;
