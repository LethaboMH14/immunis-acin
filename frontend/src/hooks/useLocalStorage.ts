// frontend/src/hooks/useLocalStorage.ts
// Persistent state hook with cross-tab sync
// WHY: Sidebar state, filter preferences, panel sizes — many components
// need state that survives page refresh. This hook handles serialization,
// error recovery, and cross-tab synchronization.

import { useState, useEffect, useCallback } from 'react';

const PREFIX = 'immunis-';

function getStoredValue<T>(key: string, initialValue: T): T {
  if (typeof window === 'undefined') return initialValue;
  try {
    const raw = localStorage.getItem(PREFIX + key);
    if (raw === null) return initialValue;
    return JSON.parse(raw) as T;
  } catch {
    // Corrupted data — return initial
    return initialValue;
  }
}

export function useLocalStorage<T>(
  key: string,
  initialValue: T
): [T, (value: T | ((prev: T) => T)) => void, () => void] {
  const [storedValue, setStoredValue] = useState<T>(() =>
    getStoredValue(key, initialValue)
  );

  const setValue = useCallback(
    (value: T | ((prev: T) => T)) => {
      setStoredValue((prev) => {
        const nextValue =
          value instanceof Function ? value(prev) : value;
        try {
          localStorage.setItem(PREFIX + key, JSON.stringify(nextValue));
        } catch (err) {
          console.warn(`[useLocalStorage] Failed to save "${key}":`, err);
        }
        return nextValue;
      });
    },
    [key]
  );

  const removeValue = useCallback(() => {
    setStoredValue(initialValue);
    try {
      localStorage.removeItem(PREFIX + key);
    } catch {
      // Silently fail
    }
  }, [key, initialValue]);

  // Cross-tab sync
  useEffect(() => {
    const handler = (e: StorageEvent) => {
      if (e.key !== PREFIX + key) return;
      if (e.newValue === null) {
        setStoredValue(initialValue);
      } else {
        try {
          setStoredValue(JSON.parse(e.newValue) as T);
        } catch {
          // Corrupted — ignore
        }
      }
    };

    window.addEventListener('storage', handler);
    return () => window.removeEventListener('storage', handler);
  }, [key, initialValue]);

  return [storedValue, setValue, removeValue];
}
