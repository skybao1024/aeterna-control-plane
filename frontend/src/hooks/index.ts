// Custom hooks example
import { useState, useCallback } from 'react';

/**
 * Hook for handling async loading states
 */
export function useLoading(initialState = false) {
  const [loading, setLoading] = useState(initialState);

  const withLoading = useCallback(async <T>(fn: () => Promise<T>): Promise<T> => {
    setLoading(true);
    try {
      return await fn();
    } finally {
      setLoading(false);
    }
  }, []);

  return { loading, setLoading, withLoading };
}

/**
 * Hook for handling toggle states
 */
export function useToggle(initialState = false) {
  const [state, setState] = useState(initialState);

  const toggle = useCallback(() => setState((prev) => !prev), []);
  const setTrue = useCallback(() => setState(true), []);
  const setFalse = useCallback(() => setState(false), []);

  return { state, toggle, setTrue, setFalse };
}
