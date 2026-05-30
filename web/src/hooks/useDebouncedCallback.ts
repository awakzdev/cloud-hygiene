import { useCallback, useEffect, useRef } from "react";

/** Debounce a callback; latest args win. Cleared on unmount. */
export function useDebouncedCallback<T extends (...args: never[]) => void>(
  fn: T,
  delayMs: number,
): T {
  const fnRef = useRef(fn);
  const timerRef = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  fnRef.current = fn;

  useEffect(() => () => clearTimeout(timerRef.current), []);

  return useCallback(
    (...args: Parameters<T>) => {
      clearTimeout(timerRef.current);
      timerRef.current = setTimeout(() => fnRef.current(...args), delayMs);
    },
    [delayMs],
  ) as T;
}
