import { useCallback, useEffect, useRef, useState } from "react";

export interface AsyncState<T> {
  data: T | undefined;
  error: Error | undefined;
  loading: boolean;
  reload: () => void;
}

/**
 * Run an async loader when `deps` change; optionally poll while `poll(data)` is true.
 * Stale responses (from an older deps value) are ignored, so fast filter changes
 * can never show results for the wrong query.
 */
export function useAsync<T>(
  load: () => Promise<T>,
  deps: readonly unknown[],
  poll?: { everyMs: number; while: (data: T | undefined) => boolean },
): AsyncState<T> {
  const [data, setData] = useState<T>();
  const [error, setError] = useState<Error>();
  const [loading, setLoading] = useState(true);
  const [tick, setTick] = useState(0);
  const generation = useRef(0);
  const reload = useCallback(() => setTick((t) => t + 1), []);

  useEffect(() => {
    const mine = ++generation.current;
    setLoading(true);
    load().then(
      (value) => {
        if (mine !== generation.current) return;
        setData(value);
        setError(undefined);
        setLoading(false);
      },
      (err: unknown) => {
        if (mine !== generation.current) return;
        setError(err instanceof Error ? err : new Error(String(err)));
        setLoading(false);
      },
    );
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick]);

  useEffect(() => {
    if (!poll || loading || !poll.while(data)) return;
    const id = setTimeout(reload, poll.everyMs);
    return () => clearTimeout(id);
  }, [poll, loading, data, reload]);

  return { data, error, loading, reload };
}
