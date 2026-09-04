/**
 * Polling hooks over the live chain.
 *
 * Deliberately plain: an interval, an abortable async read, and three explicit
 * states - loading, error, data. No optimistic values and no cached
 * placeholders, because plan Section 16.3 forbids showing a value that might
 * disagree with chain state as though it were current.
 */
import { useCallback, useEffect, useRef, useState } from "react";

export interface Poll<T> {
  data: T | null;
  error: string | null;
  loading: boolean;
  /** Wall-clock of the last successful read, for the STALE indicator. */
  updatedAt: number | null;
  refresh: () => void;
}

export function usePoll<T>(
  read: () => Promise<T>,
  intervalMs = 4000,
  deps: unknown[] = [],
): Poll<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [updatedAt, setUpdatedAt] = useState<number | null>(null);
  const [tick, setTick] = useState(0);
  const alive = useRef(true);

  const refresh = useCallback(() => setTick((t) => t + 1), []);

  useEffect(() => {
    alive.current = true;
    let timer: number | undefined;

    const run = async () => {
      try {
        const value = await read();
        if (!alive.current) return;
        setData(value);
        setError(null);
        setUpdatedAt(Date.now());
      } catch (err) {
        if (!alive.current) return;
        // Surfaced, never swallowed. A dashboard that hides a failed read is
        // worse than one that shows an error, because the reader cannot tell
        // the difference between "nothing happened" and "we could not look".
        setError(describe(err));
      } finally {
        if (alive.current) setLoading(false);
      }
    };

    run();
    if (intervalMs > 0) timer = window.setInterval(run, intervalMs);
    return () => {
      alive.current = false;
      if (timer) window.clearInterval(timer);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [intervalMs, tick, ...deps]);

  return { data, error, loading, updatedAt, refresh };
}

/** A ticking wall clock, for countdowns against chain timestamps. */
export function useNow(intervalMs = 1000): number {
  const [now, setNow] = useState(() => Math.floor(Date.now() / 1000));
  useEffect(() => {
    const t = window.setInterval(() => setNow(Math.floor(Date.now() / 1000)), intervalMs);
    return () => window.clearInterval(t);
  }, [intervalMs]);
  return now;
}

export function describe(err: unknown): string {
  if (err instanceof Error) {
    const anyErr = err as { shortMessage?: string; info?: { error?: { message?: string } } };
    return anyErr.shortMessage ?? anyErr.info?.error?.message ?? err.message;
  }
  return String(err);
}
