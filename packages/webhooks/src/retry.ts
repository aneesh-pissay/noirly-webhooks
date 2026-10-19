import type { DeliveryResult } from "./delivery.js";

/** Waits before each retry: 1 minute, 5 minutes, 30 minutes, 2 hours, 6 hours. */
export const RETRY_DELAYS_SECONDS = [60, 300, 1800, 7200, 21600] as const;

/** The first try plus every retry. */
export const MAX_ATTEMPTS = RETRY_DELAYS_SECONDS.length + 1;

/** A 410 Gone means the receiver wants no more; everything else that failed may be retried. */
export function isRetryable(result: Pick<DeliveryResult, "ok" | "status">) {
  return !result.ok && result.status !== 410;
}

/**
 * When to try again after `attemptsMade` tries, or null to give up. A little
 * jitter (up to 10%) keeps a burst of failures from retrying in lockstep.
 */
export function nextAttemptAt(attemptsMade: number, now: Date = new Date(), random: () => number = Math.random): Date | null {
  if (attemptsMade < 1 || attemptsMade >= MAX_ATTEMPTS) return null;
  const delay = RETRY_DELAYS_SECONDS[attemptsMade - 1]!;
  return new Date(now.getTime() + Math.round(delay * (1 + random() * 0.1)) * 1000);
}
