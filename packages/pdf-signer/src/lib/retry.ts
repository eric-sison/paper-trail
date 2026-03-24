/**
 * @file retry.ts
 * Generic retry utility with exponential backoff.
 */

export interface RetryOptions {
  /** Number of retry attempts after the first failure (default 2) */
  retries: number;
  /** Initial delay between retries in ms (default 500) */
  initialDelayMs: number;
  /** Multiplier applied to delay after each attempt (default 2) */
  backoffFactor?: number;
  /** Optional predicate — return false to stop retrying immediately */
  shouldRetry?: (err: Error) => boolean;
}

export const DEFAULT_OCSP_RETRY: RetryOptions = {
  retries: 2,
  initialDelayMs: 500,
  backoffFactor: 2,
};

export const DEFAULT_TSA_RETRY: RetryOptions = {
  retries: 2,
  initialDelayMs: 1000,
  backoffFactor: 2,
};

/**
 * Calls fn() up to retries+1 times with exponential backoff.
 * Throws the last error if all attempts fail.
 */
export async function withRetry<T>(fn: () => Promise<T>, options: RetryOptions): Promise<T> {
  const { retries, initialDelayMs, backoffFactor = 2, shouldRetry } = options;

  let lastError!: Error;
  let delay = initialDelayMs;

  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      return await fn();
    } catch (err) {
      lastError = err as Error;

      if (attempt === retries) break;
      if (shouldRetry && !shouldRetry(lastError)) break;

      await sleep(delay);
      delay *= backoffFactor;
    }
  }

  throw lastError;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
