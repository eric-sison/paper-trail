import { describe, it, expect, vi } from "vitest";
import { withRetry } from "../lib/retry.js";

describe("withRetry", () => {
  it("returns result on first success", async () => {
    const fn = vi.fn().mockResolvedValue("ok");
    const result = await withRetry(fn, { retries: 3, initialDelayMs: 0 });
    expect(result).toBe("ok");
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it("retries on failure and eventually succeeds", async () => {
    const fn = vi
      .fn()
      .mockRejectedValueOnce(new Error("fail"))
      .mockRejectedValueOnce(new Error("fail"))
      .mockResolvedValue("ok");

    const result = await withRetry(fn, { retries: 3, initialDelayMs: 0 });
    expect(result).toBe("ok");
    expect(fn).toHaveBeenCalledTimes(3);
  });

  it("throws last error after all retries exhausted", async () => {
    const fn = vi.fn().mockRejectedValue(new Error("persistent failure"));
    await expect(withRetry(fn, { retries: 2, initialDelayMs: 0 })).rejects.toThrow("persistent failure");
    expect(fn).toHaveBeenCalledTimes(3); // 1 initial + 2 retries
  });

  it("stops retrying when shouldRetry returns false", async () => {
    const fn = vi.fn().mockRejectedValue(new Error("fatal"));
    await expect(
      withRetry(fn, {
        retries: 5,
        initialDelayMs: 0,
        shouldRetry: () => false,
      })
    ).rejects.toThrow("fatal");
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it("applies exponential backoff — each delay is larger than the last", async () => {
    const timestamps: number[] = [];

    const fn = vi.fn().mockImplementation(async () => {
      timestamps.push(Date.now());
      throw new Error("fail");
    });

    await expect(withRetry(fn, { retries: 2, initialDelayMs: 50, backoffFactor: 3 })).rejects.toThrow("fail");

    expect(fn).toHaveBeenCalledTimes(3);
    const gap1 = timestamps[1] - timestamps[0]; // ~50ms
    const gap2 = timestamps[2] - timestamps[1]; // ~150ms (50 * 3)
    expect(gap2).toBeGreaterThan(gap1);
  });
});
