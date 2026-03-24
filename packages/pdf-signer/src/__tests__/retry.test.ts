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
});
