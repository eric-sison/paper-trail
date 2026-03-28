// packages/pdf-signer/vitest.config.ts
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["src/__tests__/**/*.test.ts"],
    exclude: ["**/dist/**", "**/node_modules/**"],
    onConsoleLog(_, type) {
      if (type === "stderr") return false; // suppress warn/error
    },
  },
});
