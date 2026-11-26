import { defineConfig } from "vitest/config";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

export default defineConfig({
  test: {
    include: ["tests/**/*.test.ts"],
    // Most suites drive a real Chromium; a cold launch on a busy CI runner can exceed 5s.
    testTimeout: 30_000,
    hookTimeout: 30_000,
    // Never touch the developer's real ~/.localmcp (saved logins, usage, audit log).
    env: { LOCALMCP_HOME: mkdtempSync(join(tmpdir(), "localmcp-test-home-")) },
  },
});
