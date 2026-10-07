// test/key-generate-race.test.ts
import { mkdtempSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import assert from "node:assert/strict";
import test from "node:test";
import { keyGenerateResult } from "../src/cli/key-generate.js";

test("two parallel generates yield one key; exactly one created:true, same jkt", async () => {
  const home = mkdtempSync(join(tmpdir(), "kg-race-"));
  const root = join(home, ".agents", "sohopay-agent-workload");
  mkdirSync(root, { recursive: true, mode: 0o700 });
  const out = join(root, "secret.json");
  const opts = { homeDir: home, env: {} as NodeJS.ProcessEnv };
  try {
    const [a, b] = (await Promise.all([
      Promise.resolve().then(() => keyGenerateResult({ borrower_id: "b1", terminal_id: "t1" }, out, opts)),
      Promise.resolve().then(() => keyGenerateResult({ borrower_id: "b1", terminal_id: "t1" }, out, opts)),
    ])) as Record<string, unknown>[];
    assert.equal([a.created, b.created].filter((c) => c === true).length, 1);
    assert.equal(a.jkt, b.jkt);
  } finally { rmSync(home, { recursive: true, force: true }); }
});
