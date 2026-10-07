// test/inv-noseed.test.ts
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import assert from "node:assert/strict";
import test from "node:test";
import { parseArgs } from "../src/cli/args.js";

test("--seed is an unknown flag (no CLI RNG seam)", () => {
  assert.throws(() => parseArgs(["key", "generate", "--seed", "0", "--out", "/x/secret.json", "--input", "-"]),
    /unknown flag: --seed/);
});

test("no source file references a seed/test-RNG env or flag", () => {
  const offenders: string[] = [];
  const walk = (d: string) => {
    for (const e of readdirSync(d, { withFileTypes: true })) {
      const p = join(d, e.name);
      if (e.isDirectory()) walk(p);
      else if (e.name.endsWith(".ts") && /--seed|SOHOPAY_SIGNER_SEED|TEST_RNG|deterministicKeygen/.test(readFileSync(p, "utf8"))) {
        offenders.push(p);
      }
    }
  };
  walk(join(process.cwd(), "src"));
  assert.deepEqual(offenders, [], `RNG seam found in: ${offenders.join(", ")}`);
});
