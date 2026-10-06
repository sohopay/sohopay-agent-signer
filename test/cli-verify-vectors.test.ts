import assert from "node:assert/strict";
import { test } from "node:test";

import { run } from "../src/cli/run.js";
import { verifyVectors } from "../src/cli/verify-vectors.js";

test("verifyVectors passes every vector with zero failures", () => {
  const summary = verifyVectors();
  assert.equal(summary.failed, 0, summary.failures.join("; "));
  assert.ok(summary.total > 0);
  assert.equal(summary.passed, summary.total);
});

test("verify-vectors (json) exits 0 and summarizes pass/fail/total", () => {
  const r = run(["verify-vectors", "--output", "json"], "");
  assert.equal(r.exitCode, 0, r.stderr);
  const out = JSON.parse(r.stdout);
  assert.equal(out.failed, 0);
  assert.equal(out.passed, out.total);
});
