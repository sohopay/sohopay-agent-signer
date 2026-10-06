import assert from "node:assert/strict";
import { test } from "node:test";

import { loadVectors } from "@sohopay/signer-vectors";

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

test("verifyVectors reports a failure when an expected value is corrupted", () => {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const doc = structuredClone(loadVectors()) as any;
  doc.vectors.voucherSignature[0].expected.signature = "AAAA";
  const summary = verifyVectors(doc);
  assert.ok(summary.failed > 0);
});

test("verifyVectors fails a negative vector whose expected code is wrong", () => {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const doc = structuredClone(loadVectors()) as any;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const neg = doc.negative.find((v: any) => v.id === "neg-pop-iat-float");
  neg.expectError = "NOT_A_REAL_CODE";
  const summary = verifyVectors(doc);
  assert.ok(summary.failures.some((f: string) => f.startsWith("neg-pop-iat-float")));
});
