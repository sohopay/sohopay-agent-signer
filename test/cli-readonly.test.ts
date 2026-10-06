import assert from "node:assert/strict";
import { test } from "node:test";

import { generateWorkloadKey } from "../src/keys.js";
import { computePaymentId } from "../src/voucher.js";
import { run } from "../src/cli/run.js";

const key = generateWorkloadKey();
const core = {
  agentId: "agent-1",
  merchantId: `0x${"5f".repeat(32)}`,
  asset: `0x${"ab".repeat(20)}`,
  chainId: "8453",
  amount: "1000000",
  feeAmount: "5000",
  orderRef: `0x${"9d".repeat(32)}`,
  nonce: "1",
  deadline: "4102444800",
};

test("payment-id over stdin returns the SDK's keccak paymentId", () => {
  const r = run(["payment-id", "--input", "-", "--output", "json"], JSON.stringify({ core }));
  assert.equal(r.exitCode, 0);
  assert.equal(JSON.parse(r.stdout).payment_id, computePaymentId(core));
});

test("key jkt from a public_jwk reproduces computeJkt", () => {
  const r = run(["key", "jkt", "--input", "-", "--output", "json"], JSON.stringify({ public_jwk: key.publicJwk }));
  assert.equal(r.exitCode, 0);
  assert.equal(JSON.parse(r.stdout).agent_key_jkt, key.jkt);
});

test("key jkt from a private seed derives the same jkt", () => {
  const r = run(
    ["key", "jkt", "--input", "-", "--output", "json"],
    JSON.stringify({ key: { private_key_base64url: key.privateKeyBase64Url } }),
  );
  assert.equal(r.exitCode, 0);
  assert.equal(JSON.parse(r.stdout).agent_key_jkt, key.jkt);
});

test("non-JSON stdin fails MALFORMED_ENVELOPE with exit 1 and no stack trace", () => {
  const r = run(["payment-id", "--input", "-", "--output", "json"], "not json {");
  assert.equal(r.exitCode, 1);
  assert.equal(r.stdout, "");
  assert.equal(JSON.parse(r.stderr).error.code, "MALFORMED_ENVELOPE");
  assert.doesNotMatch(r.stderr, /\bat \//);
});

test("missing --input on an input command is a usage error (exit 2)", () => {
  const r = run(["payment-id", "--output", "json"], "");
  assert.equal(r.exitCode, 2);
  assert.doesNotMatch(r.stderr, /"error"/);
});

test("a voucher field that is a number surfaces VOUCHER_FIELD_NOT_STRING", () => {
  const bad = { ...core, amount: 1000000 };
  const r = run(["payment-id", "--input", "-", "--output", "json"], JSON.stringify({ core: bad }));
  assert.equal(r.exitCode, 1);
  assert.equal(JSON.parse(r.stderr).error.code, "VOUCHER_FIELD_NOT_STRING");
});
