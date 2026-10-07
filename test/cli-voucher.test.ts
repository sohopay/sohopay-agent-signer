import assert from "node:assert/strict";
import { chmodSync } from "node:fs";
import { test } from "node:test";

import { loadVectors } from "@sohopay/signer-vectors";
import { generateWorkloadKey } from "../src/keys.js";
import { computePaymentId } from "../src/voucher.js";
import { run } from "../src/cli/run.js";
import { withKeyFile } from "./key-home-fixture.js";

const doc = loadVectors();
const testKey = doc.testKeys[0];
const vector = doc.vectors.voucherSignature[0] as {
  input: { voucher: Record<string, unknown>; signing?: unknown };
  expected: { signature: string };
};

const fullKey = { private_key_base64url: testKey.seedB64Url, public_jwk: testKey.publicJwk };

function signWith(content: Record<string, unknown>, voucher: unknown, extra: Record<string, unknown> = {}) {
  return withKeyFile(content, (keyPath) =>
    run(["voucher", "sign", "--input", "-", "--key", keyPath, "--output", "json"], JSON.stringify({ voucher, ...extra })),
  );
}

test("voucher sign (--key file) reproduces the vector signature + payment_id + jkt", () => {
  const r = signWith(fullKey, vector.input.voucher, { signing: vector.input.signing });
  assert.equal(r.exitCode, 0, r.stderr);
  const out = JSON.parse(r.stdout);
  assert.equal(out.signer_protocol, "sohopay-signer/1");
  assert.equal(out.algorithm, "Ed25519");
  assert.equal(out.signature, vector.expected.signature);
  assert.equal(out.payment_id, vector.input.voucher.paymentId);
  assert.equal(out.agent_key_jkt, vector.input.voucher.agentKeyJkt);
});

test("an inline key in the input is INLINE_KEY_REJECTED, even alongside --key", () => {
  const r = signWith(fullKey, vector.input.voucher, { key: { private_key_base64url: testKey.seedB64Url } });
  assert.equal(r.exitCode, 1);
  assert.equal(JSON.parse(r.stderr).error.code, "INLINE_KEY_REJECTED");
  assert.ok(!r.stderr.includes(testKey.seedB64Url), "stderr must not contain the private seed");
});

test("a group/world-readable --key file is refused with INSECURE_KEY_PERMISSIONS or KEY_PATH_INVALID", () => {
  const r = withKeyFile(fullKey, (keyPath) => {
    chmodSync(keyPath, 0o644);
    return run(["voucher", "sign", "--input", "-", "--key", keyPath, "--output", "json"], JSON.stringify({ voucher: vector.input.voucher }));
  });
  assert.equal(r.exitCode, 1);
  // The path validator rejects a too-permissive mode before storage's own check runs.
  assert.match(JSON.parse(r.stderr).error.code, /^(INSECURE_KEY_PERMISSIONS|KEY_PATH_INVALID)$/);
});

test("a tampered paymentId fails PAYMENT_ID_MISMATCH without echoing the seed", () => {
  const tampered = { ...vector.input.voucher, paymentId: `0x${"00".repeat(32)}` };
  const r = signWith(fullKey, tampered);
  assert.equal(r.exitCode, 1);
  assert.equal(JSON.parse(r.stderr).error.code, "PAYMENT_ID_MISMATCH");
  assert.ok(!r.stderr.includes(testKey.seedB64Url), "stderr must not contain the private seed");
});

function rebuiltWithOtherJkt() {
  const otherJkt = generateWorkloadKey().jkt;
  const voucher = { ...vector.input.voucher, agentKeyJkt: otherJkt } as Record<string, unknown>;
  // recompute paymentId so only the jkt guard trips, not PAYMENT_ID_MISMATCH.
  const { paymentId: _p, agentKeyJkt: _j, ...core } = voucher;
  return { ...voucher, paymentId: computePaymentId(core as never) };
}

test("a jkt that does not match the signing key fails AGENT_KEY_JKT_MISMATCH", () => {
  const r = signWith(fullKey, rebuiltWithOtherJkt());
  assert.equal(r.exitCode, 1);
  assert.equal(JSON.parse(r.stderr).error.code, "AGENT_KEY_JKT_MISMATCH");
});

test("a seed-only key whose jkt does not match the voucher fails AGENT_KEY_JKT_MISMATCH", () => {
  const r = signWith({ private_key_base64url: testKey.seedB64Url }, rebuiltWithOtherJkt());
  assert.equal(r.exitCode, 1);
  assert.equal(JSON.parse(r.stderr).error.code, "AGENT_KEY_JKT_MISMATCH");
});

test("voucher sign without --key is MALFORMED_INPUT", () => {
  const r = run(["voucher", "sign", "--input", "-", "--output", "json"], JSON.stringify({ voucher: vector.input.voucher }));
  assert.equal(r.exitCode, 1);
  assert.equal(JSON.parse(r.stderr).error.code, "MALFORMED_INPUT");
});

test("--input - and --key - cannot both read stdin (usage error, exit 2)", () => {
  const r = run(["voucher", "sign", "--input", "-", "--key", "-", "--output", "json"], "{}");
  assert.equal(r.exitCode, 2);
  assert.doesNotMatch(r.stderr, /"error"/);
});

test("a wrong-length private seed fails INVALID_PRIVATE_KEY (not MALFORMED_ENVELOPE)", () => {
  // 3 bytes, not a 32-byte Ed25519 seed
  const r = signWith({ private_key_base64url: "AAAA" }, vector.input.voucher);
  assert.equal(r.exitCode, 1);
  assert.equal(JSON.parse(r.stderr).error.code, "INVALID_PRIVATE_KEY");
});
