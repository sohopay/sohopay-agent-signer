import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { loadVectors } from "@sohopay/signer-vectors";
import { generateWorkloadKey } from "../src/keys.js";
import { computePaymentId } from "../src/voucher.js";
import { run } from "../src/cli/run.js";

const doc = loadVectors();
const testKey = doc.testKeys[0];
const vector = doc.vectors.voucherSignature[0] as {
  input: { voucher: Record<string, unknown>; signing?: unknown };
  expected: { signature: string };
};

test("voucher sign (inline key) reproduces the vector signature + payment_id + jkt", () => {
  const stdin = JSON.stringify({
    voucher: vector.input.voucher,
    signing: vector.input.signing,
    key: { private_key_base64url: testKey.seedB64Url, public_jwk: testKey.publicJwk },
  });
  const r = run(["voucher", "sign", "--input", "-", "--output", "json"], stdin);
  assert.equal(r.exitCode, 0, r.stderr);
  const out = JSON.parse(r.stdout);
  assert.equal(out.signer_protocol, "sohopay-signer/1");
  assert.equal(out.algorithm, "Ed25519");
  assert.equal(out.signature, vector.expected.signature);
  assert.equal(out.payment_id, vector.input.voucher.paymentId);
  assert.equal(out.agent_key_jkt, vector.input.voucher.agentKeyJkt);
});

test("voucher sign reads the key from --key file (stdin carries only the voucher)", () => {
  const dir = mkdtempSync(join(tmpdir(), "sohopay-cli-"));
  const keyPath = join(dir, "secret.json");
  writeFileSync(
    keyPath,
    JSON.stringify({ private_key_base64url: testKey.seedB64Url, public_jwk: testKey.publicJwk }),
    { mode: 0o600 },
  );
  chmodSync(keyPath, 0o600);
  const stdin = JSON.stringify({ voucher: vector.input.voucher, signing: vector.input.signing });
  const r = run(["voucher", "sign", "--input", "-", "--key", keyPath, "--output", "json"], stdin);
  assert.equal(r.exitCode, 0, r.stderr);
  assert.equal(JSON.parse(r.stdout).signature, vector.expected.signature);
});

test("key supplied both inline and via --key is MALFORMED_ENVELOPE", () => {
  const stdin = JSON.stringify({
    voucher: vector.input.voucher,
    key: { private_key_base64url: testKey.seedB64Url },
  });
  const r = run(["voucher", "sign", "--input", "-", "--key", "/tmp/whatever.json", "--output", "json"], stdin);
  assert.equal(r.exitCode, 1);
  assert.equal(JSON.parse(r.stderr).error.code, "MALFORMED_ENVELOPE");
});

test("a group/world-readable --key file is refused with INSECURE_KEY_PERMISSIONS", () => {
  const dir = mkdtempSync(join(tmpdir(), "sohopay-cli-"));
  const keyPath = join(dir, "secret.json");
  writeFileSync(keyPath, JSON.stringify({ private_key_base64url: testKey.seedB64Url, public_jwk: testKey.publicJwk }));
  chmodSync(keyPath, 0o644);
  const stdin = JSON.stringify({ voucher: vector.input.voucher });
  const r = run(["voucher", "sign", "--input", "-", "--key", keyPath, "--output", "json"], stdin);
  assert.equal(r.exitCode, 1);
  assert.equal(JSON.parse(r.stderr).error.code, "INSECURE_KEY_PERMISSIONS");
});

test("a tampered paymentId fails PAYMENT_ID_MISMATCH without echoing the seed", () => {
  const tampered = { ...vector.input.voucher, paymentId: `0x${"00".repeat(32)}` };
  const stdin = JSON.stringify({
    voucher: tampered,
    key: { private_key_base64url: testKey.seedB64Url, public_jwk: testKey.publicJwk },
  });
  const r = run(["voucher", "sign", "--input", "-", "--output", "json"], stdin);
  assert.equal(r.exitCode, 1);
  assert.equal(JSON.parse(r.stderr).error.code, "PAYMENT_ID_MISMATCH");
  assert.ok(!r.stderr.includes(testKey.seedB64Url), "stderr must not contain the private seed");
});

test("a jkt that does not match the signing key fails AGENT_KEY_JKT_MISMATCH", () => {
  const otherJkt = generateWorkloadKey().jkt;
  const voucher = { ...vector.input.voucher, agentKeyJkt: otherJkt } as Record<string, unknown>;
  // recompute paymentId so only the jkt guard trips, not PAYMENT_ID_MISMATCH.
  const { paymentId: _p, agentKeyJkt: _j, ...core } = voucher;
  const rebuilt = { ...voucher, paymentId: computePaymentId(core as never) };
  const stdin = JSON.stringify({
    voucher: rebuilt,
    key: { private_key_base64url: testKey.seedB64Url, public_jwk: testKey.publicJwk },
  });
  const r = run(["voucher", "sign", "--input", "-", "--output", "json"], stdin);
  assert.equal(r.exitCode, 1);
  assert.equal(JSON.parse(r.stderr).error.code, "AGENT_KEY_JKT_MISMATCH");
});

test("a seed-only key whose jkt does not match the voucher fails AGENT_KEY_JKT_MISMATCH", () => {
  const otherJkt = generateWorkloadKey().jkt;
  const voucher = { ...vector.input.voucher, agentKeyJkt: otherJkt } as Record<string, unknown>;
  const { paymentId: _p, agentKeyJkt: _j, ...core } = voucher;
  const rebuilt = { ...voucher, paymentId: computePaymentId(core as never) };
  const stdin = JSON.stringify({ voucher: rebuilt, key: { private_key_base64url: testKey.seedB64Url } });
  const r = run(["voucher", "sign", "--input", "-", "--output", "json"], stdin);
  assert.equal(r.exitCode, 1);
  assert.equal(JSON.parse(r.stderr).error.code, "AGENT_KEY_JKT_MISMATCH");
});

test("--input - and --key - cannot both read stdin (usage error, exit 2)", () => {
  const r = run(["voucher", "sign", "--input", "-", "--key", "-", "--output", "json"], "{}");
  assert.equal(r.exitCode, 2);
  assert.doesNotMatch(r.stderr, /"error"/);
});
