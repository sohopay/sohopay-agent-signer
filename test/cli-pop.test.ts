import assert from "node:assert/strict";
import { test } from "node:test";

import { loadVectors } from "@sohopay/signer-vectors";
import { run } from "../src/cli/run.js";
import { withKeyFile } from "./key-home-fixture.js";

const doc = loadVectors();
const testKey = doc.testKeys[0];
const vector = doc.vectors.pop[0] as {
  input: { fields: { borrowerId: string; terminalId: string; jkt: string } };
};

const { borrowerId, terminalId, jkt } = vector.input.fields;
// The vector's fields also carry nonce/iat; the CLI mints those itself, so pass only the three bound fields.
const popFields = { borrowerId, terminalId, jkt };

const stored = {
  private_key_base64url: testKey.seedB64Url,
  public_jwk: testKey.publicJwk,
  jkt: vector.input.fields.jkt,
  borrower_id: vector.input.fields.borrowerId,
  terminal_id: vector.input.fields.terminalId,
};

test("pop sign via --key file mints nonce/iat and returns a pop_signature", () => {
  withKeyFile(stored, (keyPath) => {
    const stdin = JSON.stringify({ fields: popFields });
    const r = run(["pop", "sign", "--input", "-", "--key", keyPath, "--output", "json"], stdin);
    assert.equal(r.exitCode, 0, r.stderr);
    const out = JSON.parse(r.stdout);
    assert.equal(out.signer_protocol, "sohopay-signer/1");
    assert.equal(out.algorithm, "Ed25519");
    assert.ok(typeof out.pop_signature === "string" && out.pop_signature.length > 0);
    assert.ok(typeof out.nonce === "string");
    assert.ok(Number.isSafeInteger(out.iat));
  });
});

test("a caller-supplied iat is rejected by the strict input schema (MALFORMED_INPUT)", () => {
  withKeyFile(stored, (keyPath) => {
    const stdin = JSON.stringify({ fields: { ...popFields, iat: 1.5 } });
    const r = run(["pop", "sign", "--input", "-", "--key", keyPath, "--output", "json"], stdin);
    assert.equal(r.exitCode, 1);
    assert.equal(JSON.parse(r.stderr).error.code, "MALFORMED_INPUT");
  });
});

test("pop sign with no --key is MALFORMED_INPUT", () => {
  const stdin = JSON.stringify({ fields: popFields });
  const r = run(["pop", "sign", "--input", "-", "--output", "json"], stdin);
  assert.equal(r.exitCode, 1);
  assert.equal(JSON.parse(r.stderr).error.code, "MALFORMED_INPUT");
});

test("pop sign with an inline key is MALFORMED_INPUT (schema forbids top-level key)", () => {
  const stdin = JSON.stringify({ fields: popFields, key: { private_key_base64url: testKey.seedB64Url } });
  const r = run(["pop", "sign", "--input", "-", "--output", "json"], stdin);
  assert.equal(r.exitCode, 1);
  assert.equal(JSON.parse(r.stderr).error.code, "MALFORMED_INPUT");
  assert.ok(!r.stderr.includes(testKey.seedB64Url));
});
