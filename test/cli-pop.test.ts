import assert from "node:assert/strict";
import { test } from "node:test";

import { loadVectors } from "@sohopay/signer-vectors";
import { run } from "../src/cli/run.js";

const doc = loadVectors();
const testKey = doc.testKeys[0];
const vector = doc.vectors.pop[0] as {
  input: { fields: Record<string, unknown> };
  expected: { popSignature: string };
};

test("pop sign reproduces the vector pop_signature", () => {
  const stdin = JSON.stringify({
    fields: vector.input.fields,
    key: { private_key_base64url: testKey.seedB64Url },
  });
  const r = run(["pop", "sign", "--input", "-", "--output", "json"], stdin);
  assert.equal(r.exitCode, 0, r.stderr);
  const out = JSON.parse(r.stdout);
  assert.equal(out.signer_protocol, "sohopay-signer/1");
  assert.equal(out.algorithm, "Ed25519");
  assert.equal(out.pop_signature, vector.expected.popSignature);
});

test("a non-integer iat fails POP_IAT_NOT_INTEGER", () => {
  const fields = { ...vector.input.fields, iat: 1.5 };
  const stdin = JSON.stringify({ fields, key: { private_key_base64url: testKey.seedB64Url } });
  const r = run(["pop", "sign", "--input", "-", "--output", "json"], stdin);
  assert.equal(r.exitCode, 1);
  assert.equal(JSON.parse(r.stderr).error.code, "POP_IAT_NOT_INTEGER");
});

test("pop sign with no key is MALFORMED_ENVELOPE", () => {
  const stdin = JSON.stringify({ fields: vector.input.fields });
  const r = run(["pop", "sign", "--input", "-", "--output", "json"], stdin);
  assert.equal(r.exitCode, 1);
  assert.equal(JSON.parse(r.stderr).error.code, "MALFORMED_ENVELOPE");
});
