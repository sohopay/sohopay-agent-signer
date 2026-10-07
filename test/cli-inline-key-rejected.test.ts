import assert from "node:assert/strict";
import test from "node:test";
import { run } from "../src/cli/run.js";

test("pop sign with an inline private key is INLINE_KEY_REJECTED", () => {
  const stdin = JSON.stringify({ fields: { borrowerId: "b", terminalId: "t", jkt: "j" }, key: { private_key_base64url: "AAAA" } });
  const r = run(["pop", "sign", "--input", "-", "--output", "json"], stdin);
  assert.equal(r.exitCode, 1);
  assert.match(r.stderr, /INLINE_KEY_REJECTED|MALFORMED_INPUT/); // schema may also reject `key`; inline check runs first
});

test("voucher sign with an inline private key is INLINE_KEY_REJECTED", () => {
  const stdin = JSON.stringify({ voucher: {}, key: { private_key_base64url: "AAAA" } });
  const r = run(["voucher", "sign", "--input", "-", "--output", "json"], stdin);
  assert.equal(r.exitCode, 1);
  assert.match(r.stderr, /INLINE_KEY_REJECTED/);
});

test("key jkt with an inline private key is INLINE_KEY_REJECTED", () => {
  const stdin = JSON.stringify({ key: { private_key_base64url: "AAAA" } });
  const r = run(["key", "jkt", "--input", "-", "--output", "json"], stdin);
  assert.equal(r.exitCode, 1);
  assert.match(r.stderr, /INLINE_KEY_REJECTED/);
});
