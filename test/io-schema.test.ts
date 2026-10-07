// test/io-schema.test.ts
import assert from "node:assert/strict";
import test from "node:test";
import { assertInputSchema, assertOutputSchema } from "../src/cli/io-schema.js";

test("pop sign input rejects a client-supplied nonce", () => {
  assert.throws(
    () => assertInputSchema("pop sign", { fields: { borrowerId: "b", terminalId: "t", jkt: "j", nonce: "x" } }),
    (e: { code?: string }) => e.code === "MALFORMED_INPUT",
  );
  assert.doesNotThrow(() => assertInputSchema("pop sign", { fields: { borrowerId: "b", terminalId: "t", jkt: "j" } }));
});

test("key generate input rejects extra keys", () => {
  assert.throws(
    () => assertInputSchema("key generate", { borrower_id: "b", terminal_id: "t", extra: 1 }),
    (e: { code?: string }) => e.code === "MALFORMED_INPUT",
  );
});

test("output schema rejects a leaked field", () => {
  assert.throws(() => assertOutputSchema("key generate",
    { public_jwk: {}, jkt: "j", borrower_id: "b", terminal_id: "t", created: true, private_key_base64url: "LEAK" }));
});

test("assertOutputSchema rejects public_jwk with private d field", () => {
  assert.throws(
    () => assertOutputSchema("key generate",
      { public_jwk: { kty: "OKP", crv: "Ed25519", x: "AAA", d: "PRIVATE" }, jkt: "j", borrower_id: "b", terminal_id: "t", created: true }),
  );
  assert.doesNotThrow(() => assertOutputSchema("key generate",
    { public_jwk: { kty: "OKP", crv: "Ed25519", x: "AAA" }, jkt: "j", borrower_id: "b", terminal_id: "t", created: true }));
});

test("assertInputSchema rejects array at top level", () => {
  assert.throws(
    () => assertInputSchema("key generate", []),
    (e: { code?: string }) => e.code === "MALFORMED_INPUT",
  );
});

test("assertInputSchema rejects array in fields", () => {
  assert.throws(
    () => assertInputSchema("pop sign", { fields: [] }),
    (e: { code?: string }) => e.code === "MALFORMED_INPUT",
  );
});

test("pop sign input rejects client iat field", () => {
  assert.throws(
    () => assertInputSchema("pop sign", { fields: { borrowerId: "b", terminalId: "t", jkt: "j", iat: 1 } }),
    (e: { code?: string }) => e.code === "MALFORMED_INPUT",
  );
});

test("assertOutputSchema pop sign valid passes", () => {
  assert.doesNotThrow(() => assertOutputSchema("pop sign",
    { signer_protocol: "sohopay-signer/1", implementation: "x", implementation_version: "0", pop_signature: "s", nonce: "n", iat: 1, algorithm: "Ed25519" }));
});

test("assertOutputSchema pop sign with extra field throws", () => {
  assert.throws(() => assertOutputSchema("pop sign",
    { signer_protocol: "sohopay-signer/1", implementation: "x", implementation_version: "0", pop_signature: "s", nonce: "n", iat: 1, algorithm: "Ed25519", private_key_base64url: "LEAK" }));
});

test("assertInputSchema unknown command is no-op", () => {
  assert.doesNotThrow(() => assertInputSchema("voucher sign", { anything: 1 }));
});
