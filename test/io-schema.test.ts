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
