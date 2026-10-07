import assert from "node:assert/strict";
import test from "node:test";
import { SignerError, type SignerErrorCode } from "../src/errors.js";

test("new SP5-complete error codes construct and carry their code", () => {
  const codes: SignerErrorCode[] = [
    "KEY_PATH_INVALID", "CROSS_BORROWER_KEY", "TERMINAL_MISMATCH",
    "KEY_INTEGRITY_FAILED", "KEY_PERSIST_FAILED", "INLINE_KEY_REJECTED", "MALFORMED_INPUT",
  ];
  for (const c of codes) {
    assert.equal(new SignerError(c, "msg").code, c);
  }
});
