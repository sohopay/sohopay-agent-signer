import assert from "node:assert/strict";
import test from "node:test";
import { loadVectors as realLoad } from "@sohopay/signer-vectors";
// @ts-expect-error — plain .mjs shim, no types
import { loadVectors as shimLoad } from "../scripts/bundle-vectors-shim.mjs";

test("vectors shim returns byte-identical payload to the package (same IDs/count/content)", () => {
  assert.deepStrictEqual(shimLoad(), realLoad());
});
