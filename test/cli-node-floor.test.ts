import assert from "node:assert/strict";
import test from "node:test";
import { assertNodeFloor, MIN_NODE_MAJOR } from "../src/cli/node-floor.js";

test("assertNodeFloor rejects below the floor with a coded error", () => {
  assert.equal(MIN_NODE_MAJOR, 18);
  assert.throws(() => assertNodeFloor("16.20.2"), { code: "NODE_VERSION_UNSUPPORTED" });
  assert.throws(() => assertNodeFloor("not-a-version"));
});

test("assertNodeFloor accepts the floor and above", () => {
  assert.doesNotThrow(() => assertNodeFloor("18.0.0"));
  assert.doesNotThrow(() => assertNodeFloor("20.11.1"));
});
