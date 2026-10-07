import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";
import test from "node:test";
import { implementationVersion } from "../src/cli/commands.js";

test("implementationVersion returns package.json version, never the 0.0.0 fallback", () => {
  const pkg = JSON.parse(
    readFileSync(fileURLToPath(new URL("../package.json", import.meta.url)), "utf8"),
  ) as { version?: string };
  const v = implementationVersion();
  assert.equal(v, pkg.version);
  assert.notEqual(v, "0.0.0");
});
