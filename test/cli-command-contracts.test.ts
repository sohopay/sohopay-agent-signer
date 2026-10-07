// test/cli-command-contracts.test.ts
import assert from "node:assert/strict";
import test from "node:test";
import { capabilitiesResult } from "../src/cli/commands.js";
import { parseArgs } from "../src/cli/args.js";

test("capabilities advertises the workload-keygen/1 and pop-sign/1 contracts", () => {
  const caps = capabilitiesResult() as { commands: string[]; command_contracts: Record<string, string> };
  assert.ok(caps.commands.includes("key generate"));
  assert.equal(caps.command_contracts["key generate"], "workload-keygen/1");
  assert.equal(caps.command_contracts["pop sign"], "pop-sign/1");
});

test("args parses `key generate --out <path>`", () => {
  const parsed = parseArgs(["key", "generate", "--out", "/x/secret.json", "--input", "-"]);
  assert.equal(parsed.command, "key generate");
  assert.equal(parsed.out, "/x/secret.json");
});
