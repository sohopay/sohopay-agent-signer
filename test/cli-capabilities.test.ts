import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { test } from "node:test";

import { parseArgs, UsageError } from "../src/cli/args.js";
import { run } from "../src/cli/run.js";

test("parseArgs reads a two-token command plus flags", () => {
  const p = parseArgs(["voucher", "sign", "--input", "-", "--output", "json"]);
  assert.equal(p.command, "voucher sign");
  assert.equal(p.input, "-");
  assert.equal(p.output, "json");
});

test("parseArgs defaults output to human and recognizes single-token commands", () => {
  const p = parseArgs(["capabilities"]);
  assert.equal(p.command, "capabilities");
  assert.equal(p.output, "human");
});

test("parseArgs throws UsageError on an unknown flag", () => {
  assert.throws(() => parseArgs(["capabilities", "--nope"]), UsageError);
});

test("parseArgs throws UsageError when a flag is missing its value", () => {
  assert.throws(() => parseArgs(["capabilities", "--output"]), UsageError);
});

test("capabilities (json) reports sohopay-signer/1 and the command set", () => {
  const r = run(["capabilities", "--output", "json"], "");
  assert.equal(r.exitCode, 0);
  assert.equal(r.stderr, "");
  const out = JSON.parse(r.stdout);
  assert.equal(out.signer_protocol, "sohopay-signer/1");
  assert.equal(out.implementation, "@sohopay/agent-signer");
  assert.deepEqual(out.algorithms, ["Ed25519"]);
  assert.ok(out.commands.includes("voucher sign"));
  assert.ok(out.commands.includes("verify-vectors"));
  assert.match(out.implementation_version, /^\d+\.\d+\.\d+/);
});

test("an unknown command is a usage error: exit 2, plain stderr, no JSON envelope", () => {
  const r = run(["frobnicate"], "");
  assert.equal(r.exitCode, 2);
  assert.equal(r.stdout, "");
  assert.ok(r.stderr.length > 0);
  assert.doesNotMatch(r.stderr, /"error"/);
});

test("the real bin pipes capabilities over stdio (subprocess smoke)", () => {
  const r = spawnSync("node", ["--import", "tsx", "src/cli/index.ts", "capabilities", "--output", "json"], {
    input: "",
    encoding: "utf8",
    cwd: process.cwd(),
  });
  assert.equal(r.status, 0);
  assert.equal(JSON.parse(r.stdout).signer_protocol, "sohopay-signer/1");
});
