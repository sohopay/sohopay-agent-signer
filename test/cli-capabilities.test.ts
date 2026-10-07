import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { test } from "node:test";

import { needsStdin, parseArgs, UsageError } from "../src/cli/args.js";
import { run } from "../src/cli/run.js";
import { cliInvocation } from "./helpers/cli-bin.js";

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

test("parseArgs accepts the --flag=value form", () => {
  const p = parseArgs(["payment-id", "--input=-", "--output=json"]);
  assert.equal(p.command, "payment-id");
  assert.equal(p.input, "-");
  assert.equal(p.output, "json");
});

test("parseArgs rejects an unexpected extra positional", () => {
  assert.throws(() => parseArgs(["capabilities", "extra"]), UsageError);
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
  const { cmd, prefix } = cliInvocation();
  const r = spawnSync(cmd, [...prefix, "capabilities", "--output", "json"], {
    input: "",
    encoding: "utf8",
    cwd: process.cwd(),
  });
  assert.equal(r.status, 0);
  assert.equal(JSON.parse(r.stdout).signer_protocol, "sohopay-signer/1");
});

test("needsStdin is false for a no-input command and true when a '-' source is present", () => {
  assert.equal(needsStdin(["capabilities"]), false);
  assert.equal(needsStdin(["payment-id", "--input", "-"]), true);
  assert.equal(needsStdin(["voucher", "sign", "--key", "-"]), true);
});
