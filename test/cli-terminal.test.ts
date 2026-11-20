import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readdirSync, rmSync, statSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { run } from "../src/cli/run.js";

const ENV_KEYS = ["HOME", "SOHO_DATA_DIR", "SOHO_TERMINAL_ID", "SOHOPAY_SIGNER_KEY_ROOTS"] as const;

/** Fresh HOME with no key root and no data dir, so both are created by the code under test. */
function withHome(fn: (home: string) => void): void {
  const home = mkdtempSync(join(tmpdir(), "sohopay-terminal-"));
  const prev = Object.fromEntries(ENV_KEYS.map((k) => [k, process.env[k]]));
  for (const k of ENV_KEYS) delete process.env[k];
  process.env.HOME = home;
  try {
    fn(home);
  } finally {
    for (const k of ENV_KEYS) {
      if (prev[k] === undefined) delete process.env[k];
      else process.env[k] = prev[k];
    }
    rmSync(home, { recursive: true, force: true });
  }
}

const ok = (argv: string[], stdin = "") => {
  const r = run([...argv, "--output", "json"], stdin);
  assert.equal(r.exitCode, 0, r.stderr);
  return JSON.parse(r.stdout) as Record<string, unknown>;
};
const errCode = (argv: string[], stdin = "") => {
  const r = run([...argv, "--output", "json"], stdin);
  assert.equal(r.exitCode, 1, r.stdout);
  return (JSON.parse(r.stderr) as { error: { code: string } }).error.code;
};
const gen = (terminal: string, terminalId = terminal) => ({
  argv: ["key", "generate", "--terminal", terminal, "--input", "-"],
  stdin: JSON.stringify({ borrower_id: "b-1", terminal_id: terminalId }),
});

test("terminal id: stable per harness, distinct across harnesses, 0600 file in a 0700 dir", () => {
  withHome((home) => {
    process.env.SOHO_TERMINAL_ID = "host-wide:override"; // must not collapse harnesses
    const a1 = ok(["terminal", "id", "--harness", "claude-code"]).terminal_id as string;
    const a2 = ok(["terminal", "id", "--harness", "claude-code"]).terminal_id as string;
    const b = ok(["terminal", "id", "--harness", "codex"]).terminal_id as string;
    assert.match(a1, /^claude-code:[0-9a-f-]{36}$/);
    assert.equal(a1, a2);
    assert.match(b, /^codex:/);
    assert.notEqual(a1, b);
    assert.equal(statSync(join(home, ".sohopay", "claude-code")).mode & 0o777, 0o700);
    assert.equal(statSync(join(home, ".sohopay", "claude-code", "terminal_id")).mode & 0o777, 0o600);
    assert.equal(readdirSync(home).includes(".agents"), false); // id never written under ~/.agents
  });
});

test("terminal id: a harness outside the fixed list is refused", () => {
  withHome(() => {
    for (const h of ["vim", "..", "../claude-code", "claude-code/x", ""]) {
      assert.equal(errCode(["terminal", "id", "--harness", h]), "INVALID_HARNESS", h);
    }
    assert.equal(run(["terminal", "id"], "").exitCode, 2);
  });
});

test("--terminal: two terminals get two digest-named key files; rerun is created:false", () => {
  withHome((home) => {
    const t1 = "claude-code:11111111-1111-4111-8111-111111111111";
    const t2 = "codex:22222222-2222-4222-8222-222222222222";
    const k1 = gen(t1);
    const first = ok(k1.argv, k1.stdin);
    assert.equal(first.created, true);
    const again = ok(k1.argv, k1.stdin);
    assert.equal(again.created, false);
    assert.equal(again.jkt, first.jkt);
    const k2 = gen(t2);
    const second = ok(k2.argv, k2.stdin);
    assert.notEqual(second.jkt, first.jkt);

    const root = join(home, ".agents", "sohopay-agent-workload");
    const dirs = readdirSync(root).sort();
    assert.equal(dirs.length, 2);
    for (const d of dirs) {
      assert.match(d, /^[0-9a-f]{64}$/); // no ':', '@' or raw id on disk
      assert.equal(statSync(join(root, d)).mode & 0o777, 0o700);
      assert.equal(statSync(join(root, d, "secret.json")).mode & 0o777, 0o600);
    }

    // PoP with the right terminal signs; a cross-terminal claim is TERMINAL_MISMATCH.
    const pop = (terminal: string, terminalId: string) => [
      ["pop", "sign", "--terminal", terminal, "--input", "-"],
      JSON.stringify({ fields: { borrowerId: "b-1", terminalId, jkt: first.jkt } }),
    ] as const;
    const [okArgv, okIn] = pop(t1, t1);
    assert.ok(ok([...okArgv], okIn).pop_signature);
    const [xArgv, xIn] = pop(t1, t2);
    assert.equal(errCode([...xArgv], xIn), "TERMINAL_MISMATCH");
  });
});

test("--terminal: input terminal_id must match the flag", () => {
  withHome(() => {
    const k = gen("claude-code:a", "codex:b");
    assert.equal(errCode(k.argv, k.stdin), "TERMINAL_MISMATCH");
  });
});

test("--terminal: a '..' id and a symlinked digest folder are rejected", () => {
  withHome((home) => {
    const dotdot = gen("..");
    assert.equal(errCode(dotdot.argv, dotdot.stdin), "KEY_PATH_INVALID");

    const t = "cursor:33333333-3333-4333-8333-333333333333";
    const k = gen(t);
    ok(k.argv, k.stdin);
    const root = join(home, ".agents", "sohopay-agent-workload");
    const [digest] = readdirSync(root);
    const elsewhere = join(home, "elsewhere");
    mkdirSync(elsewhere, { mode: 0o700 });
    rmSync(join(root, digest!), { recursive: true });
    symlinkSync(elsewhere, join(root, digest!));
    assert.equal(errCode(k.argv, k.stdin), "KEY_PATH_INVALID");
  });
});

test("--terminal is exclusive with --key/--out and limited to key/pop/voucher commands", () => {
  withHome(() => {
    assert.equal(run(["pop", "sign", "--terminal", "a:b", "--key", "x/secret.json", "--input", "-"], "{}").exitCode, 2);
    assert.equal(run(["key", "generate", "--terminal", "a:b", "--out", "x/secret.json", "--input", "-"], "{}").exitCode, 2);
    assert.equal(run(["key", "jkt", "--terminal", "a:b", "--input", "-"], "{}").exitCode, 2);
    assert.equal(run(["capabilities", "--harness", "codex"], "").exitCode, 2);
  });
});

test("capabilities advertises workload-terminal/1", () => {
  const caps = ok(["capabilities"]);
  assert.ok((caps.commands as string[]).includes("terminal id"));
  assert.equal((caps.command_contracts as Record<string, string>)["terminal id"], "workload-terminal/1");
});
