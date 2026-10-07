import { mkdtempSync, mkdirSync, readFileSync, statSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import assert from "node:assert/strict";
import test from "node:test";
import { keyGenerateResult } from "../src/cli/key-generate.js";

function env() {
  const home = mkdtempSync(join(tmpdir(), "kg-home-"));
  const root = join(home, ".agents", "sohopay-agent-workload");
  mkdirSync(root, { recursive: true, mode: 0o700 });
  return { home, out: join(root, "secret.json"), opts: { homeDir: home, env: {} as NodeJS.ProcessEnv } };
}

test("absent → generates, writes 0600, returns created:true and only public material", () => {
  const { home, out, opts } = env();
  try {
    const r = keyGenerateResult({ borrower_id: "b1", terminal_id: "t1" }, out, opts) as Record<string, unknown>;
    assert.equal(r.created, true);
    assert.equal(r.borrower_id, "b1");
    assert.ok((r.public_jwk as { x?: string }).x);
    assert.equal((r as { private_key_base64url?: unknown }).private_key_base64url, undefined);
    assert.equal(statSync(out).mode & 0o777, 0o600);
    assert.ok(JSON.parse(readFileSync(out, "utf8")).private_key_base64url);
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test("same borrower + same terminal → created:false, same jkt, byte-identical file", () => {
  const { home, out, opts } = env();
  try {
    const first = keyGenerateResult({ borrower_id: "b1", terminal_id: "t1" }, out, opts) as Record<string, unknown>;
    const before = readFileSync(out, "utf8");
    const second = keyGenerateResult({ borrower_id: "b1", terminal_id: "t1" }, out, opts) as Record<string, unknown>;
    assert.equal(second.created, false);
    assert.equal(second.jkt, first.jkt);
    assert.equal(readFileSync(out, "utf8"), before);
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test("same borrower + different terminal → TERMINAL_MISMATCH", () => {
  const { home, out, opts } = env();
  try {
    keyGenerateResult({ borrower_id: "b1", terminal_id: "t1" }, out, opts);
    assert.throws(() => keyGenerateResult({ borrower_id: "b1", terminal_id: "t2" }, out, opts),
      (e: { code?: string }) => e.code === "TERMINAL_MISMATCH");
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test("different borrower at the same path → CROSS_BORROWER_KEY", () => {
  const { home, out, opts } = env();
  try {
    keyGenerateResult({ borrower_id: "b1", terminal_id: "t1" }, out, opts);
    assert.throws(() => keyGenerateResult({ borrower_id: "b2", terminal_id: "t1" }, out, opts),
      (e: { code?: string }) => e.code === "CROSS_BORROWER_KEY");
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test("stored public ≠ derived → KEY_INTEGRITY_FAILED", () => {
  const { home, out, opts } = env();
  try {
    keyGenerateResult({ borrower_id: "b1", terminal_id: "t1" }, out, opts);
    const raw = JSON.parse(readFileSync(out, "utf8"));
    raw.public_jwk.x = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    writeFileSync(out, JSON.stringify(raw), { mode: 0o600 });
    assert.throws(() => keyGenerateResult({ borrower_id: "b1", terminal_id: "t1" }, out, opts),
      (e: { code?: string }) => e.code === "KEY_INTEGRITY_FAILED");
  } finally { rmSync(home, { recursive: true, force: true }); }
});
