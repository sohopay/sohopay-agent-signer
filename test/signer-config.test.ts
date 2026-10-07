// test/signer-config.test.ts
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import assert from "node:assert/strict";
import test from "node:test";
import { resolveKeyRoots } from "../src/cli/signer-config.js";

function home(): string { return mkdtempSync(join(tmpdir(), "sc-home-")); }

test("default root is the compiled ~/.agents/sohopay-agent-workload", () => {
  const h = home();
  try {
    const roots = resolveKeyRoots({ homeDir: h, env: {} });
    assert.ok(roots.some((r) => r.endsWith("/.agents/sohopay-agent-workload")));
  } finally { rmSync(h, { recursive: true, force: true }); }
});

test("config file adds a root (0600, owner)", () => {
  const h = home();
  try {
    mkdirSync(join(h, ".config", "sohopay-signer"), { recursive: true });
    chmodSync(join(h, ".config", "sohopay-signer"), 0o700); // umask-independent
    const extra = join(h, "custom-store"); mkdirSync(extra);
    const cfg = join(h, ".config", "sohopay-signer", "config.json");
    writeFileSync(cfg, JSON.stringify({ keyRoots: [extra] }), { mode: 0o600 });
    chmodSync(cfg, 0o600);
    const roots = resolveKeyRoots({ homeDir: h, env: {} });
    assert.ok(roots.some((r) => r.endsWith("/custom-store")));
  } finally { rmSync(h, { recursive: true, force: true }); }
});

test("env narrows to the intersection, never widens", () => {
  const h = home();
  try {
    const def = join(h, ".agents", "sohopay-agent-workload"); mkdirSync(def, { recursive: true });
    const narrowed = resolveKeyRoots({ homeDir: h, env: { SOHOPAY_SIGNER_KEY_ROOTS: def } });
    assert.ok(narrowed.every((r) => r.endsWith("/.agents/sohopay-agent-workload")));
    assert.throws(
      () => resolveKeyRoots({ homeDir: h, env: { SOHOPAY_SIGNER_KEY_ROOTS: "/tmp" } }),
      (e: { code?: string }) => e.code === "KEY_PATH_INVALID",
    );
  } finally { rmSync(h, { recursive: true, force: true }); }
});

test("a group/world-readable config file is refused", () => {
  const h = home();
  try {
    mkdirSync(join(h, ".config", "sohopay-signer"), { recursive: true });
    chmodSync(join(h, ".config", "sohopay-signer"), 0o700); // umask-independent
    const cfg = join(h, ".config", "sohopay-signer", "config.json");
    writeFileSync(cfg, JSON.stringify({ keyRoots: [] }), { mode: 0o644 });
    chmodSync(cfg, 0o644);
    assert.throws(
      () => resolveKeyRoots({ homeDir: h, env: {} }),
      (e: { code?: string }) => e.code === "KEY_PATH_INVALID",
    );
  } finally { rmSync(h, { recursive: true, force: true }); }
});
