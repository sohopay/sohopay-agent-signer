// test/key-path.test.ts
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, chmodSync, statSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import assert from "node:assert/strict";
import test from "node:test";
import { validateKeyPath } from "../src/cli/key-path.js";

function fixture(): { home: string; root: string } {
  const home = mkdtempSync(join(tmpdir(), "kp-home-"));
  const root = join(home, ".agents", "sohopay-agent-workload");
  mkdirSync(root, { recursive: true, mode: 0o700 });
  return { home, root };
}
const code = (e: { code?: string }) => e.code === "KEY_PATH_INVALID";

test("ensure mode accepts an absent secret.json under the root", () => {
  const { home, root } = fixture();
  try {
    const p = validateKeyPath(join(root, "secret.json"), "ensure", { homeDir: home, env: {} });
    assert.ok(p.endsWith("/secret.json"));
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test("ensure mode creates an absent allowed root at 0700 (fresh machine)", () => {
  const home = mkdtempSync(join(tmpdir(), "kp-fresh-"));
  try {
    const root = join(home, ".agents", "sohopay-agent-workload"); // intentionally NOT created
    const p = validateKeyPath(join(root, "secret.json"), "ensure", { homeDir: home, env: {} });
    assert.ok(p.endsWith("/sohopay-agent-workload/secret.json"));
    const st = statSync(root);
    assert.ok(st.isDirectory());
    assert.equal(st.mode & 0o077, 0); // owner-only, never group/world accessible
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test("ensure mode refuses an existing file (never overwrite)", () => {
  const { home, root } = fixture();
  try {
    const p = join(root, "secret.json");
    writeFileSync(p, "{}", { mode: 0o600 }); chmodSync(p, 0o600);
    assert.throws(() => validateKeyPath(p, "ensure", { homeDir: home, env: {} }), code);
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test("read mode refuses a loosened (0644) file", () => {
  const { home, root } = fixture();
  try {
    const p = join(root, "secret.json");
    writeFileSync(p, "{}", { mode: 0o644 }); chmodSync(p, 0o644);
    assert.throws(() => validateKeyPath(p, "read", { homeDir: home, env: {} }), code);
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test("a wrong leaf basename is refused", () => {
  const { home, root } = fixture();
  try {
    assert.throws(() => validateKeyPath(join(root, "key.json"), "ensure", { homeDir: home, env: {} }), code);
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test("a symlinked component below the root is refused", () => {
  const { home, root } = fixture();
  try {
    const realDir = join(home, "elsewhere"); mkdirSync(realDir, { mode: 0o700 });
    const linked = join(root, "sub"); symlinkSync(realDir, linked);
    assert.throws(() => validateKeyPath(join(linked, "secret.json"), "ensure", { homeDir: home, env: {} }), code);
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test("a path outside every root is refused", () => {
  const { home } = fixture();
  try {
    const out = mkdtempSync(join(tmpdir(), "kp-out-"));
    try {
      assert.throws(() => validateKeyPath(join(out, "secret.json"), "ensure", { homeDir: home, env: {} }), code);
    } finally { rmSync(out, { recursive: true, force: true }); }
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test("INV-rootenv: env root outside configured roots fails KEY_PATH_INVALID", () => {
  const { home, root } = fixture();
  try {
    assert.throws(
      () => validateKeyPath(join(root, "secret.json"), "ensure",
        { homeDir: home, env: { SOHOPAY_SIGNER_KEY_ROOTS: "/tmp" } }), code);
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test("a dangling symlink at secret.json is refused in ensure and read mode", () => {
  const { home, root } = fixture();
  try {
    const p = join(root, "secret.json");
    symlinkSync(join(home, "nonexistent", "evil", "secret.json"), p);
    assert.throws(() => validateKeyPath(p, "ensure", { homeDir: home, env: {} }), code);
    assert.throws(() => validateKeyPath(p, "read", { homeDir: home, env: {} }), code);
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test("a missing parent directory is KEY_PATH_INVALID, not a raw ENOENT", () => {
  const { home, root } = fixture();
  try {
    assert.throws(() => validateKeyPath(join(root, "nodir", "secret.json"), "ensure", { homeDir: home, env: {} }), code);
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test("`..` is normalised lexically: root/x/../secret.json resolves to the in-root path", () => {
  const { home, root } = fixture();
  try {
    const p = validateKeyPath(join(root, "x", "..", "secret.json"), "ensure", { homeDir: home, env: {} });
    assert.ok(p.endsWith("/sohopay-agent-workload/secret.json"));
    assert.ok(!p.includes(".."));
    // an escaping `..` normalises outside the root and is refused
    assert.throws(() => validateKeyPath(join(root, "..", "secret.json"), "ensure", { homeDir: home, env: {} }), code);
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test("read mode accepts an existing 0600 owner file and returns the canonical path", () => {
  const { home, root } = fixture();
  try {
    const p = join(root, "secret.json");
    writeFileSync(p, "{}", { mode: 0o600 }); chmodSync(p, 0o600);
    const out = validateKeyPath(p, "read", { homeDir: home, env: {} });
    assert.ok(out.endsWith("/.agents/sohopay-agent-workload/secret.json"));
  } finally { rmSync(home, { recursive: true, force: true }); }
});
