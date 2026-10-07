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

function defRoot(h: string): string {
  const def = join(h, ".agents", "sohopay-agent-workload");
  mkdirSync(def, { recursive: true });
  return def;
}
const isInvalid = (e: { code?: string }): boolean => e.code === "KEY_PATH_INVALID";

test("a sibling-prefix path is not treated as inside the default root", () => {
  const h = home();
  try {
    const def = defRoot(h);
    mkdirSync(`${def}-evil`);
    assert.throws(
      () => resolveKeyRoots({ homeDir: h, env: { SOHOPAY_SIGNER_KEY_ROOTS: `${def}-evil` } }),
      isInvalid,
    );
  } finally { rmSync(h, { recursive: true, force: true }); }
});

test("a descendant directory under a configured root is accepted", () => {
  const h = home();
  try {
    const def = defRoot(h);
    mkdirSync(join(def, "sub"));
    const roots = resolveKeyRoots({ homeDir: h, env: { SOHOPAY_SIGNER_KEY_ROOTS: join(def, "sub") } });
    assert.equal(roots.length, 1);
    assert.ok(roots[0]!.endsWith("/.agents/sohopay-agent-workload/sub"));
  } finally { rmSync(h, { recursive: true, force: true }); }
});

test("an env entry containing .. is rejected", () => {
  const h = home();
  try {
    const def = defRoot(h);
    assert.throws(
      () => resolveKeyRoots({ homeDir: h, env: { SOHOPAY_SIGNER_KEY_ROOTS: `${def}/../escape` } }),
      isInvalid,
    );
  } finally { rmSync(h, { recursive: true, force: true }); }
});

test("a relative env entry is rejected", () => {
  const h = home();
  try {
    defRoot(h);
    assert.throws(
      () => resolveKeyRoots({ homeDir: h, env: { SOHOPAY_SIGNER_KEY_ROOTS: "relative/x" } }),
      isInvalid,
    );
  } finally { rmSync(h, { recursive: true, force: true }); }
});

test("config keyRoots with a relative or .. entry is rejected", () => {
  for (const bad of ["relative/x", "/tmp/../etc"]) {
    const h = home();
    try {
      const dir = join(h, ".config", "sohopay-signer");
      mkdirSync(dir, { recursive: true });
      chmodSync(dir, 0o700);
      const cfg = join(dir, "config.json");
      writeFileSync(cfg, JSON.stringify({ keyRoots: [bad] }), { mode: 0o600 });
      chmodSync(cfg, 0o600);
      assert.throws(() => resolveKeyRoots({ homeDir: h, env: {} }), isInvalid);
    } finally { rmSync(h, { recursive: true, force: true }); }
  }
});

test("a non-object config JSON is rejected, not a raw TypeError", () => {
  for (const body of ["null", "5", "\"s\"", "[]"]) {
    const h = home();
    try {
      const dir = join(h, ".config", "sohopay-signer");
      mkdirSync(dir, { recursive: true });
      chmodSync(dir, 0o700);
      const cfg = join(dir, "config.json");
      writeFileSync(cfg, body, { mode: 0o600 });
      chmodSync(cfg, 0o600);
      assert.throws(() => resolveKeyRoots({ homeDir: h, env: {} }), isInvalid);
    } finally { rmSync(h, { recursive: true, force: true }); }
  }
});

test("a config whose parent dir is not 0700 is rejected", () => {
  const h = home();
  try {
    const dir = join(h, ".config", "sohopay-signer");
    mkdirSync(dir, { recursive: true });
    chmodSync(dir, 0o755);
    const cfg = join(dir, "config.json");
    writeFileSync(cfg, JSON.stringify({ keyRoots: [] }), { mode: 0o600 });
    chmodSync(cfg, 0o600);
    assert.throws(
      () => resolveKeyRoots({ homeDir: h, env: {} }),
      (e: { code?: string; message?: string }) => isInvalid(e) && /parent dir/.test(e.message ?? ""),
    );
  } finally { rmSync(h, { recursive: true, force: true }); }
});
