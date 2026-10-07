// test/bundle-behavior.test.ts
import { spawnSync } from "node:child_process";
import { chmodSync, cpSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import assert from "node:assert/strict";
import test, { before } from "node:test";

import { ed25519 } from "@noble/curves/ed25519";
import { loadVectors } from "@sohopay/signer-vectors";

import { fromBase64Url } from "../src/encoding.js";
import { buildPopChallengeMessage } from "../src/pop.js";

const BUNDLE = join(process.cwd(), "dist-bundle/sohopay-signer.mjs");

before(() => {
  const r = spawnSync("npm", ["run", "bundle"], { encoding: "utf8" });
  assert.equal(r.status, 0, `${r.stdout}\n${r.stderr}`);
});

function cleanRoom(): string {
  const dir = mkdtempSync(join(tmpdir(), "signer-cleanroom-"));
  cpSync(BUNDLE, join(dir, "sohopay-signer.mjs")); // ONLY the bundle; no node_modules
  return dir;
}

test("runs capabilities with no node_modules present", () => {
  const dir = cleanRoom();
  try {
    const r = spawnSync("node", ["sohopay-signer.mjs", "capabilities", "--output", "json"], {
      cwd: dir, encoding: "utf8",
    });
    assert.equal(r.status, 0, r.stderr);
    const caps = JSON.parse(r.stdout);
    assert.equal(caps.signer_protocol, "sohopay-signer/1");
    assert.equal(caps.implementation, "@sohopay/agent-signer");
    const pkg = JSON.parse(readFileSync(join(process.cwd(), "package.json"), "utf8"));
    assert.equal(caps.implementation_version, pkg.version); // no 0.0.0 drift
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("verify-vectors passes offline with the real (non-zero) vector count", () => {
  const dir = cleanRoom();
  try {
    const r = spawnSync("node", ["sohopay-signer.mjs", "verify-vectors", "--output", "json"], {
      cwd: dir, encoding: "utf8",
    });
    assert.equal(r.status, 0, r.stderr);
    const s = JSON.parse(r.stdout);
    assert.ok(s.total > 0 && s.failed === 0, `unexpected summary ${r.stdout}`);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("direct exec (shebang) works", () => {
  const dir = cleanRoom();
  try {
    const r = spawnSync("./sohopay-signer.mjs", ["capabilities"], { cwd: dir, encoding: "utf8" });
    assert.equal(r.status, 0, r.stderr);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("symlink named 'sohopay-signer' on PATH resolves (SP5 route 2)", () => {
  const dir = cleanRoom();
  try {
    symlinkSync(join(dir, "sohopay-signer.mjs"), join(dir, "sohopay-signer"));
    const r = spawnSync("sohopay-signer", ["capabilities"], {
      cwd: dir, encoding: "utf8", env: { ...process.env, PATH: `${dir}:${process.env.PATH}` },
    });
    assert.equal(r.status, 0, r.stderr);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("extensionless COPY (not symlink) fails loudly, not oddly", () => {
  const dir = cleanRoom();
  try {
    cpSync(join(dir, "sohopay-signer.mjs"), join(dir, "sohopay-signer")); // real copy, no .mjs
    const r = spawnSync("node", ["sohopay-signer", "capabilities", "--output", "json"], { cwd: dir, encoding: "utf8" });
    if (r.status === 0) {
      // Node >=22.7 auto-detects ESM syntax in extensionless files (detect-module), so the copy
      // legitimately runs. Older Node rejects it (nonzero, below). Either way: never "odd" output.
      assert.equal(JSON.parse(r.stdout).signer_protocol, "sohopay-signer/1");
    } else {
      assert.ok(r.stderr.length > 0, "extensionless copy must fail loudly (stderr), not silently");
    }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("capabilities is semantically identical between source and bundle", () => {
  const src = spawnSync("node", ["--import", "tsx", "src/cli/index.ts", "capabilities", "--output", "json"], { encoding: "utf8" });
  const bnd = spawnSync("node", [BUNDLE, "capabilities", "--output", "json"], { encoding: "utf8" });
  assert.equal(src.status, 0); assert.equal(bnd.status, 0);
  assert.deepStrictEqual(JSON.parse(bnd.stdout), JSON.parse(src.stdout));
});

const doc = loadVectors();
const testKey = doc.testKeys[0];

function cleanRoomRun(args: string[], stdin: string, home?: string) {
  const dir = cleanRoom();
  // When a home is given, point the child's HOME at it so the signer resolves its
  // allowed key root there (env roots may only narrow, so --key must live under HOME).
  const env = home ? { ...process.env, HOME: home, USERPROFILE: home } : process.env;
  try {
    return spawnSync("node", ["sohopay-signer.mjs", ...args], {
      cwd: dir, encoding: "utf8", input: stdin, env,
    });
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

/** Writes a 0600 secret.json under a fresh HOME's default key root; returns { home, keyPath }. */
function keyUnderHome(stored: Record<string, unknown>): { home: string; keyPath: string } {
  const home = mkdtempSync(join(tmpdir(), "signer-key-home-"));
  const root = join(home, ".agents", "sohopay-agent-workload");
  mkdirSync(root, { recursive: true, mode: 0o700 });
  chmodSync(root, 0o700);
  const keyPath = join(root, "secret.json");
  writeFileSync(keyPath, JSON.stringify(stored), { mode: 0o600 });
  chmodSync(keyPath, 0o600);
  return { home, keyPath };
}

test("clean-room: pop sign --key <file> --input - mints nonce/iat and signs verifiably", () => {
  const vector = doc.vectors.pop[0] as {
    input: { fields: { borrowerId: string; terminalId: string; jkt: string } };
  };
  const { borrowerId, terminalId, jkt } = vector.input.fields;
  // Reference-only key input (INV-3): the private key enters via --key, never inline.
  const { home, keyPath } = keyUnderHome({
    private_key_base64url: testKey.seedB64Url,
    public_jwk: testKey.publicJwk,
    jkt,
    borrower_id: borrowerId,
    terminal_id: terminalId,
  });
  try {
    // Only the three bound fields; the CLI mints nonce/iat itself (rejects client-supplied ones).
    const stdin = JSON.stringify({ fields: { borrowerId, terminalId, jkt } });
    const r = cleanRoomRun(["pop", "sign", "--key", keyPath, "--input", "-", "--output", "json"], stdin, home);
    assert.equal(r.status, 0, r.stderr);
    const out = JSON.parse(r.stdout);
    assert.equal(out.algorithm, "Ed25519");
    assert.ok(typeof out.pop_signature === "string" && out.pop_signature.length > 0);
    assert.ok(typeof out.nonce === "string" && out.nonce.length >= 43);
    assert.ok(Number.isSafeInteger(out.iat));
    // The signature must verify under the test public key over the CLI's own minted challenge
    // — the correctness proof that replaces the (now non-deterministic) fixed-vector match.
    const message = buildPopChallengeMessage({ borrowerId, terminalId, jkt, nonce: out.nonce, iat: out.iat });
    assert.ok(
      ed25519.verify(fromBase64Url(out.pop_signature), message, fromBase64Url(testKey.publicJwk.x)),
      "pop signature must verify under the test public key",
    );
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test("clean-room: voucher sign --envelope --key <file> --input - reproduces the vector signature", () => {
  const vector = doc.vectors.voucherSignature[0] as {
    input: { voucher: Record<string, unknown>; signing?: unknown };
    expected: { signature: string };
  };
  const voucher = vector.input.voucher;
  // Reference-only key input (INV-3): the private key enters via --key, never inline.
  const { home, keyPath } = keyUnderHome({
    private_key_base64url: testKey.seedB64Url,
    public_jwk: testKey.publicJwk,
  });
  try {
    const stdin = JSON.stringify({
      voucher,
      signing: vector.input.signing,
      envelope: { x402Version: 2, paymentPayload: { payload: { voucher, signature: null } } },
      header_name: "PAYMENT-SIGNATURE",
    });
    const r = cleanRoomRun(["voucher", "sign", "--envelope", "--key", keyPath, "--input", "-", "--output", "json"], stdin, home);
    assert.equal(r.status, 0, r.stderr);
    const out = JSON.parse(r.stdout);
    assert.equal(out.payment_id, voucher.paymentId);
    assert.equal(out.signature, vector.expected.signature);
    assert.equal(out.header_name, "PAYMENT-SIGNATURE");
    assert.ok(typeof out.header_value === "string" && out.header_value.length > 0);
  } finally { rmSync(home, { recursive: true, force: true }); }
});

