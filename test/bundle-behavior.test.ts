// test/bundle-behavior.test.ts
import { spawnSync } from "node:child_process";
import { cpSync, mkdtempSync, rmSync, symlinkSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import assert from "node:assert/strict";
import test, { before } from "node:test";

import { loadVectors } from "@sohopay/signer-vectors";

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

function cleanRoomRun(args: string[], stdin: string) {
  const dir = cleanRoom();
  try {
    return spawnSync("node", ["sohopay-signer.mjs", ...args], {
      cwd: dir, encoding: "utf8", input: stdin,
    });
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

test("clean-room: pop sign --input - reproduces the vector pop_signature", () => {
  const vector = doc.vectors.pop[0] as {
    input: { fields: Record<string, unknown> };
    expected: { popSignature: string };
  };
  const stdin = JSON.stringify({
    fields: vector.input.fields,
    key: { private_key_base64url: testKey.seedB64Url },
  });
  const r = cleanRoomRun(["pop", "sign", "--input", "-", "--output", "json"], stdin);
  assert.equal(r.status, 0, r.stderr);
  const out = JSON.parse(r.stdout);
  assert.equal(out.algorithm, "Ed25519");
  assert.equal(out.pop_signature, vector.expected.popSignature);
});

test("clean-room: voucher sign --envelope --input - reproduces the vector signature", () => {
  const vector = doc.vectors.voucherSignature[0] as {
    input: { voucher: Record<string, unknown>; signing?: unknown };
    expected: { signature: string };
  };
  const voucher = vector.input.voucher;
  const stdin = JSON.stringify({
    voucher,
    signing: vector.input.signing,
    envelope: { x402Version: 2, paymentPayload: { payload: { voucher, signature: null } } },
    header_name: "PAYMENT-SIGNATURE",
    key: { private_key_base64url: testKey.seedB64Url, public_jwk: testKey.publicJwk },
  });
  const r = cleanRoomRun(["voucher", "sign", "--envelope", "--input", "-", "--output", "json"], stdin);
  assert.equal(r.status, 0, r.stderr);
  const out = JSON.parse(r.stdout);
  assert.equal(out.payment_id, voucher.paymentId);
  assert.equal(out.signature, vector.expected.signature);
  assert.equal(out.header_name, "PAYMENT-SIGNATURE");
  assert.ok(typeof out.header_value === "string" && out.header_value.length > 0);
});

