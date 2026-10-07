import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import assert from "node:assert/strict";
import test from "node:test";
import { run } from "../src/cli/run.js";
import { generateWorkloadKey } from "../src/keys.js";
import { withKeyFile } from "./key-home-fixture.js";

test("voucher sign --key rejects a wrong-leaf path but validates the documented secret.json", () => {
  const kp = generateWorkloadKey();
  const content = {
    private_key_base64url: kp.privateKeyBase64Url,
    public_jwk: kp.publicJwk,
    jkt: kp.jkt,
    terminal_id: "t",
    borrower_id: "b",
  };
  withKeyFile(content, (good) => {
    const wrong = join(dirname(good), "key.json");
    writeFileSync(wrong, "{}", { mode: 0o600 });
    chmodSync(wrong, 0o600);
    const voucher = JSON.stringify({ voucher: { paymentId: "0x", agentKeyJkt: kp.jkt } });
    const bad = run(["voucher", "sign", "--key", wrong, "--input", "-", "--output", "json"], voucher);
    assert.equal(bad.exitCode, 1);
    assert.match(bad.stderr, /KEY_PATH_INVALID/);
    const ok = run(["voucher", "sign", "--key", good, "--input", "-", "--output", "json"], voucher);
    // The path validates; any later error concerns voucher shape.
    assert.doesNotMatch(ok.stderr, /KEY_PATH_INVALID/);
  });
});

test("key generate end-to-end emits public material only and never the private key", () => {
  const home = mkdtempSync(join(tmpdir(), "sohopay-keygen-home-"));
  const root = join(home, ".agents", "sohopay-agent-workload");
  mkdirSync(root, { recursive: true, mode: 0o700 });
  chmodSync(root, 0o700);
  const prevHome = process.env.HOME;
  const prevProfile = process.env.USERPROFILE;
  const prevRoots = process.env.SOHOPAY_SIGNER_KEY_ROOTS;
  process.env.HOME = home;
  process.env.USERPROFILE = home;
  delete process.env.SOHOPAY_SIGNER_KEY_ROOTS;
  try {
    const r = run(
      ["key", "generate", "--out", join(root, "secret.json"), "--input", "-", "--output", "json"],
      JSON.stringify({ borrower_id: "b1", terminal_id: "t1" }),
    );
    assert.equal(r.exitCode, 0, r.stderr);
    const out = JSON.parse(r.stdout) as Record<string, any>;
    assert.equal(out.created, true);
    assert.ok(out.public_jwk && typeof out.public_jwk.x === "string");
    assert.equal(out.borrower_id, "b1");
    assert.equal(out.terminal_id, "t1");
    assert.ok(!r.stdout.includes("private_key_base64url"), "stdout must carry no private key material");
  } finally {
    const restore = (k: string, v: string | undefined) => {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    };
    restore("HOME", prevHome);
    restore("USERPROFILE", prevProfile);
    restore("SOHOPAY_SIGNER_KEY_ROOTS", prevRoots);
    rmSync(home, { recursive: true, force: true });
  }
});
