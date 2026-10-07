import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import assert from "node:assert/strict";
import test from "node:test";
import { run } from "../src/cli/run.js";

const CANARY = "CANARY_SECRET_a1b2c3d4";
const INLINE = "INLINE_KEY_aaaaaaaaaaaaaaaa";

test("a corrupted secret.json never surfaces its contents in any command's output", () => {
  // HOME is redirected so the corrupted file sits under the DEFAULT key root and is
  // actually read (env roots can only narrow, so a temp root would fail path validation first).
  const home = mkdtempSync(join(tmpdir(), "leak-home-"));
  const prevHome = process.env.HOME;
  const prevProfile = process.env.USERPROFILE;
  const prevRoots = process.env.SOHOPAY_SIGNER_KEY_ROOTS;
  process.env.HOME = home;
  process.env.USERPROFILE = home;
  delete process.env.SOHOPAY_SIGNER_KEY_ROOTS;
  try {
    const root = join(home, ".agents", "sohopay-agent-workload");
    mkdirSync(root, { recursive: true, mode: 0o700 });
    chmodSync(root, 0o700);
    const out = join(root, "secret.json");
    writeFileSync(out, `{ not json ${CANARY}`, { mode: 0o600 });
    chmodSync(out, 0o600);
    for (const argv of [
      ["pop", "sign", "--key", out, "--input", "-", "--output", "json"],
      ["key", "generate", "--out", out, "--input", "-", "--output", "json"],
    ]) {
      const stdin = argv[0] === "pop"
        ? JSON.stringify({ fields: { borrowerId: "b", terminalId: "t", jkt: "j" } })
        : JSON.stringify({ borrower_id: "b", terminal_id: "t" });
      const r = run(argv, stdin);
      assert.ok(!r.stdout.includes(CANARY) && !r.stderr.includes(CANARY), `leaked canary: ${r.stdout}${r.stderr}`);
    }
  } finally {
    if (prevHome === undefined) delete process.env.HOME; else process.env.HOME = prevHome;
    if (prevProfile === undefined) delete process.env.USERPROFILE; else process.env.USERPROFILE = prevProfile;
    if (prevRoots !== undefined) process.env.SOHOPAY_SIGNER_KEY_ROOTS = prevRoots;
    rmSync(home, { recursive: true, force: true });
  }
});

test("a rejected inline key never surfaces the key material", () => {
  const r = run(["voucher", "sign", "--input", "-", "--output", "json"],
    JSON.stringify({ voucher: {}, key: { private_key_base64url: INLINE } }));
  assert.ok(!r.stdout.includes(INLINE) && !r.stderr.includes(INLINE), "inline key leaked");
  assert.match(r.stderr, /INLINE_KEY_REJECTED/);
});
