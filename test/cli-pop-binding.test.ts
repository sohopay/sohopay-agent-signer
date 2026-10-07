import { mkdtempSync, mkdirSync, writeFileSync, rmSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import assert from "node:assert/strict";
import test from "node:test";
import { popSignResult } from "../src/cli/commands.js";
import { generateWorkloadKey } from "../src/keys.js";

function keyFile(borrowerId: string, terminalId: string) {
  const home = mkdtempSync(join(tmpdir(), "pop-home-"));
  const root = join(home, ".agents", "sohopay-agent-workload");
  mkdirSync(root, { recursive: true, mode: 0o700 });
  const kp = generateWorkloadKey();
  const out = join(root, "secret.json");
  writeFileSync(out, JSON.stringify({ private_key_base64url: kp.privateKeyBase64Url, public_jwk: kp.publicJwk, jkt: kp.jkt, terminal_id: terminalId, borrower_id: borrowerId }), { mode: 0o600 });
  chmodSync(out, 0o600);
  return { home, out, jkt: kp.jkt, opts: { homeDir: home, env: {} as NodeJS.ProcessEnv } };
}

test("pop sign mints nonce+iat and returns them; signs with the file key", () => {
  const { home, out, jkt, opts } = keyFile("b1", "t1");
  try {
    const r = popSignResult({ fields: { borrowerId: "b1", terminalId: "t1", jkt } }, out, "", opts) as Record<string, unknown>;
    assert.ok(typeof r.pop_signature === "string" && (r.pop_signature as string).length > 0);
    assert.ok(typeof r.nonce === "string" && (r.nonce as string).length >= 43);
    assert.ok(Number.isSafeInteger(r.iat));
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test("pop sign refuses a terminal mismatch and a borrower mismatch", () => {
  const { home, out, jkt, opts } = keyFile("b1", "t1");
  try {
    assert.throws(() => popSignResult({ fields: { borrowerId: "b1", terminalId: "tX", jkt } }, out, "", opts),
      (e: { code?: string }) => e.code === "TERMINAL_MISMATCH");
    assert.throws(() => popSignResult({ fields: { borrowerId: "bX", terminalId: "t1", jkt } }, out, "", opts),
      (e: { code?: string }) => e.code === "CROSS_BORROWER_KEY");
  } finally { rmSync(home, { recursive: true, force: true }); }
});
