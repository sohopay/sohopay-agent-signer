import { closeSync, openSync } from "node:fs";

import { SignerError } from "../errors.js";
import { generateWorkloadKey, workloadKeyFromPrivate, type Ed25519PublicJwk } from "../keys.js";
import { loadKeyFile, writeSecretFileAtPath, type StoredWorkloadKey } from "../storage.js";
import { validateKeyPath } from "./key-path.js";

function str(rec: Record<string, unknown>, k: string): string {
  const v = rec[k];
  if (typeof v !== "string" || v.length === 0) {
    throw new SignerError("MALFORMED_INPUT", `key generate requires a non-empty string \`${k}\``);
  }
  return v;
}

/** Public-only projection; the private key must never leave this module. */
function publicMaterial(stored: StoredWorkloadKey): Record<string, unknown> {
  return { public_jwk: stored.public_jwk, jkt: stored.jkt, borrower_id: stored.borrower_id, terminal_id: stored.terminal_id };
}

/**
 * Ensure-mode key generation + persistence. Never overwrites an existing key:
 * an existing file is only verified (borrower, terminal, derived-public integrity).
 */
export function keyGenerateResult(
  input: unknown,
  outPath: string | undefined,
  opts: { homeDir?: string; env?: NodeJS.ProcessEnv } = {},
): Record<string, unknown> {
  if (outPath === undefined) {
    throw new SignerError("MALFORMED_INPUT", "key generate requires --out <path>");
  }
  const rec = (input ?? {}) as Record<string, unknown>;
  const borrowerId = str(rec, "borrower_id");
  const terminalId = str(rec, "terminal_id");

  // Probe existence via a read-mode validation (throws KEY_PATH_INVALID when absent).
  let existing: StoredWorkloadKey | undefined;
  try {
    existing = loadKeyFile(validateKeyPath(outPath, "read", opts)) as StoredWorkloadKey;
  } catch (e) {
    if ((e as { code?: string }).code !== "KEY_PATH_INVALID") throw e;
    existing = undefined;
  }

  if (existing) {
    if (existing.borrower_id !== borrowerId) {
      throw new SignerError("CROSS_BORROWER_KEY", "a key for a different borrower exists at this path");
    }
    if (existing.terminal_id !== terminalId) {
      throw new SignerError("TERMINAL_MISMATCH", "the stored key is bound to a different terminal");
    }
    const derived = workloadKeyFromPrivate(existing.private_key_base64url);
    if (derived.jkt !== existing.jkt || derived.publicJwk.x !== (existing.public_jwk as Ed25519PublicJwk).x) {
      throw new SignerError("KEY_INTEGRITY_FAILED", "stored public material does not match the private key");
    }
    return { ...publicMaterial(existing), created: false };
  }

  const writePath = validateKeyPath(outPath, "ensure", opts); // re-checks nothing exists (race)
  const keypair = generateWorkloadKey();
  const stored: StoredWorkloadKey = {
    private_key_base64url: keypair.privateKeyBase64Url,
    public_jwk: keypair.publicJwk,
    jkt: keypair.jkt,
    terminal_id: terminalId,
    borrower_id: borrowerId,
  };
  try {
    // O_EXCL placeholder claims the path; a race loser re-enters the read branch.
    closeSync(openSync(writePath, "wx", 0o600));
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "EEXIST") {
      return keyGenerateResult(input, outPath, opts);
    }
    throw new SignerError("KEY_PERSIST_FAILED", `cannot create ${writePath}`);
  }
  try {
    writeSecretFileAtPath(writePath, stored); // atomic rename over the placeholder
  } catch {
    throw new SignerError("KEY_PERSIST_FAILED", "cannot persist the workload key");
  }
  return { ...publicMaterial(stored), created: true };
}
