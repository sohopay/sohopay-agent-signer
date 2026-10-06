import {
  chmodSync,
  closeSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { platform } from "node:os";
import { dirname, join } from "node:path";

import { SignerError } from "./errors.js";
import { generateWorkloadKey, type Ed25519PublicJwk } from "./keys.js";
import { resolveDataDir } from "./terminal.js";

/** On-disk shape of a persisted agent workload key. */
export interface StoredWorkloadKey {
  private_key_base64url: string;
  public_jwk: Ed25519PublicJwk;
  jkt: string;
  terminal_id: string;
  borrower_id: string;
}

/** borrower_id must be safe as a single path segment (no separators / traversal). */
const BORROWER_ID_PATTERN = /^[A-Za-z0-9._:@-]+$/;

function assertSafeBorrowerId(borrowerId: string): string {
  const trimmed = borrowerId.trim();
  if (!trimmed || !BORROWER_ID_PATTERN.test(trimmed)) {
    throw new SignerError(
      "INVALID_BORROWER_ID",
      "borrower_id must contain only letters, digits, and . _ : @ - (safe as a path segment)",
    );
  }
  return trimmed;
}

export interface WorkloadKeyStoreOptions {
  dataDir?: string;
}

/** Per-borrower secret path — keying by borrower prevents cross-borrower overwrite. */
function secretPath(borrowerId: string, dataDir?: string): string {
  return join(
    resolveDataDir(dataDir),
    "agent-workload",
    assertSafeBorrowerId(borrowerId),
    "secret.json",
  );
}

function assertSecurePermissions(path: string): void {
  if (platform() === "win32") {
    // POSIX mode bits are not meaningful on Windows; ACLs govern access there.
    return;
  }
  const mode = statSync(path).mode & 0o777;
  if (mode & 0o077) {
    throw new SignerError(
      "INSECURE_KEY_PERMISSIONS",
      `${path} is group/world-accessible (mode ${mode.toString(8)}); refusing to load`,
    );
  }
}

/** Reads and parses a key file at an explicit path, refusing group/world-readable files. */
export function loadKeyFile(path: string): unknown {
  // Permissions are checked before the secret is read so a loosened file is never parsed.
  assertSecurePermissions(path);
  const raw = readFileSync(path, "utf8");
  try {
    return JSON.parse(raw);
  } catch {
    throw new SignerError("STORED_KEY_CORRUPT", `${path} is not valid JSON`);
  }
}

/**
 * Loads the stored key for a borrower, or `undefined` if none exists or it does
 * not match (borrower, and optionally jkt). Refuses to load a world/group
 * readable file. Throws on unexpected IO errors and on corrupt JSON.
 */
export function loadWorkloadKey(args: {
  borrowerId: string;
  expectedJkt?: string;
  dataDir?: string;
}): StoredWorkloadKey | undefined {
  const path = secretPath(args.borrowerId, args.dataDir);
  let raw: string;
  try {
    raw = readFileSync(path, "utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return undefined;
    }
    throw error;
  }
  assertSecurePermissions(path);

  let parsed: StoredWorkloadKey;
  try {
    parsed = JSON.parse(raw) as StoredWorkloadKey;
  } catch {
    throw new SignerError("STORED_KEY_CORRUPT", `${path} is not valid JSON`);
  }

  if (parsed.borrower_id !== assertSafeBorrowerId(args.borrowerId)) {
    return undefined;
  }
  if (args.expectedJkt && parsed.jkt !== args.expectedJkt) {
    return undefined;
  }
  return parsed;
}

/** Atomically persists a workload key at 0600 (temp file → fsync → rename). */
export function saveWorkloadKey(key: StoredWorkloadKey, options: WorkloadKeyStoreOptions = {}): void {
  assertSafeBorrowerId(key.borrower_id);
  const path = secretPath(key.borrower_id, options.dataDir);
  const dir = dirname(path);
  mkdirSync(dir, { recursive: true, mode: 0o700 });

  const tmp = join(dir, `.secret.${process.pid}.${Date.now()}.tmp`);
  const fd = openSync(tmp, "w", 0o600);
  try {
    writeFileSync(fd, `${JSON.stringify(key, null, 2)}\n`);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  chmodSync(tmp, 0o600);
  renameSync(tmp, path);
}

/**
 * Returns the borrower's existing key, or generates and persists a fresh one.
 * Because the path is borrower-scoped, this never overwrites another borrower's
 * key on the same host.
 */
export function loadOrCreateWorkloadKey(args: {
  borrowerId: string;
  terminalId: string;
  dataDir?: string;
}): StoredWorkloadKey {
  const existing = loadWorkloadKey({ borrowerId: args.borrowerId, dataDir: args.dataDir });
  if (existing) {
    return existing;
  }
  const keypair = generateWorkloadKey();
  const stored: StoredWorkloadKey = {
    private_key_base64url: keypair.privateKeyBase64Url,
    public_jwk: keypair.publicJwk,
    jkt: keypair.jkt,
    terminal_id: args.terminalId,
    borrower_id: assertSafeBorrowerId(args.borrowerId),
  };
  saveWorkloadKey(stored, { dataDir: args.dataDir });
  return stored;
}
