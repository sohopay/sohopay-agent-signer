import { randomUUID } from "node:crypto";
import { chmodSync, linkSync, mkdirSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { homedir, hostname } from "node:os";
import { dirname, join } from "node:path";

import { SignerError } from "./errors.js";

/** Backend `RegisterBorrowerDto.terminal_id` charset / length. */
export const TERMINAL_ID_PATTERN = /^[A-Za-z0-9._:@-]+$/;
export const TERMINAL_ID_MAX_LENGTH = 128;

/** Backend sentinel for adopted terminal-1 rows — never accepted as input. */
const ADOPTED_TERMINAL_SENTINEL = "__adopted__";

/** Validates a terminal id against the backend's charset/length rules. */
export function assertValidTerminalId(terminalId: string): string {
  const trimmed = terminalId.trim();
  if (!trimmed) {
    throw new SignerError("INVALID_TERMINAL_ID", "terminal_id must be a non-empty string");
  }
  if (trimmed.length > TERMINAL_ID_MAX_LENGTH) {
    throw new SignerError(
      "INVALID_TERMINAL_ID",
      `terminal_id must be at most ${TERMINAL_ID_MAX_LENGTH} characters`,
    );
  }
  if (!TERMINAL_ID_PATTERN.test(trimmed)) {
    throw new SignerError(
      "INVALID_TERMINAL_ID",
      "terminal_id must contain only letters, digits, and . _ : @ - (no whitespace)",
    );
  }
  if (trimmed === ADOPTED_TERMINAL_SENTINEL) {
    throw new SignerError("INVALID_TERMINAL_ID", "terminal_id is reserved and cannot be used");
  }
  return trimmed;
}

/** The SDK data directory: explicit → `SOHO_DATA_DIR` → `~/.sohopay`. */
export function resolveDataDir(dataDir?: string): string {
  const explicit = (dataDir ?? process.env.SOHO_DATA_DIR ?? "").trim();
  return explicit || join(homedir(), ".sohopay");
}

function terminalIdPath(dataDir?: string): string {
  return join(resolveDataDir(dataDir), "terminal_id");
}

function hostLabel(): string {
  const raw = hostname().trim().toLowerCase() || "host";
  const sanitized = raw.replace(/[^a-z0-9._:@-]+/gi, "-").replace(/^-+|-+$/g, "") || "host";
  return sanitized.slice(0, 48);
}

function readPersistedTerminalId(filePath: string): string | undefined {
  let raw: string;
  try {
    raw = readFileSync(filePath, "utf8").trim();
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return undefined;
    }
    // Never silently regenerate on an unexpected IO error (EACCES, EISDIR, …):
    // that would rotate this host's terminal identity and mint a new
    // OperationalAgent on the next register. Surface it instead.
    throw error;
  }
  if (!raw) {
    return undefined;
  }
  try {
    return assertValidTerminalId(raw);
  } catch {
    return undefined;
  }
}

function persistTerminalId(filePath: string, terminalId: string): void {
  mkdirSync(dirname(filePath), { recursive: true });
  writeFileSync(filePath, `${terminalId}\n`, { encoding: "utf8", mode: 0o600 });
}

export interface ResolveTerminalIdOptions {
  /** Explicit id (e.g. two clients sharing one remote MCP); validated and returned as-is. */
  explicit?: string;
  dataDir?: string;
}

/**
 * Resolves a stable per-host `terminal_id`. Precedence:
 * 1. explicit argument, 2. `SOHO_TERMINAL_ID`, 3. persisted `{hostname}:{uuid}`
 * under the data dir (minted + persisted on first use).
 */
export function resolveTerminalId(options: ResolveTerminalIdOptions = {}): string {
  if (options.explicit) {
    return assertValidTerminalId(options.explicit);
  }
  const envValue = (process.env.SOHO_TERMINAL_ID ?? "").trim();
  if (envValue) {
    return assertValidTerminalId(envValue);
  }

  const filePath = terminalIdPath(options.dataDir);
  const persisted = readPersistedTerminalId(filePath);
  if (persisted) {
    return persisted;
  }

  const minted = `${hostLabel()}:${randomUUID()}`;
  persistTerminalId(filePath, minted);
  return minted;
}

/**
 * Harnesses that may hold their own terminal id. A fixed list, so the slug is a safe
 * single path segment and no caller-chosen string ever names a directory.
 */
export const HARNESSES = ["antigravity", "claude-code", "codex", "cursor", "hermes"] as const;
export type Harness = (typeof HARNESSES)[number];

/**
 * Per-harness terminal id: `{harness}:{uuid}` persisted at `<dataDir>/<harness>/terminal_id`
 * (dir 0700, file 0600), minted on first use and stable afterwards. Unlike
 * {@link resolveTerminalId} it ignores `SOHO_TERMINAL_ID`: a host-wide override would
 * collapse every harness back onto one terminal.
 */
export function resolveHarnessTerminalId(harness: string, dataDir?: string): string {
  if (!(HARNESSES as readonly string[]).includes(harness)) {
    throw new SignerError("INVALID_HARNESS", `--harness must be one of: ${HARNESSES.join(", ")}`);
  }
  const dir = join(resolveDataDir(dataDir), harness);
  const filePath = join(dir, "terminal_id");
  const persisted = readHarnessTerminalId(filePath, harness);
  if (persisted) return persisted;
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  chmodSync(dir, 0o700);
  const minted = `${harness}:${randomUUID()}`;
  // Write a private temp file, then publish it with link(2): the id appears complete or
  // not at all, so a racing first call can never read a half-written file, and EEXIST
  // means someone else won and their id is already whole.
  const tmp = join(dir, `.terminal_id.${process.pid}.${randomUUID()}`);
  writeFileSync(tmp, `${minted}\n`, { encoding: "utf8", mode: 0o600, flag: "wx" });
  try {
    linkSync(tmp, filePath);
    return minted;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    const winner = readHarnessTerminalId(filePath, harness);
    if (!winner) throw new SignerError("INVALID_TERMINAL_ID", `${filePath} holds no valid terminal id`);
    return winner;
  } finally {
    unlinkSync(tmp);
  }
}

/** Reads the persisted id and refuses one minted for another harness (a copied or edited file). */
function readHarnessTerminalId(filePath: string, harness: string): string | undefined {
  const id = readPersistedTerminalId(filePath);
  if (id !== undefined && !id.startsWith(`${harness}:`)) {
    throw new SignerError("INVALID_TERMINAL_ID", `${filePath} holds an id that does not belong to ${harness}`);
  }
  return id;
}
