import { randomUUID } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
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
