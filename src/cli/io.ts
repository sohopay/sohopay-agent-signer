import { readFileSync } from "node:fs";

import { UsageError } from "./args.js";
import { SignerError } from "../errors.js";
import { assertPublicJwk, type Ed25519PublicJwk } from "../keys.js";
import { loadKeyFile } from "../storage.js";

/** A key block coerced to the SDK's camelCase argument names. */
export interface ResolvedKey {
  privateKeyBase64Url?: string;
  publicJwk?: Ed25519PublicJwk;
}

/** Reads and JSON-parses the --input source. Absence is a usage error (exit 2). */
export function readInput(source: string | undefined, stdin: string): unknown {
  if (source === undefined) {
    throw new UsageError("this command requires --input <file|->");
  }
  let raw: string;
  if (source === "-") {
    raw = stdin;
  } else {
    try {
      raw = readFileSync(source, "utf8");
    } catch {
      throw new SignerError("MALFORMED_ENVELOPE", `cannot read input file: ${source}`);
    }
  }
  try {
    return JSON.parse(raw);
  } catch {
    throw new SignerError("MALFORMED_ENVELOPE", "input is not valid JSON");
  }
}

/**
 * Coerces an on-wire key block ({ private_key_base64url?, public_jwk? }) to the
 * SDK's camelCase names. `public_jwk` is validated by the SDK (rejects `d`).
 */
export function resolveKeyBlock(block: unknown): ResolvedKey {
  if (block === null || typeof block !== "object") {
    throw new SignerError("MALFORMED_ENVELOPE", "key block must be an object");
  }
  const record = block as Record<string, unknown>;
  const resolved: ResolvedKey = {};

  const priv = record.private_key_base64url;
  if (priv !== undefined) {
    if (typeof priv !== "string") {
      throw new SignerError("MALFORMED_ENVELOPE", "private_key_base64url must be a string");
    }
    resolved.privateKeyBase64Url = priv;
  }
  if (record.public_jwk !== undefined) {
    resolved.publicJwk = assertPublicJwk(record.public_jwk);
  }
  return resolved;
}

/** Reads a key JSON file (or "-" = stdin) into a ResolvedKey. */
export function readKeyFile(source: string, stdin: string): ResolvedKey {
  if (source === "-") {
    let parsed: unknown;
    try {
      parsed = JSON.parse(stdin);
    } catch {
      throw new SignerError("MALFORMED_ENVELOPE", "key file is not valid JSON");
    }
    return resolveKeyBlock(parsed);
  }
  // Delegates to the permission-checked read so a loosened file is refused.
  return resolveKeyBlock(loadKeyFile(source));
}
