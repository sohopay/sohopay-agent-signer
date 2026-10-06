import { readFileSync } from "node:fs";

import { IMPLEMENTATION, SIGNER_PROTOCOL, SUPPORTED_SIGNING } from "../constants.js";
import { SignerError } from "../errors.js";
import { computeJkt, workloadKeyFromPrivate } from "../keys.js";
import { computePaymentId, type AgentPaymentVoucherCore } from "../voucher.js";
import { resolveKeyBlock } from "./io.js";

/** Reads this package's version from package.json, relative to the module. */
export function implementationVersion(): string {
  const pkg = JSON.parse(
    readFileSync(new URL("../../package.json", import.meta.url), "utf8"),
  ) as { version?: string };
  return pkg.version ?? "0.0.0";
}

const COMMANDS = ["voucher sign", "payment-id", "key jkt", "pop sign", "verify-vectors", "capabilities"];

/** Static advertisement SP5 routing probes to confirm a usable signer. */
export function capabilitiesResult(): Record<string, unknown> {
  return {
    signer_protocol: SIGNER_PROTOCOL,
    implementation: IMPLEMENTATION,
    implementation_version: implementationVersion(),
    algorithms: [SUPPORTED_SIGNING.algorithm],
    commands: COMMANDS,
  };
}

/** `{ core } → { payment_id }`. */
export function paymentIdResult(input: unknown): Record<string, unknown> {
  const core = (input as { core?: unknown } | null)?.core;
  if (core === null || typeof core !== "object") {
    throw new SignerError("MALFORMED_ENVELOPE", "payment-id requires a `core` object");
  }
  return { payment_id: computePaymentId(core as AgentPaymentVoucherCore) };
}

/** `{ public_jwk } | { key: { public_jwk | private_key_base64url } } → { agent_key_jkt }`. */
export function keyJktResult(input: unknown): Record<string, unknown> {
  const record = (input ?? {}) as Record<string, unknown>;
  const block = record.public_jwk !== undefined ? { public_jwk: record.public_jwk } : record.key;
  const key = resolveKeyBlock(block);
  if (key.publicJwk) {
    return { agent_key_jkt: computeJkt(key.publicJwk) };
  }
  if (key.privateKeyBase64Url) {
    return { agent_key_jkt: workloadKeyFromPrivate(key.privateKeyBase64Url).jkt };
  }
  throw new SignerError("MALFORMED_ENVELOPE", "key jkt requires public_jwk or a key with private/public material");
}
