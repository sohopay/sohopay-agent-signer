import { readFileSync } from "node:fs";

import { IMPLEMENTATION, SIGNER_PROTOCOL, SUPPORTED_SIGNING } from "../constants.js";
import { SignerError } from "../errors.js";
import { computeJkt, workloadKeyFromPrivate } from "../keys.js";
import {
  computePaymentId,
  signVoucher,
  type AgentPaymentVoucher,
  type AgentPaymentVoucherCore,
} from "../voucher.js";
import { readKeyFile, resolveKeyBlock, type ResolvedKey } from "./io.js";

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

/** Resolves the signing key from exactly one source: inline `input.key` or --key. */
export function resolveSigningKey(
  input: Record<string, unknown>,
  keyFileSource: string | undefined,
  stdin: string,
): ResolvedKey {
  const inline = input.key;
  if (inline !== undefined && keyFileSource !== undefined) {
    throw new SignerError("MALFORMED_ENVELOPE", "provide the key inline OR via --key, not both");
  }
  if (keyFileSource !== undefined) {
    return readKeyFile(keyFileSource, stdin);
  }
  if (inline !== undefined) {
    return resolveKeyBlock(inline);
  }
  throw new SignerError("MALFORMED_ENVELOPE", "signing requires a key (inline `key` or --key)");
}

/** `{ voucher, signing?, key? } (+ optional --key) → signed result`. */
export function voucherSignResult(
  input: unknown,
  keyFileSource: string | undefined,
  stdin: string,
): Record<string, unknown> {
  const record = (input ?? {}) as Record<string, unknown>;
  const voucher = record.voucher as AgentPaymentVoucher | undefined;
  if (voucher === null || typeof voucher !== "object") {
    throw new SignerError("MALFORMED_ENVELOPE", "voucher sign requires a `voucher` object");
  }
  const key = resolveSigningKey(record, keyFileSource, stdin);
  if (!key.privateKeyBase64Url) {
    throw new SignerError("MALFORMED_ENVELOPE", "signing key is missing private_key_base64url");
  }

  const { signature } = signVoucher({
    voucher,
    privateKeyBase64Url: key.privateKeyBase64Url,
    signing: record.signing as never,
    // Derive the public key from the seed when absent so the jkt-binding guard always runs.
    publicJwk: key.publicJwk ?? workloadKeyFromPrivate(key.privateKeyBase64Url).publicJwk,
  });

  return {
    signer_protocol: SIGNER_PROTOCOL,
    implementation: IMPLEMENTATION,
    implementation_version: implementationVersion(),
    payment_id: voucher.paymentId,
    agent_key_jkt: voucher.agentKeyJkt,
    signature,
    algorithm: SUPPORTED_SIGNING.algorithm,
  };
}
