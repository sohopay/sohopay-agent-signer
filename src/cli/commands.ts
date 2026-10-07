import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";

import { IMPLEMENTATION, SIGNER_PROTOCOL, SUPPORTED_SIGNING } from "../constants.js";
import { toBase64Url } from "../encoding.js";
import { buildPaymentSignatureHeader } from "../envelope.js";
import { SignerError } from "../errors.js";
import { computeJkt, decodeWorkloadSeed, workloadKeyFromPrivate } from "../keys.js";
import { signPoP } from "../pop.js";
import {
  computePaymentId,
  signVoucher,
  type AgentPaymentVoucher,
  type AgentPaymentVoucherCore,
} from "../voucher.js";
import { loadKeyFile, type StoredWorkloadKey } from "../storage.js";
import { validateKeyPath } from "./key-path.js";
import { readKeyFile, resolveKeyBlock, type ResolvedKey } from "./io.js";
import { verifyVectors } from "./verify-vectors.js";

/** Reads this package's version from package.json, relative to the module. */
export function implementationVersion(): string {
  const pkg = JSON.parse(
    readFileSync(new URL("../../package.json", import.meta.url), "utf8"),
  ) as { version?: string };
  return pkg.version ?? "0.0.0";
}

const COMMANDS = ["voucher sign", "payment-id", "key jkt", "key generate", "pop sign", "verify-vectors", "capabilities"];

const COMMAND_CONTRACTS: Record<string, string> = {
  "key generate": "workload-keygen/1",
  "pop sign": "pop-sign/1",
};

/** Static advertisement SP5 routing probes to confirm a usable signer. */
export function capabilitiesResult(): Record<string, unknown> {
  return {
    signer_protocol: SIGNER_PROTOCOL,
    implementation: IMPLEMENTATION,
    implementation_version: implementationVersion(),
    algorithms: [SUPPORTED_SIGNING.algorithm],
    commands: COMMANDS,
    command_contracts: COMMAND_CONTRACTS,
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

type KeyOpts = { homeDir?: string; env?: NodeJS.ProcessEnv };

/** `{ public_jwk } | { key: { public_jwk | private_key_base64url } } → { agent_key_jkt }`. */
export function keyJktResult(input: unknown): Record<string, unknown> {
  const record = (input ?? {}) as Record<string, unknown>;
  const block = record.public_jwk !== undefined ? { public_jwk: record.public_jwk } : record.key;
  if (block && typeof block === "object" && (block as Record<string, unknown>).private_key_base64url !== undefined) {
    throw new SignerError("INLINE_KEY_REJECTED", "key jkt does not accept inline private key material; pass public_jwk");
  }
  const key = resolveKeyBlock(block);
  if (key.publicJwk) {
    return { agent_key_jkt: computeJkt(key.publicJwk) };
  }
  if (key.privateKeyBase64Url) {
    return { agent_key_jkt: workloadKeyFromPrivate(key.privateKeyBase64Url).jkt };
  }
  throw new SignerError("MALFORMED_ENVELOPE", "key jkt requires public_jwk or a key with private/public material");
}

/**
 * Resolves the signing key from a validated `--key <path>` file only. Inline key
 * material is rejected first (INV-3) so a secret never travels through input JSON.
 */
export function resolveSigningKey(
  input: Record<string, unknown>,
  keyFileSource: string | undefined,
  stdin: string,
  opts: KeyOpts = {},
): ResolvedKey {
  if (input.key !== undefined) {
    throw new SignerError("INLINE_KEY_REJECTED", "inline key material is not accepted; use --key <path>");
  }
  if (keyFileSource === undefined) {
    throw new SignerError("MALFORMED_INPUT", "signing requires --key <path>");
  }
  const key = readKeyFile(keyFileSource, stdin, opts);

  // Validate the seed here so a malformed key surfaces as INVALID_PRIVATE_KEY on
  // every signing path — even when a public_jwk is supplied and the SDK would
  // otherwise only decode the seed deep inside ed25519.sign.
  if (key.privateKeyBase64Url !== undefined) {
    decodeWorkloadSeed(key.privateKeyBase64Url);
  }
  return key;
}

/** `{ voucher, signing?, key? } (+ optional --key) → signed result`. */
export function voucherSignResult(
  input: unknown,
  keyFileSource: string | undefined,
  stdin: string,
  opts: KeyOpts = {},
): Record<string, unknown> {
  const record = (input ?? {}) as Record<string, unknown>;
  const voucher = record.voucher as AgentPaymentVoucher | undefined;
  if (voucher === null || typeof voucher !== "object") {
    throw new SignerError("MALFORMED_ENVELOPE", "voucher sign requires a `voucher` object");
  }
  const key = resolveSigningKey(record, keyFileSource, stdin, opts);
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

/**
 * `--envelope`: `{ voucher, signing?, envelope, header_name, key? } (+ optional --key)`
 * -> signed result plus the completed x402 envelope and PAYMENT-SIGNATURE header.
 * Fills ONLY paymentPayload.payload.signature; never re-signs a filled envelope.
 */
export function voucherSignEnvelopeResult(
  input: unknown,
  keyFileSource: string | undefined,
  stdin: string,
  opts: KeyOpts = {},
): Record<string, unknown> {
  const record = (input ?? {}) as Record<string, unknown>;

  const voucher = record.voucher as AgentPaymentVoucher | undefined;
  if (voucher === null || typeof voucher !== "object") {
    throw new SignerError("MALFORMED_ENVELOPE", "voucher sign --envelope requires a `voucher` object");
  }

  const prepareEnvelope = record.envelope;
  if (prepareEnvelope === null || typeof prepareEnvelope !== "object") {
    throw new SignerError("MALFORMED_ENVELOPE", "voucher sign --envelope requires an `envelope` object");
  }

  const headerName = record.header_name;
  if (typeof headerName !== "string" || headerName.length === 0) {
    throw new SignerError(
      "MALFORMED_ENVELOPE",
      "voucher sign --envelope requires a non-empty string `header_name`",
    );
  }
  // header_name is emitted into a curl-ready header line ("<name>: <value>\n"), so it
  // must be a valid HTTP field-name (RFC 7230 token) — no CR/LF, colon, space, or control
  // chars that could inject a second header. Fail closed on anything else.
  if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(headerName)) {
    throw new SignerError(
      "MALFORMED_ENVELOPE",
      "header_name is not a valid HTTP header name",
    );
  }

  const payload = (prepareEnvelope as {
    paymentPayload?: { payload?: { signature?: unknown; voucher?: { paymentId?: unknown } } };
  }).paymentPayload?.payload;
  if (payload === null || typeof payload !== "object") {
    throw new SignerError("MALFORMED_ENVELOPE", "input envelope is missing paymentPayload.payload");
  }

  // Guard: never re-sign an already-filled envelope.
  if (payload.signature !== undefined && payload.signature !== null) {
    throw new SignerError("MALFORMED_ENVELOPE", "input envelope already carries a signature");
  }

  // Guard: the voucher embedded in the envelope must be the voucher we sign (payment_id cross-check).
  const embeddedPaymentId = payload.voucher?.paymentId;
  if (typeof embeddedPaymentId !== "string") {
    throw new SignerError(
      "MALFORMED_ENVELOPE",
      "input envelope is missing paymentPayload.payload.voucher.paymentId",
    );
  }
  if (embeddedPaymentId !== voucher.paymentId) {
    throw new SignerError(
      "PAYMENT_ID_MISMATCH",
      "voucher paymentId does not match the envelope's embedded voucher",
    );
  }

  const key = resolveSigningKey(record, keyFileSource, stdin, opts);
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

  const { headerValue, envelope } = buildPaymentSignatureHeader(prepareEnvelope, signature);

  return {
    signer_protocol: SIGNER_PROTOCOL,
    implementation: IMPLEMENTATION,
    implementation_version: implementationVersion(),
    payment_id: voucher.paymentId,
    agent_key_jkt: voucher.agentKeyJkt,
    signature,
    algorithm: SUPPORTED_SIGNING.algorithm,
    envelope,
    header_name: headerName,
    header_value: headerValue,
  };
}

/** `{ fields: { borrowerId, terminalId, jkt } } (+ --key <path>) → { …, pop_signature, nonce, iat }`. */
export function popSignResult(
  input: unknown,
  keyFileSource: string | undefined,
  _stdin: string,
  opts: { homeDir?: string; env?: NodeJS.ProcessEnv } = {},
): Record<string, unknown> {
  const record = (input ?? {}) as Record<string, unknown>;
  const fields = record.fields as { borrowerId?: unknown; terminalId?: unknown; jkt?: unknown } | undefined;
  if (fields === null || fields === undefined || typeof fields !== "object") {
    throw new SignerError("MALFORMED_INPUT", "pop sign requires a `fields` object");
  }
  if (keyFileSource === undefined) {
    throw new SignerError("MALFORMED_INPUT", "pop sign requires --key <path>");
  }
  const { borrowerId, terminalId, jkt } = fields;
  if (typeof borrowerId !== "string" || typeof terminalId !== "string" || typeof jkt !== "string") {
    throw new SignerError("MALFORMED_INPUT", "pop sign fields require string borrowerId, terminalId, jkt");
  }

  // Bind the claimed identity to the stored key before signing anything.
  const stored = loadKeyFile(validateKeyPath(keyFileSource, "read", opts)) as StoredWorkloadKey;
  if (stored.borrower_id !== borrowerId) throw new SignerError("CROSS_BORROWER_KEY", "fields.borrowerId does not match the key file");
  if (stored.terminal_id !== terminalId) throw new SignerError("TERMINAL_MISMATCH", "fields.terminalId does not match the key file");
  if (stored.jkt !== jkt) throw new SignerError("AGENT_KEY_JKT_MISMATCH", "fields.jkt does not match the key file");

  // Nonce/iat are minted here, never accepted from the caller (replay defense).
  const nonce = toBase64Url(randomBytes(32));
  const iat = Math.floor(Date.now() / 1000);
  const { pop_signature } = signPoP({ borrowerId, terminalId, jkt, nonce, iat }, stored.private_key_base64url);
  return {
    signer_protocol: SIGNER_PROTOCOL,
    implementation: IMPLEMENTATION,
    implementation_version: implementationVersion(),
    pop_signature,
    nonce,
    iat,
    algorithm: SUPPORTED_SIGNING.algorithm,
  };
}

/** `verify-vectors → ({ passed, failed, total }, ok)`; ok drives the exit code. */
export function verifyVectorsResult(): { result: Record<string, unknown>; ok: boolean } {
  const summary = verifyVectors();
  return {
    result: { passed: summary.passed, failed: summary.failed, total: summary.total },
    ok: summary.failed === 0,
  };
}
