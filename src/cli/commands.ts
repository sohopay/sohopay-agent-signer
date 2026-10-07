import { readFileSync } from "node:fs";

import { IMPLEMENTATION, SIGNER_PROTOCOL, SUPPORTED_SIGNING } from "../constants.js";
import { buildPaymentSignatureHeader } from "../envelope.js";
import { SignerError } from "../errors.js";
import { computeJkt, decodeWorkloadSeed, workloadKeyFromPrivate } from "../keys.js";
import { signPoP, type PopChallengeFields } from "../pop.js";
import {
  computePaymentId,
  signVoucher,
  type AgentPaymentVoucher,
  type AgentPaymentVoucherCore,
} from "../voucher.js";
import { readKeyFile, resolveKeyBlock, type ResolvedKey } from "./io.js";
import { verifyVectors } from "./verify-vectors.js";

// ambient — esbuild `define` replaces this literal in the bundle; undefined in the tsc/tsx path
declare const __SIGNER_IMPL_VERSION__: string | undefined;

/** The signer's implementation version: build-injected in the bundle, else from package.json. */
export function implementationVersion(): string {
  if (typeof __SIGNER_IMPL_VERSION__ !== "undefined" && __SIGNER_IMPL_VERSION__) {
    return __SIGNER_IMPL_VERSION__;
  }
  // Below is the tsc/tsx path only. In the esbuild bundle the `define` above makes the
  // first branch always true, so this package.json read is dead there — its relative
  // `../../package.json` URL would not resolve from the single-file bundle if ever reached.
  const pkg = JSON.parse(
    readFileSync(new URL("../../package.json", import.meta.url), "utf8"),
  ) as { version?: string };
  if (!pkg.version) {
    throw new Error("implementation_version could not be resolved from package.json");
  }
  return pkg.version;
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
  let key: ResolvedKey;
  if (keyFileSource !== undefined) {
    key = readKeyFile(keyFileSource, stdin);
  } else if (inline !== undefined) {
    key = resolveKeyBlock(inline);
  } else {
    throw new SignerError("MALFORMED_ENVELOPE", "signing requires a key (inline `key` or --key)");
  }

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

/**
 * `--envelope`: `{ voucher, signing?, envelope, header_name, key? } (+ optional --key)`
 * -> signed result plus the completed x402 envelope and PAYMENT-SIGNATURE header.
 * Fills ONLY paymentPayload.payload.signature; never re-signs a filled envelope.
 */
export function voucherSignEnvelopeResult(
  input: unknown,
  keyFileSource: string | undefined,
  stdin: string,
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

/** `{ fields, key? } (+ optional --key) → { pop_signature }`. */
export function popSignResult(
  input: unknown,
  keyFileSource: string | undefined,
  stdin: string,
): Record<string, unknown> {
  const record = (input ?? {}) as Record<string, unknown>;
  const fields = record.fields;
  if (fields === null || typeof fields !== "object") {
    throw new SignerError("MALFORMED_ENVELOPE", "pop sign requires a `fields` object");
  }
  const key = resolveSigningKey(record, keyFileSource, stdin);
  if (!key.privateKeyBase64Url) {
    throw new SignerError("MALFORMED_ENVELOPE", "signing key is missing private_key_base64url");
  }
  const { pop_signature } = signPoP(fields as PopChallengeFields, key.privateKeyBase64Url);
  return {
    signer_protocol: SIGNER_PROTOCOL,
    implementation: IMPLEMENTATION,
    implementation_version: implementationVersion(),
    pop_signature,
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
