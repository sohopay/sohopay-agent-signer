import { ed25519 } from "@noble/curves/ed25519";
import { keccak_256 } from "@noble/hashes/sha3";

import {
  DOMAIN_SEPARATOR_BYTE,
  SUPPORTED_SIGNING,
  VOUCHER_CORE_FIELDS,
  VOUCHER_DOMAIN_TAG,
} from "./constants.js";
import { fromBase64Url, toBase64Url, toHex, utf8Bytes } from "./encoding.js";
import { SignerError } from "./errors.js";
import { jcs } from "./jcs.js";
import { computeJkt, type Ed25519PublicJwk } from "./keys.js";

export interface AgentPaymentVoucherCore {
  agentId: string;
  merchantId: string;
  asset: string;
  chainId: string;
  amount: string;
  feeAmount: string;
  orderRef: string;
  nonce: string;
  deadline: string;
}

export interface AgentPaymentVoucher extends AgentPaymentVoucherCore {
  paymentId: `0x${string}`;
  agentKeyJkt: string;
}

/** The server's advertised signing block, validated against {@link SUPPORTED_SIGNING}. */
export interface ServerSigningBlock {
  algorithm?: string;
  domain_tag?: string;
  canonicalization?: string;
  signature_encoding?: string;
}

/** Every core field must be a string — no JSON number enters a signed preimage. */
function assertCoreStrings(core: AgentPaymentVoucherCore): void {
  for (const field of VOUCHER_CORE_FIELDS) {
    if (typeof core[field] !== "string") {
      throw new SignerError(
        "VOUCHER_FIELD_NOT_STRING",
        `voucher field "${field}" must be a string, got ${typeof core[field]}`,
      );
    }
  }
}

/** Explicit 9-field projection — an unknown wire key never enters the preimage. */
function voucherCoreOf(core: AgentPaymentVoucherCore): AgentPaymentVoucherCore {
  return {
    agentId: core.agentId,
    merchantId: core.merchantId,
    asset: core.asset,
    chainId: core.chainId,
    amount: core.amount,
    feeAmount: core.feeAmount,
    orderRef: core.orderRef,
    nonce: core.nonce,
    deadline: core.deadline,
  };
}

/** `utf8(tag) || 0x00 || JCS(value)`. */
function taggedPreimage(value: unknown): Uint8Array {
  const tag = utf8Bytes(VOUCHER_DOMAIN_TAG);
  const body = utf8Bytes(jcs(value));
  const out = new Uint8Array(tag.length + 1 + body.length);
  out.set(tag, 0);
  out[tag.length] = DOMAIN_SEPARATOR_BYTE;
  out.set(body, tag.length + 1);
  return out;
}

/** `paymentId = keccak256(utf8(tag) || 0x00 || JCS(core))`. */
export function computePaymentId(core: AgentPaymentVoucherCore): `0x${string}` {
  assertCoreStrings(core);
  return `0x${toHex(keccak_256(taggedPreimage(voucherCoreOf(core))))}`;
}

/** The exact bytes the agent signs: tagged preimage over the full 11-field voucher. */
export function buildVoucherSignedBytes(voucher: AgentPaymentVoucher): Uint8Array {
  assertCoreStrings(voucher);
  return taggedPreimage({
    ...voucherCoreOf(voucher),
    paymentId: voucher.paymentId,
    agentKeyJkt: voucher.agentKeyJkt,
  });
}

function assertSigningAllowed(signing?: ServerSigningBlock): void {
  if (!signing) {
    return;
  }
  const checks: ReadonlyArray<[keyof ServerSigningBlock, string]> = [
    ["algorithm", SUPPORTED_SIGNING.algorithm],
    ["domain_tag", SUPPORTED_SIGNING.domain_tag],
    ["canonicalization", SUPPORTED_SIGNING.canonicalization],
    ["signature_encoding", SUPPORTED_SIGNING.signature_encoding],
  ];
  for (const [key, expected] of checks) {
    const actual = signing[key];
    if (actual !== undefined && actual !== expected) {
      throw new SignerError(
        "SIGNING_SCHEME_NOT_ALLOWED",
        `server proposed ${key}="${actual}"; this SDK signs only "${expected}"`,
      );
    }
  }
}

export interface SignVoucherArgs {
  voucher: AgentPaymentVoucher;
  privateKeyBase64Url: string;
  /** The server `signing` block from prepare — validated, never substituted. */
  signing?: ServerSigningBlock;
  /** When given, asserts the voucher's `agentKeyJkt` matches this signing key. */
  publicJwk?: Ed25519PublicJwk;
}

/** Signs a voucher after fail-closed guards (scheme allowlist, paymentId, jkt). */
export function signVoucher(args: SignVoucherArgs): { signature: string } {
  assertSigningAllowed(args.signing);

  const recomputed = computePaymentId(args.voucher);
  if (recomputed.toLowerCase() !== args.voucher.paymentId.toLowerCase()) {
    throw new SignerError(
      "PAYMENT_ID_MISMATCH",
      "voucher.paymentId does not match the hash of its core",
    );
  }

  if (args.publicJwk) {
    const jkt = computeJkt(args.publicJwk);
    if (jkt !== args.voucher.agentKeyJkt) {
      throw new SignerError(
        "AGENT_KEY_JKT_MISMATCH",
        "voucher.agentKeyJkt does not match the signing key's thumbprint",
      );
    }
  }

  const signature = ed25519.sign(
    buildVoucherSignedBytes(args.voucher),
    fromBase64Url(args.privateKeyBase64Url),
  );
  return { signature: toBase64Url(signature) };
}
