/**
 * Compiled-in protocol constants. These are the SDK's source of truth for what
 * it will sign; a server-supplied `signing` block is only ever VALIDATED against
 * these, never substituted for them (downgrade protection).
 */

/** Protocol-V2 Envelope 1 domain-separation tag (SOHO-251 / T12). */
export const VOUCHER_DOMAIN_TAG = "SohoPay:AgentPaymentVoucher:v2";

/** Single 0x00 byte between the tag and the canonical JSON in every tagged preimage. */
export const DOMAIN_SEPARATOR_BYTE = 0x00;

/** Merchant-settler unlock header for the filled x402 envelope. */
export const PAYMENT_SIGNATURE_HEADER = "PAYMENT-SIGNATURE";

/** The only signing scheme this SDK version implements. */
export const SUPPORTED_SIGNING = {
  algorithm: "Ed25519",
  domain_tag: VOUCHER_DOMAIN_TAG,
  canonicalization: "RFC8785",
  signature_encoding: "base64url",
} as const;

/** The nine economic core fields, in the explicit projection order (never a spread). */
export const VOUCHER_CORE_FIELDS = [
  "agentId",
  "merchantId",
  "asset",
  "chainId",
  "amount",
  "feeAmount",
  "orderRef",
  "nonce",
  "deadline",
] as const;
