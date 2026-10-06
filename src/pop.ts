import { ed25519 } from "@noble/curves/ed25519";

import { fromBase64Url, toBase64Url, utf8Bytes } from "./encoding.js";
import { SignerError } from "./errors.js";
import { jcs } from "./jcs.js";

export interface PopChallengeFields {
  borrowerId: string;
  terminalId: string;
  jkt: string;
  nonce: string;
  /** Unix seconds. Server enforces a ±skew window; keep it current. */
  iat: number;
}

/**
 * Untagged JCS challenge bytes (SOHO-74). Deliberately NOT domain-tagged, so it
 * stays byte-compatible with the deployed backend verifier; the voucher preimage
 * carries a tag, which keeps the two signatures non-interchangeable. `iat` is the
 * one numeric field in any signed payload, so it is constrained to a safe integer.
 */
export function buildPopChallengeMessage(fields: PopChallengeFields): Uint8Array {
  if (!Number.isSafeInteger(fields.iat)) {
    throw new SignerError("POP_IAT_NOT_INTEGER", "pop iat must be a safe integer (unix seconds)");
  }
  return utf8Bytes(
    jcs({
      borrowerId: fields.borrowerId,
      terminalId: fields.terminalId,
      jkt: fields.jkt,
      nonce: fields.nonce,
      iat: fields.iat,
    }),
  );
}

/** Signs the PoP challenge with the agent workload key. */
export function signPoP(
  fields: PopChallengeFields,
  privateKeyBase64Url: string,
): { pop_signature: string } {
  const signature = ed25519.sign(
    buildPopChallengeMessage(fields),
    fromBase64Url(privateKeyBase64Url),
  );
  return { pop_signature: toBase64Url(signature) };
}
