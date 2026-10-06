import { isDeepStrictEqual } from "node:util";

import { loadVectors } from "@sohopay/signer-vectors";

import { toHex } from "../encoding.js";
import { SignerError } from "../errors.js";
import { buildPaymentSignatureHeader } from "../envelope.js";
import { jcs } from "../jcs.js";
import { computeJkt } from "../keys.js";
import { buildPopChallengeMessage, signPoP } from "../pop.js";
import {
  buildVoucherSignedBytes,
  computePaymentId,
  signVoucher,
  type AgentPaymentVoucher,
} from "../voucher.js";

export interface VerifySummary {
  passed: number;
  failed: number;
  total: number;
  failures: string[];
}

/**
 * Negative vectors that are backend-verify-only (cross-replay invariants): the
 * client cannot reproduce them, so they are intentionally skipped here. Any
 * negative id NOT handled by the switch and NOT in this set is treated as an
 * unhandled new vector and fails, so coverage can never regress silently.
 */
const BACKEND_ONLY_NEGATIVES = new Set([
  "neg-cross-replay-voucher-as-pop",
  "neg-cross-replay-pop-as-voucher",
]);

/** Runs the full known-answer set in-process. A host calls this to self-certify. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function verifyVectors(doc: any = loadVectors()): VerifySummary {
  const testKey = doc.testKeys[0];
  const failures: string[] = [];
  let passed = 0;

  const check = (id: string, actual: unknown, expected: unknown): void => {
    if (expected === undefined) {
      failures.push(`${id}:no-expected`);
      return;
    }
    if (isDeepStrictEqual(actual, expected)) {
      passed += 1;
    } else {
      failures.push(id);
    }
  };

  const checkThrows = (id: string, fn: () => unknown, expectedCode: unknown): void => {
    try {
      fn();
      failures.push(`${id}:did-not-throw`);
    } catch (e) {
      if (e instanceof SignerError && e.code === expectedCode) passed += 1;
      else failures.push(`${id}:wrong-error`);
    }
  };

  for (const v of doc.vectors.jcs) {
    // Standalone canonicalization, incl. the unicode/NUL edges the voucher
    // payloads don't exercise — asserted directly so a JCS divergence surfaces.
    check(`jcs:${v.id}`, jcs(v.input), v.expected.canonical);
  }
  for (const v of doc.vectors.jkt) {
    check(`jkt:${v.id}`, computeJkt(v.input.publicJwk), v.expected.jkt);
  }
  for (const v of doc.vectors.pop) {
    check(`pop-msg:${v.id}`, toHex(buildPopChallengeMessage(v.input.fields)), v.expected.messageUtf8Hex);
    check(`pop-sig:${v.id}`, signPoP(v.input.fields, testKey.seedB64Url).pop_signature, v.expected.popSignature);
  }
  for (const v of doc.vectors.voucherPaymentId) {
    check(`pid:${v.id}`, computePaymentId(v.input.core), v.expected.paymentId);
  }
  for (const v of doc.vectors.voucherSignature) {
    const voucher = v.input.voucher as AgentPaymentVoucher;
    check(`vsig-pre:${v.id}`, toHex(buildVoucherSignedBytes(voucher)), v.expected.preimageHex);
    check(
      `vsig:${v.id}`,
      signVoucher({
        voucher,
        privateKeyBase64Url: testKey.seedB64Url,
        signing: v.input.signing,
        publicJwk: testKey.publicJwk,
      }).signature,
      v.expected.signature,
    );
  }
  for (const v of doc.vectors.envelope) {
    const { headerName, headerValue } = buildPaymentSignatureHeader(v.input.prepareResponse, v.input.signature);
    check(`env-name:${v.id}`, headerName, v.expected.headerName);
    // Normative byte-exact header_value (standard base64 of the compact completed envelope).
    check(`env-value:${v.id}`, headerValue, v.expected.headerValue);
    check(
      `env-decoded:${v.id}`,
      JSON.parse(Buffer.from(headerValue, "base64").toString("utf8")),
      v.expected.decodedEnvelope,
    );
  }
  for (const v of doc.negative) {
    switch (v.id) {
      case "neg-voucher-field-number":
        checkThrows(v.id, () => computePaymentId(v.input.core), v.expectError);
        break;
      case "neg-pop-iat-float":
        checkThrows(v.id, () => buildPopChallengeMessage(v.input.fields), v.expectError);
        break;
      case "neg-downgrade-algorithm":
        checkThrows(
          v.id,
          () =>
            signVoucher({
              voucher: doc.vectors.voucherSignature[0].input.voucher,
              privateKeyBase64Url: testKey.seedB64Url,
              signing: v.input.signing,
            }),
          v.expectError,
        );
        break;
      case "neg-public-jwk-has-private-d":
        checkThrows(v.id, () => computeJkt(v.input.publicJwk), v.expectError);
        break;
      default:
        // Backend-only cross-replay invariants are skipped by design; anything
        // else is a new negative vector this client doesn't yet assert — fail so
        // it is noticed rather than silently uncovered.
        if (!BACKEND_ONLY_NEGATIVES.has(v.id)) {
          failures.push(`${v.id}:unhandled-negative`);
        }
        break;
    }
  }

  return { passed, failed: failures.length, total: passed + failures.length, failures };
}
