import { loadVectors } from "@sohopay/signer-vectors";

import { toHex } from "../encoding.js";
import { buildPaymentSignatureHeader } from "../envelope.js";
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

/** Runs the full known-answer set in-process. A host calls this to self-certify. */
export function verifyVectors(): VerifySummary {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const doc = loadVectors() as any;
  const testKey = doc.testKeys[0];
  const failures: string[] = [];
  let passed = 0;

  const check = (id: string, actual: unknown, expected: unknown): void => {
    if (JSON.stringify(actual) === JSON.stringify(expected)) {
      passed += 1;
    } else {
      failures.push(id);
    }
  };

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
    check(
      `env-decoded:${v.id}`,
      JSON.parse(Buffer.from(headerValue, "base64").toString("utf8")),
      v.expected.decodedEnvelope,
    );
  }

  return { passed, failed: failures.length, total: passed + failures.length, failures };
}
