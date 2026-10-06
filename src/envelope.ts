import { PAYMENT_SIGNATURE_HEADER } from "./constants.js";
import { SignerError } from "./errors.js";

/** Minimal shape the SDK fills — matches the prepare-response envelope. */
interface X402Envelope {
  paymentPayload?: { payload?: { signature?: unknown } };
}

export interface PaymentSignatureHeader {
  headerName: string;
  headerValue: string;
  envelope: unknown;
}

/**
 * Fills `paymentPayload.payload.signature` on a clone of the prepare response and
 * base64-encodes it into the PAYMENT-SIGNATURE header. The signature is bound by
 * JCS(voucher), so envelope key ordering here is not security-relevant.
 */
export function buildPaymentSignatureHeader(
  prepareResponse: unknown,
  signature: string,
): PaymentSignatureHeader {
  if (prepareResponse === null || typeof prepareResponse !== "object") {
    throw new SignerError("MALFORMED_ENVELOPE", "prepare response must be an object");
  }
  const envelope = structuredClone(prepareResponse) as X402Envelope;
  const payload = envelope.paymentPayload?.payload;
  if (!payload) {
    throw new SignerError(
      "MALFORMED_ENVELOPE",
      "prepare response missing paymentPayload.payload",
    );
  }
  payload.signature = signature;
  const headerValue = Buffer.from(JSON.stringify(envelope), "utf8").toString("base64");
  return { headerName: PAYMENT_SIGNATURE_HEADER, headerValue, envelope };
}
