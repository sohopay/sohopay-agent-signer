/** Typed error taxonomy. Hosts (S12) use `code` to tell terminal from retryable. */
export type SignerErrorCode =
  | "VOUCHER_FIELD_NOT_STRING"
  | "POP_IAT_NOT_INTEGER"
  | "SIGNING_SCHEME_NOT_ALLOWED"
  | "PRIVATE_KEY_MATERIAL_REJECTED"
  | "INVALID_PUBLIC_JWK"
  | "PAYMENT_ID_MISMATCH"
  | "AGENT_KEY_JKT_MISMATCH"
  | "MALFORMED_ENVELOPE"
  | "INVALID_TERMINAL_ID"
  | "INVALID_BORROWER_ID"
  | "INSECURE_KEY_PERMISSIONS"
  | "STORED_KEY_CORRUPT"
  | "IDEMPOTENCY_PAYLOAD_MISMATCH";

/** All SDK-raised failures carry a stable `code` from {@link SignerErrorCode}. */
export class SignerError extends Error {
  readonly code: SignerErrorCode;

  constructor(code: SignerErrorCode, message: string) {
    super(message);
    this.name = "SignerError";
    this.code = code;
  }
}
