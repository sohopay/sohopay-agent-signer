/** Byte/string encoding helpers, centralized so every preimage uses the same ones. */

export const toBase64Url = (bytes: Uint8Array): string =>
  Buffer.from(bytes).toString("base64url");

export const fromBase64Url = (value: string): Uint8Array =>
  new Uint8Array(Buffer.from(value, "base64url"));

export const toHex = (bytes: Uint8Array): string =>
  Buffer.from(bytes).toString("hex");

export const utf8Bytes = (value: string): Uint8Array =>
  new Uint8Array(Buffer.from(value, "utf8"));
