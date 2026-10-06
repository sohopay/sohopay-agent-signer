import canonicalize from "canonicalize";

/**
 * RFC 8785 JSON Canonicalization Scheme. Uses the same `canonicalize` package
 * (exact-pinned) as the backend so preimages are byte-identical. Throws rather
 * than returning an empty string on non-canonicalizable input (undefined,
 * functions) — an empty preimage would hash/sign deterministically to a value
 * no verifier expects.
 */
export function jcs(value: unknown): string {
  const canonical = canonicalize(value);
  if (canonical === undefined) {
    throw new Error("JCS canonicalization produced undefined");
  }
  return canonical;
}
