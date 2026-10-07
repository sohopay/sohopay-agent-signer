/**
 * How the CLI tests spawn the signer. Default: the source via tsx (no build needed, matches
 * the existing suite). SOHOPAY_SIGNER_BIN=<path> runs that file with node instead (the bundle
 * parity pass points it at dist-bundle/sohopay-signer.mjs).
 */
export function cliInvocation(): { cmd: string; prefix: string[] } {
  const bin = process.env.SOHOPAY_SIGNER_BIN;
  if (bin && bin.length > 0) return { cmd: "node", prefix: [bin] };
  return { cmd: "node", prefix: ["--import", "tsx", "src/cli/index.ts"] };
}
