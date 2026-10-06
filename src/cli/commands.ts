import { readFileSync } from "node:fs";

import { IMPLEMENTATION, SIGNER_PROTOCOL, SUPPORTED_SIGNING } from "../constants.js";

/** Reads this package's version from package.json, relative to the module. */
export function implementationVersion(): string {
  const pkg = JSON.parse(
    readFileSync(new URL("../../package.json", import.meta.url), "utf8"),
  ) as { version?: string };
  return pkg.version ?? "0.0.0";
}

const COMMANDS = ["voucher sign", "payment-id", "key jkt", "pop sign", "verify-vectors", "capabilities"];

/** Static advertisement SP5 routing probes to confirm a usable signer. */
export function capabilitiesResult(): Record<string, unknown> {
  return {
    signer_protocol: SIGNER_PROTOCOL,
    implementation: IMPLEMENTATION,
    implementation_version: implementationVersion(),
    algorithms: [SUPPORTED_SIGNING.algorithm],
    commands: COMMANDS,
  };
}
