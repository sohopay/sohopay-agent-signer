import { chmodSync, writeFileSync } from "node:fs";

import { parseArgs, UsageError } from "./args.js";
import { capabilitiesResult, keyJktResult, paymentIdResult, popSignResult, verifyVectorsResult, voucherSignEnvelopeResult, voucherSignResult } from "./commands.js";
import { readInput } from "./io.js";
import { assertInputSchema, assertOutputSchema } from "./io-schema.js";
import { keyGenerateResult } from "./key-generate.js";
import { SignerError } from "../errors.js";

export interface CliResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

/** Renders a result object as human-readable `key: value` lines (never secrets). */
function toHuman(result: Record<string, unknown>): string {
  return (
    Object.entries(result)
      .map(([k, v]) => `${k}: ${typeof v === "string" ? v : JSON.stringify(v)}`)
      .join("\n") + "\n"
  );
}

function format(result: Record<string, unknown>, output: "json" | "human"): string {
  return output === "json" ? JSON.stringify(result) : toHuman(result);
}

/**
 * Pure orchestrator: parse → dispatch → format. Never throws; every failure is
 * mapped to a CliResult. Usage errors exit 2 (plain stderr); SignerError and
 * other operational failures exit 1 with a machine error envelope on stderr.
 */
export function run(argv: string[], stdin: string): CliResult {
  try {
    const parsed = parseArgs(argv);

    if (parsed.input === "-" && parsed.key === "-") {
      throw new UsageError("--input and --key cannot both read stdin");
    }

    if ((parsed.envelope || parsed.writeHeader !== undefined) && parsed.command !== "voucher sign") {
      throw new UsageError("--envelope and --write-header are only valid for `voucher sign`");
    }
    if (parsed.writeHeader !== undefined && !parsed.envelope) {
      throw new UsageError("--write-header requires --envelope");
    }

    let result: Record<string, unknown>;
    switch (parsed.command) {
      case "capabilities":
        result = capabilitiesResult();
        break;
      case "payment-id":
        result = paymentIdResult(readInput(parsed.input, stdin));
        break;
      case "key jkt":
        result = keyJktResult(readInput(parsed.input, stdin));
        break;
      case "voucher sign":
        if (parsed.envelope) {
          result = voucherSignEnvelopeResult(readInput(parsed.input, stdin), parsed.key, stdin);
          if (parsed.writeHeader !== undefined) {
            const headerName = result.header_name;
            const headerValue = result.header_value;
            if (typeof headerName !== "string" || typeof headerValue !== "string") {
              throw new SignerError("MALFORMED_ENVELOPE", "internal: header fields missing");
            }
            // Write a curl-ready header line ("<name>: <value>\n") BEFORE stdout, so the
            // value can be replayed with `curl -H @<file>` without ever entering a shell
            // argument or the model's context, and a failed write leaves no mismatched stdout.
            try {
              // mode 0600: the header line is a replayable credential until expiry.
              writeFileSync(parsed.writeHeader, `${headerName}: ${headerValue}\n`, {
                encoding: "utf8",
                mode: 0o600,
              });
              // writeFileSync's `mode` is honored only when it creates the file; a
              // pre-existing path keeps its old (possibly world-readable) perms, so
              // tighten unconditionally — the line is a replayable credential.
              chmodSync(parsed.writeHeader, 0o600);
            } catch {
              throw new SignerError("MALFORMED_ENVELOPE", `cannot write header file: ${parsed.writeHeader}`);
            }
          }
        } else {
          result = voucherSignResult(readInput(parsed.input, stdin), parsed.key, stdin);
        }
        break;
      case "key generate": {
        const input = readInput(parsed.input, stdin);
        assertInputSchema("key generate", input);
        result = keyGenerateResult(input, parsed.out);
        assertOutputSchema("key generate", result);
        break;
      }
      case "pop sign": {
        const input = readInput(parsed.input, stdin);
        assertInputSchema("pop sign", input);
        result = popSignResult(input, parsed.key, stdin);
        assertOutputSchema("pop sign", result);
        break;
      }
      case "verify-vectors": {
        const { result: summary, ok } = verifyVectorsResult();
        return { stdout: format(summary, parsed.output), stderr: "", exitCode: ok ? 0 : 1 };
      }
      default:
        // Later tasks add the signing/read commands here.
        throw new UsageError(`command not implemented: ${parsed.command}`);
    }

    return { stdout: format(result, parsed.output), stderr: "", exitCode: 0 };
  } catch (error) {
    if (error instanceof UsageError) {
      return { stdout: "", stderr: `${error.message}\n`, exitCode: 2 };
    }
    const code = error instanceof SignerError ? error.code : "MALFORMED_ENVELOPE";
    const message = error instanceof Error ? error.message : String(error);
    return {
      stdout: "",
      stderr: `${JSON.stringify({ error: { code, message } })}\n`,
      exitCode: 1,
    };
  }
}
