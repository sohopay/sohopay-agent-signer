import { parseArgs, UsageError } from "./args.js";
import { capabilitiesResult, keyJktResult, paymentIdResult, voucherSignResult } from "./commands.js";
import { readInput } from "./io.js";
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
        result = voucherSignResult(readInput(parsed.input, stdin), parsed.key, stdin);
        break;
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
