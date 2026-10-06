/** Parsed CLI invocation. `input`/`key` are a path or "-" (stdin); undefined = absent. */
export interface ParsedArgs {
  command: string;
  input?: string;
  key?: string;
  output: "json" | "human";
}

/** A caller mistake (unknown command/flag, missing value). Mapped to exit 2. */
export class UsageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UsageError";
  }
}

const KNOWN_COMMANDS = new Set([
  "voucher sign",
  "payment-id",
  "key jkt",
  "pop sign",
  "verify-vectors",
  "capabilities",
]);

function requireValue(argv: string[], index: number, flag: string): string {
  const value = argv[index];
  if (value === undefined) {
    throw new UsageError(`${flag} requires a value`);
  }
  return value;
}

/** Splits argv into a known command (1–2 leading tokens) plus flags. */
export function parseArgs(argv: string[]): ParsedArgs {
  const positionals: string[] = [];
  let input: string | undefined;
  let key: string | undefined;
  let output: "json" | "human" = "human";

  for (let i = 0; i < argv.length; i++) {
    const token = argv[i];
    if (token === "--input") {
      input = requireValue(argv, ++i, "--input");
    } else if (token === "--key") {
      key = requireValue(argv, ++i, "--key");
    } else if (token === "--output") {
      const value = requireValue(argv, ++i, "--output");
      if (value !== "json" && value !== "human") {
        throw new UsageError(`--output must be "json" or "human", got "${value}"`);
      }
      output = value;
    } else if (token !== undefined && token.startsWith("--")) {
      throw new UsageError(`unknown flag: ${token}`);
    } else if (token !== undefined) {
      positionals.push(token);
    }
  }

  const twoToken = positionals.slice(0, 2).join(" ");
  const oneToken = positionals[0] ?? "";
  let command: string;
  if (KNOWN_COMMANDS.has(twoToken)) {
    command = twoToken;
  } else if (KNOWN_COMMANDS.has(oneToken)) {
    command = oneToken;
  } else {
    throw new UsageError(`unknown command: ${positionals.join(" ") || "(none)"}`);
  }

  return { command, input, key, output };
}

/** True when this invocation reads stdin — "-" is the only stdin sentinel (an --input/--key value). */
export function needsStdin(argv: string[]): boolean {
  return argv.includes("-");
}
