/** Parsed CLI invocation. `input`/`key` are a path or "-" (stdin); undefined = absent. */
export interface ParsedArgs {
  command: string;
  input?: string;
  key?: string;
  output: "json" | "human";
  envelope: boolean;
  writeHeader?: string;
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
  let envelope = false;
  let writeHeader: string | undefined;

  for (let i = 0; i < argv.length; i++) {
    const token = argv[i];
    if (token === undefined) {
      continue;
    }
    if (token.startsWith("--")) {
      // Accept both `--flag value` and `--flag=value`.
      const eq = token.indexOf("=");
      const name = eq === -1 ? token : token.slice(0, eq);
      const inlineValue = eq === -1 ? undefined : token.slice(eq + 1);
      const valueOf = (flag: string): string =>
        inlineValue ?? requireValue(argv, ++i, flag);
      if (name === "--input") {
        input = valueOf("--input");
      } else if (name === "--key") {
        key = valueOf("--key");
      } else if (name === "--output") {
        const value = valueOf("--output");
        if (value !== "json" && value !== "human") {
          throw new UsageError(`--output must be "json" or "human", got "${value}"`);
        }
        output = value;
      } else if (name === "--envelope") {
        envelope = true; // boolean flag; any inline value is ignored
      } else if (name === "--write-header") {
        writeHeader = valueOf("--write-header");
      } else {
        throw new UsageError(`unknown flag: ${name}`);
      }
    } else {
      positionals.push(token);
    }
  }

  const twoToken = positionals.slice(0, 2).join(" ");
  const oneToken = positionals[0] ?? "";
  let command: string;
  let commandTokens: number;
  if (KNOWN_COMMANDS.has(twoToken)) {
    command = twoToken;
    commandTokens = 2;
  } else if (KNOWN_COMMANDS.has(oneToken)) {
    command = oneToken;
    commandTokens = 1;
  } else {
    throw new UsageError(`unknown command: ${positionals.join(" ") || "(none)"}`);
  }

  if (positionals.length > commandTokens) {
    throw new UsageError(`unexpected argument: ${positionals[commandTokens]}`);
  }

  return { command, input, key, output, envelope, writeHeader };
}

/** True when this invocation reads stdin — "-" is the stdin sentinel for --input/--key (space- or `=`-separated). */
export function needsStdin(argv: string[]): boolean {
  return argv.some(
    (token) => token === "-" || token === "--input=-" || token === "--key=-",
  );
}
