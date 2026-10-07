import { SignerError } from "../errors.js";

const INPUT_ALLOW: Record<string, { top: string[]; fields?: string[] }> = {
  "pop sign": { top: ["fields"], fields: ["borrowerId", "terminalId", "jkt"] },
  "key generate": { top: ["borrower_id", "terminal_id"] },
};

const OUTPUT_ALLOW: Record<string, string[]> = {
  "key generate": ["public_jwk", "jkt", "borrower_id", "terminal_id", "created"],
  "pop sign": ["signer_protocol", "implementation", "implementation_version", "pop_signature", "nonce", "iat", "algorithm"],
};

function keysOutside(obj: Record<string, unknown>, allow: string[]): string[] {
  return Object.keys(obj).filter((k) => !allow.includes(k));
}

export function assertInputSchema(command: string, input: unknown): void {
  const spec = INPUT_ALLOW[command];
  if (!spec) return;
  if (input === null || typeof input !== "object") {
    throw new SignerError("MALFORMED_INPUT", `${command} input must be an object`);
  }
  const rec = input as Record<string, unknown>;
  const extraTop = keysOutside(rec, spec.top);
  if (extraTop.length > 0) {
    throw new SignerError("MALFORMED_INPUT", `${command}: unexpected input field(s): ${extraTop.join(", ")}`);
  }
  if (spec.fields) {
    const fields = rec.fields;
    if (fields === null || typeof fields !== "object") {
      throw new SignerError("MALFORMED_INPUT", `${command} requires a \`fields\` object`);
    }
    const extra = keysOutside(fields as Record<string, unknown>, spec.fields);
    if (extra.length > 0) {
      throw new SignerError("MALFORMED_INPUT", `${command}: unexpected field(s): ${extra.join(", ")}`);
    }
  }
}

export function assertOutputSchema(command: string, output: Record<string, unknown>): void {
  const allow = OUTPUT_ALLOW[command];
  if (!allow) return;
  const extra = keysOutside(output, allow);
  if (extra.length > 0) {
    throw new Error(`internal: ${command} output leaked field(s): ${extra.join(", ")}`);
  }
}
