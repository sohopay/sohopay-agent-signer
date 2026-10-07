#!/usr/bin/env node
import { assertNodeFloor } from "./node-floor.js";

// ESM hoists static imports, so only the guard is imported statically; everything that may
// touch Node-18-only APIs is loaded dynamically after the check.
try {
  assertNodeFloor(process.versions.node);
} catch (e) {
  const code = (e as { code?: string }).code ?? "NODE_VERSION_UNSUPPORTED";
  process.stderr.write(JSON.stringify({ error: { code, message: (e as Error).message } }) + "\n");
  process.exit(1);
}

const { readFileSync } = await import("node:fs");
const { needsStdin } = await import("./args.js");
const { run } = await import("./run.js");

/** Reads all of stdin synchronously (fd 0). Empty string when nothing is piped. */
function readStdin(): string {
  try {
    return readFileSync(0, "utf8");
  } catch {
    return "";
  }
}

const argv = process.argv.slice(2);
const stdin = needsStdin(argv) ? readStdin() : "";
const result = run(argv, stdin);
if (result.stdout) process.stdout.write(result.stdout);
if (result.stderr) process.stderr.write(result.stderr);
process.exitCode = result.exitCode;
