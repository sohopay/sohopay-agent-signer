#!/usr/bin/env node
import { readFileSync } from "node:fs";

import { needsStdin } from "./args.js";
import { run } from "./run.js";

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
if (result.stdout) {
  process.stdout.write(result.stdout);
}
if (result.stderr) {
  process.stderr.write(result.stderr);
}
process.exitCode = result.exitCode;
