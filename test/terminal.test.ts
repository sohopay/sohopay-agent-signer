import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { SignerError } from "../src/errors.js";
import { assertValidTerminalId, resolveTerminalId, TERMINAL_ID_MAX_LENGTH } from "../src/terminal.js";

const isTerminalIdError = (e: unknown): boolean =>
  e instanceof SignerError && e.code === "INVALID_TERMINAL_ID";

function tempDir(): string {
  return mkdtempSync(join(tmpdir(), "soho-term-"));
}

test("explicit terminal id is validated and returned", () => {
  assert.equal(resolveTerminalId({ explicit: "host:abc-123" }), "host:abc-123");
});

test("invalid terminal id throws INVALID_TERMINAL_ID", () => {
  assert.throws(() => assertValidTerminalId("has space"), isTerminalIdError);
  assert.throws(() => assertValidTerminalId("__adopted__"), isTerminalIdError);
  assert.throws(() => assertValidTerminalId("x".repeat(TERMINAL_ID_MAX_LENGTH + 1)), isTerminalIdError);
});

test("persists and reuses a minted terminal id", () => {
  const dir = tempDir();
  try {
    const first = resolveTerminalId({ dataDir: dir });
    const second = resolveTerminalId({ dataDir: dir });
    assert.equal(first, second);
    assert.match(first, /^[a-z0-9._:@-]+:[0-9a-f-]{36}$/i);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("SOHO_TERMINAL_ID env takes precedence over persisted", () => {
  const dir = tempDir();
  const prev = process.env.SOHO_TERMINAL_ID;
  process.env.SOHO_TERMINAL_ID = "env:terminal-1";
  try {
    assert.equal(resolveTerminalId({ dataDir: dir }), "env:terminal-1");
  } finally {
    if (prev === undefined) {
      delete process.env.SOHO_TERMINAL_ID;
    } else {
      process.env.SOHO_TERMINAL_ID = prev;
    }
    rmSync(dir, { recursive: true, force: true });
  }
});
