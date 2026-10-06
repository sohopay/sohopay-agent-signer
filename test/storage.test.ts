import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, rmSync, statSync } from "node:fs";
import { platform, tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { SignerError } from "../src/errors.js";
import { loadOrCreateWorkloadKey, loadWorkloadKey } from "../src/storage.js";

function tempDir(): string {
  return mkdtempSync(join(tmpdir(), "soho-store-"));
}

test("creates then reloads the same borrower key", () => {
  const dir = tempDir();
  try {
    const created = loadOrCreateWorkloadKey({ borrowerId: "b-1", terminalId: "host:t", dataDir: dir });
    const reloaded = loadOrCreateWorkloadKey({ borrowerId: "b-1", terminalId: "host:t", dataDir: dir });
    assert.equal(created.jkt, reloaded.jkt);
    assert.equal(created.private_key_base64url, reloaded.private_key_base64url);
    assert.ok(loadWorkloadKey({ borrowerId: "b-1", expectedJkt: created.jkt, dataDir: dir }));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a second borrower gets a distinct key and does not overwrite the first", () => {
  const dir = tempDir();
  try {
    const a = loadOrCreateWorkloadKey({ borrowerId: "b-A", terminalId: "host:t", dataDir: dir });
    const b = loadOrCreateWorkloadKey({ borrowerId: "b-B", terminalId: "host:t", dataDir: dir });
    assert.notEqual(a.jkt, b.jkt);
    assert.equal(loadWorkloadKey({ borrowerId: "b-A", dataDir: dir })?.jkt, a.jkt);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("expectedJkt mismatch returns undefined (caller regenerates)", () => {
  const dir = tempDir();
  try {
    loadOrCreateWorkloadKey({ borrowerId: "b-1", terminalId: "host:t", dataDir: dir });
    assert.equal(loadWorkloadKey({ borrowerId: "b-1", expectedJkt: "not-the-jkt", dataDir: dir }), undefined);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("invalid borrower id throws INVALID_BORROWER_ID", () => {
  const dir = tempDir();
  try {
    assert.throws(
      () => loadOrCreateWorkloadKey({ borrowerId: "../escape", terminalId: "host:t", dataDir: dir }),
      (e) => e instanceof SignerError && e.code === "INVALID_BORROWER_ID",
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test(
  "saved secret is 0600 and a loosened file is refused",
  { skip: platform() === "win32" },
  () => {
    const dir = tempDir();
    try {
      loadOrCreateWorkloadKey({ borrowerId: "b-1", terminalId: "host:t", dataDir: dir });
      const path = join(dir, "agent-workload", "b-1", "secret.json");
      assert.equal(statSync(path).mode & 0o777, 0o600);
      chmodSync(path, 0o644);
      assert.throws(
        () => loadWorkloadKey({ borrowerId: "b-1", dataDir: dir }),
        (e) => e instanceof SignerError && e.code === "INSECURE_KEY_PERMISSIONS",
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  },
);
