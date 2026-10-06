import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { SignerError } from "../src/errors.js";
import {
  FileOperationStore,
  InMemoryOperationStore,
  advancePhase,
  beginOperation,
  recordPrepared,
  recoveryAction,
  resolveOperation,
} from "../src/operations.js";

function tempDir(): string {
  return mkdtempSync(join(tmpdir(), "soho-ops-"));
}

test("beginOperation starts STARTED with an idempotency key; recovery = RETRY_PREPARE", () => {
  const store = new InMemoryOperationStore();
  const op = beginOperation({ store, borrowerId: "b", orderRef: "o1" });
  assert.equal(op.phase, "STARTED");
  assert.ok(op.idempotencyKey);
  assert.equal(op.attempts, 1);
  assert.equal(recoveryAction(op), "RETRY_PREPARE");
});

test("resuming bumps attempts and keeps the idempotency key", () => {
  const store = new InMemoryOperationStore();
  const a = beginOperation({ store, borrowerId: "b", orderRef: "o1" });
  const b = beginOperation({ store, borrowerId: "b", orderRef: "o1" });
  assert.equal(b.attempts, 2);
  assert.equal(b.idempotencyKey, a.idempotencyKey);
});

test("recordPrepared sets paymentId; recovery = QUERY_STATUS", () => {
  const store = new InMemoryOperationStore();
  beginOperation({ store, borrowerId: "b", orderRef: "o1" });
  const op = recordPrepared({
    store,
    borrowerId: "b",
    orderRef: "o1",
    paymentId: "0xabc",
    agentKeyJkt: "jkt1",
    voucherDeadline: "1760000000",
  });
  assert.equal(op.paymentId, "0xabc");
  assert.equal(recoveryAction(op), "QUERY_STATUS");
});

test("resolveOperation is terminal; recovery = DONE and re-begin returns it unchanged", () => {
  const store = new InMemoryOperationStore();
  beginOperation({ store, borrowerId: "b", orderRef: "o1" });
  const resolved = resolveOperation({ store, borrowerId: "b", orderRef: "o1", status: "CONFIRMED" });
  assert.equal(resolved.terminal, true);
  assert.equal(recoveryAction(resolved), "DONE");
  const again = beginOperation({ store, borrowerId: "b", orderRef: "o1" });
  assert.equal(again.terminal, true);
  assert.equal(again.attempts, 1);
});

test("advancePhase on a missing operation throws OPERATION_NOT_FOUND", () => {
  const store = new InMemoryOperationStore();
  assert.throws(
    () => advancePhase({ store, borrowerId: "b", orderRef: "missing", phase: "SIGNED" }),
    (e) => e instanceof SignerError && e.code === "OPERATION_NOT_FOUND",
  );
});

test("FileOperationStore persists across instances", () => {
  const dir = tempDir();
  try {
    const s1 = new FileOperationStore({ dataDir: dir });
    beginOperation({ store: s1, borrowerId: "b", orderRef: "o1", idempotencyKey: "key-1" });
    recordPrepared({ store: s1, borrowerId: "b", orderRef: "o1", paymentId: "0xabc" });

    const s2 = new FileOperationStore({ dataDir: dir });
    const op = s2.get("b", "o1");
    assert.equal(op?.idempotencyKey, "key-1");
    assert.equal(op?.paymentId, "0xabc");
    assert.equal(s2.list("b").length, 1);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
