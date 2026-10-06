import assert from "node:assert/strict";
import { test } from "node:test";

import {
  executePayment,
  type HostTransport,
  type PrepareResult,
  type SettlementStatus,
} from "../src/flow.js";
import { generateWorkloadKey } from "../src/keys.js";
import { InMemoryOperationStore, beginOperation, recordPrepared, resolveOperation } from "../src/operations.js";
import { computePaymentId } from "../src/voucher.js";

const key = generateWorkloadKey();

function makeVoucher() {
  const core = {
    agentId: "agent-1",
    merchantId: `0x${"5f".repeat(32)}`,
    asset: `0x${"ab".repeat(20)}`,
    chainId: "8453",
    amount: "1000000",
    feeAmount: "5000",
    orderRef: `0x${"9d".repeat(32)}`,
    nonce: "1",
    deadline: String(Math.floor(Date.now() / 1000) + 3600),
  };
  const voucher = { ...core, paymentId: computePaymentId(core), agentKeyJkt: key.jkt };
  const prepareResponse = { x402Version: 2, paymentPayload: { payload: { voucher, signature: null } } };
  return { voucher, prepareResponse };
}

class FakeTransport implements HostTransport {
  prepareCalls = 0;
  submitCalls = 0;
  statusCalls = 0;
  lastHeaderValue?: string;

  constructor(private readonly cfg: { prepareResult: PrepareResult; status: SettlementStatus }) {}

  async prepare(): Promise<PrepareResult> {
    this.prepareCalls += 1;
    return this.cfg.prepareResult;
  }

  async submit(input: { paymentId: string; headerName: string; headerValue: string }): Promise<void> {
    this.submitCalls += 1;
    this.lastHeaderValue = input.headerValue;
  }

  async getStatus(): Promise<SettlementStatus> {
    this.statusCalls += 1;
    return this.cfg.status;
  }
}

test("happy path: prepare → sign → submit → resolve terminal", async () => {
  const store = new InMemoryOperationStore();
  const { voucher, prepareResponse } = makeVoucher();
  const t = new FakeTransport({
    prepareResult: { status: "VOUCHER_ISSUED", voucher, prepareResponse },
    status: { status: "CONFIRMED", terminal: true },
  });

  const r = await executePayment({
    transport: t,
    store,
    borrowerId: "b",
    orderRef: "o1",
    privateKeyBase64Url: key.privateKeyBase64Url,
    publicJwk: key.publicJwk,
  });

  assert.equal(r.terminal, true);
  assert.equal(r.status, "CONFIRMED");
  assert.equal(r.paymentId, voucher.paymentId);
  assert.equal(t.prepareCalls, 1);
  assert.equal(t.submitCalls, 1);
  assert.ok(t.lastHeaderValue);
  assert.equal(store.get("b", "o1")?.terminal, true);
});

test("recovery: a resumed op with a voucher queries status and never re-prepares", async () => {
  const store = new InMemoryOperationStore();
  beginOperation({ store, borrowerId: "b", orderRef: "o1" });
  recordPrepared({ store, borrowerId: "b", orderRef: "o1", paymentId: "0xdead" });
  const { voucher, prepareResponse } = makeVoucher();
  const t = new FakeTransport({
    prepareResult: { status: "VOUCHER_ISSUED", voucher, prepareResponse },
    status: { status: "PENDING", terminal: false },
  });

  const r = await executePayment({
    transport: t,
    store,
    borrowerId: "b",
    orderRef: "o1",
    privateKeyBase64Url: key.privateKeyBase64Url,
  });

  assert.equal(t.prepareCalls, 0);
  assert.equal(t.statusCalls, 1);
  assert.equal(t.submitCalls, 0);
  assert.equal(r.paymentId, "0xdead");
  assert.equal(r.terminal, false);
  assert.equal(r.status, "PENDING");
});

test("a terminal op returns DONE with no transport calls", async () => {
  const store = new InMemoryOperationStore();
  beginOperation({ store, borrowerId: "b", orderRef: "o1" });
  resolveOperation({ store, borrowerId: "b", orderRef: "o1", status: "CONFIRMED" });
  const { voucher, prepareResponse } = makeVoucher();
  const t = new FakeTransport({
    prepareResult: { status: "VOUCHER_ISSUED", voucher, prepareResponse },
    status: { status: "x", terminal: true },
  });

  const r = await executePayment({
    transport: t,
    store,
    borrowerId: "b",
    orderRef: "o1",
    privateKeyBase64Url: key.privateKeyBase64Url,
  });

  assert.equal(t.prepareCalls, 0);
  assert.equal(t.statusCalls, 0);
  assert.equal(r.terminal, true);
  assert.equal(r.status, "CONFIRMED");
});

test("a non-voucher prepare resolves terminal without signing or submitting", async () => {
  const store = new InMemoryOperationStore();
  const t = new FakeTransport({
    prepareResult: { status: "FAILED" },
    status: { status: "unused", terminal: true },
  });

  const r = await executePayment({
    transport: t,
    store,
    borrowerId: "b",
    orderRef: "o1",
    privateKeyBase64Url: key.privateKeyBase64Url,
  });

  assert.equal(r.terminal, true);
  assert.equal(r.status, "FAILED");
  assert.equal(t.submitCalls, 0);
  assert.equal(store.get("b", "o1")?.terminal, true);
});
