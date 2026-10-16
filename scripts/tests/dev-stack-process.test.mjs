import test from "node:test";
import assert from "node:assert/strict";
import { sameProcess, signalOwnedGroup, signalOwnedProcess, processIdentity, assertGroupsGone } from "../dev-stack-process.mjs";

const original = { pid: 23001, pgid: 23001, startId: "boot:12345" };

test("ownership requires creation identity and a dedicated process group", () => {
  assert.equal(sameProcess(original, { ...original }), true);
  for (const changed of [null, { ...original, startId: "boot:54321" }, { ...original, pgid: 10 }, { ...original, pid: 9 }]) {
    assert.equal(sameProcess(original, changed), false);
  }
  assert.equal(sameProcess({ ...original, pgid: 9 }, { ...original, pgid: 9 }), false);
});

test("PID reuse refuses every signal, including escalation", () => {
  for (const signal of ["SIGTERM", "SIGKILL"]) {
    let calls = 0;
    assert.throws(() => signalOwnedGroup(original, signal, {
      inspect: () => ({ ...original, startId: "other-creation" }), kill: () => calls++
    }), /identity changed/);
    assert.equal(calls, 0);
  }
});

test("only an observed matching private group receives a supported signal", () => {
  const calls = [];
  assert.equal(signalOwnedGroup(original, "SIGTERM", { inspect: () => original, kill: (...args) => calls.push(args) }), true);
  assert.deepEqual(calls, [[-23001, "SIGTERM"]]);
  assert.equal(signalOwnedGroup(original, "SIGKILL", { inspect: () => null, kill: () => assert.fail() }), false);
  assert.throws(() => signalOwnedGroup(original, "SIGINT", { inspect: () => original, kill: () => assert.fail() }), /Unsupported/);
});

test("invalid persisted PIDs are rejected before OS inspection", () => {
  for (const value of [undefined, null, 0, 1, -23, 2.5, "23"]) assert.throws(() => processIdentity(value), /Invalid/);
});

test("a dead leader or permission error must not disguise a remaining group", () => {
  assert.throws(() => assertGroupsGone([original], { kill: () => {} }), /remains/);
  assert.doesNotThrow(() => assertGroupsGone([original], { kill: () => { throw Object.assign(new Error(), { code: "ESRCH" }); } }));
  assert.throws(() => assertGroupsGone([original], { kill: () => { throw Object.assign(new Error("denied"), { code: "EPERM" }); } }), /denied/);
  assert.throws(() => assertGroupsGone([{ ...original, pgid: 1 }], { kill: () => assert.fail() }), /Invalid/);
});

test("supervisor teardown signals only its own birth-checked PID, not the caller's shared group", () => {
  const supervisor = { pid: 23001, pgid: 22000, startId: "boot:12345" };
  const calls = [];
  signalOwnedProcess(supervisor, "SIGTERM", { inspect: () => supervisor, kill: (...args) => calls.push(args) });
  assert.deepEqual(calls, [[23001, "SIGTERM"]]);
  assert.throws(() => signalOwnedProcess(supervisor, "SIGKILL", {
    inspect: () => ({ ...supervisor, startId: "other-birth" }), kill: () => assert.fail()
  }), /creation identity changed/);
});
