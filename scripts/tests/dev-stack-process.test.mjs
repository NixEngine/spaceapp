import test from "node:test";
import assert from "node:assert/strict";
import { sameProcess, signalOwnedGroup, signalOwnedProcess, processIdentity, assertGroupsGone } from "../dev-stack-process.mjs";
import { parseCwdRecords, darwinStateCwdProcesses } from "../dev-stack-process.mjs";
import { resolve, join } from "node:path";

const original = { pid: 23001, pgid: 23001, startId: "boot:12345" };

test("NUL cwd records bind each path to its PID and exclude sibling prefixes", () => {
  const state = resolve("isolated state");
  const output = `p23001\0\nfcwd\0n${state}\0\np23002\0\nfcwd\0n${join(state, "child with spaces")}\0\np23003\0\nfcwd\0n${state}-foreign\0\n`;
  assert.deepEqual(parseCwdRecords(output, state), [23001, 23002]);
  assert.deepEqual(parseCwdRecords("", state), []);
  assert.throws(() => parseCwdRecords(`n${state}\0`, state), /Unbound/u);
  assert.throws(() => parseCwdRecords(`pnot-a-pid\0`, state), /Invalid/u);
  assert.throws(() => parseCwdRecords(`p23001\0cunexpected\0`, state), /Unexpected/u);
});

test("Darwin cwd scanner requests only the selected user's cwd, not recursive paths", () => {
  const state = resolve("isolated-state");
  assert.deepEqual(darwinStateCwdProcesses(state, { uid: 501, execute: (command, args) => {
    assert.equal(command, "lsof");
    assert.deepEqual(args, ["-nP", "-a", "-u", "501", "-d", "cwd", "-F0pfn"]);
    return { status: 0, stdout: `p23001\0\nfcwd\0n${state}\0\n`, stderr: "" };
  } }), [23001]);
});

test("Darwin cwd no-match is distinct from failed or denied observation", () => {
  const state = resolve("isolated-state");
  assert.deepEqual(darwinStateCwdProcesses(state, { uid: 501, execute: () => ({ status: 1, stdout: "", stderr: "" }) }), []);
  for (const observation of [{ error: { code: "ENOENT" } }, { status: 1, stderr: "permission denied", stdout: "" },
    { status: 2, stdout: "", stderr: "" }, { status: 0, stdout: "", stderr: "partial permission failure" }]) {
    assert.throws(() => darwinStateCwdProcesses(state, { uid: 501, execute: () => observation }), /not certified/u);
  }
  assert.throws(() => darwinStateCwdProcesses(state, { uid: -1, execute: () => assert.fail() }), /identity/u);
});

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
