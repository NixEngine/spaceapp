import test from "node:test";
import assert from "node:assert/strict";
import { sameProcess, signalOwnedGroup, signalOwnedProcess, processIdentity, assertGroupsGone,
  createShutdownSignals, waitGroupsGone, verifyShutdownGroups } from "../dev-stack-process.mjs";
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

test("shutdown signals once before a post-signal identity transition, without certifying group absence", () => {
  const receipt = Object.freeze({ ...original });
  let observation = { ...original }, signals = 0, inspections = 0;
  const shutdown = createShutdownSignals({ signalGroup: record => signalOwnedGroup(record, "SIGTERM", {
    inspect: () => { inspections++; return observation; }, kill: () => { signals++; }
  }) });
  shutdown.signalAll([receipt]);
  observation = { ...original, startId: "same-pid-command-changed-after-signal" };
  shutdown.signalAll([receipt]);
  shutdown.signalAll([receipt]);
  assert.equal(signals, 1); assert.equal(inspections, 1);
  assert.deepEqual(shutdown.failures(), []);
  assert.throws(() => assertGroupsGone([receipt], { kill: () => {} }), /remains/);
});

test("a first shutdown mismatch or probe failure is retained, never hidden by a later pass", () => {
  const mismatch = new Error("original mismatch"), denied = Object.assign(new Error("original denied"), { code: "EPERM" });
  for (const failure of [mismatch, denied]) {
    const receipt = Object.freeze({ ...original });
    let calls = 0;
    const shutdown = createShutdownSignals({ signalGroup: () => { calls++; throw failure; } });
    shutdown.signalAll([receipt]); shutdown.signalAll([receipt]);
    assert.equal(calls, 1);
    assert.equal(shutdown.failures()[0].error, failure);
    assert.equal(shutdown.failures()[0].record, receipt);
  }
  let kills = 0;
  const receipt = Object.freeze({ ...original });
  const guarded = createShutdownSignals({ signalGroup: record => signalOwnedGroup(record, "SIGTERM", {
    inspect: () => ({ ...original, startId: "foreign-creation" }), kill: () => { kills++; }
  }) });
  guarded.signalAll([receipt]); guarded.signalAll([receipt]);
  assert.equal(kills, 0);
  assert.match(guarded.failures()[0].error.message, /identity changed/);
});

test("an absent leader still requires group disappearance and a new receipt is not cached", () => {
  let calls = 0;
  const receipt = Object.freeze({ ...original });
  const shutdown = createShutdownSignals({ signalGroup: () => { calls++; return false; } });
  shutdown.signalAll([receipt]); shutdown.signalAll([receipt]);
  assert.equal(calls, 1);
  assert.throws(() => assertGroupsGone([receipt], { kill: () => {} }), /remains/);
  shutdown.signalAll([Object.freeze({ ...receipt, startId: "different-launch" })]);
  assert.equal(calls, 2);
});

test("a reentrant shutdown callback cannot repeat the same in-flight signal", () => {
  const receipt = Object.freeze({ ...original });
  let calls = 0, shutdown;
  shutdown = createShutdownSignals({ signalGroup: () => { calls++; shutdown.signalAll([receipt]); return true; } });
  shutdown.signalAll([receipt]); assert.equal(calls, 1); assert.deepEqual(shutdown.failures(), []);
});

function virtualGroupWait() {
  let now = 0;
  const sleeps = [];
  return { sleeps, clock: () => now, pause: async milliseconds => { sleeps.push(milliseconds); now += milliseconds; } };
}

test("EPERM is retried only until a fresh full pass observes ESRCH for every group", async () => {
  const second = { ...original, pid: 23002, pgid: 23002 };
  const timing = virtualGroupWait(), observations = [];
  let passes = 0;
  await waitGroupsGone([original, second], { ...timing,
    assertGone: records => {
      passes++;
      assertGroupsGone(records, { kill: (pgid, signal) => {
        observations.push([passes, pgid, signal]);
        if (passes === 1 && pgid === -second.pgid) throw Object.assign(new Error("probe denied"), { code: "EPERM" });
        throw Object.assign(new Error("absent"), { code: "ESRCH" });
      } });
    }
  });
  assert.equal(passes, 2);
  assert.deepEqual(timing.sleeps, [250]);
  assert.deepEqual(observations, [[1, -23001, 0], [1, -23002, 0], [2, -23001, 0], [2, -23002, 0]]);
});

test("persistent EPERM retains the original error at the same ten-second deadline", async () => {
  const timing = virtualGroupWait();
  const denied = Object.assign(new Error("original denied probe"), { code: "EPERM" });
  const laterDenied = Object.assign(new Error("later denied probe"), { code: "EPERM" });
  let probes = 0;
  await assert.rejects(waitGroupsGone([original], { ...timing,
    assertGone: () => { probes++; throw probes === 1 ? denied : laterDenied; } }), error => error === denied);
  assert.equal(timing.clock(), 10_000);
  assert.equal(timing.sleeps.length, 40);
  assert.equal(probes, 40);
});

test("an earlier permission error does not replace a terminal observed-remaining timeout", async () => {
  const timing = virtualGroupWait();
  const denied = Object.assign(new Error("first denied probe"), { code: "EPERM" });
  let probes = 0;
  await assert.rejects(waitGroupsGone([original], { ...timing, timeoutMs: 500,
    assertGone: records => {
      if (++probes === 1) throw denied;
      assertGroupsGone(records, { kill: () => {} });
    } }), error => error !== denied && error.message === "Timed out waiting for child shutdown.");
  assert.equal(timing.clock(), 500);
  assert.equal(probes, 2);
});

test("a failed signal still observes every group and forbids subsequent cleanup despite ESRCH", async () => {
  const records = [Object.freeze({ ...original }), Object.freeze({ ...original, pid: 23002, pgid: 23002 })];
  const firstSignalError = new Error("original guarded signal failure");
  const shutdown = createShutdownSignals({ signalGroup: record => { if (record === records[0]) throw firstSignalError; } });
  shutdown.signalAll(records);
  const observed = [];
  let cleanupStarted = false;
  await assert.rejects((async () => {
    await verifyShutdownGroups(records, shutdown, { assertGone: values => assertGroupsGone(values, {
      kill: (pgid, signal) => {
        observed.push([pgid, signal]);
        throw Object.assign(new Error("absent"), { code: "ESRCH" });
      }
    }) });
    cleanupStarted = true;
  })(), error => error instanceof AggregateError && error.errors.length === 1 && error.errors[0] === firstSignalError);
  assert.deepEqual(observed, [[-23001, 0], [-23002, 0]]);
  assert.equal(cleanupStarted, false);
});

test("failed signalling and terminal group permission retain both original errors", async () => {
  const timing = virtualGroupWait();
  const signalError = new Error("original signal failure");
  const firstDenied = Object.assign(new Error("first group probe denied"), { code: "EPERM" });
  const laterDenied = Object.assign(new Error("later group probe denied"), { code: "EPERM" });
  const shutdown = createShutdownSignals({ signalGroup: () => { throw signalError; } });
  shutdown.signalAll([original]);
  let probes = 0;
  await assert.rejects(verifyShutdownGroups([original], shutdown, { ...timing, timeoutMs: 500,
    assertGone: () => { throw ++probes === 1 ? firstDenied : laterDenied; } }), error => {
    assert.ok(error instanceof AggregateError);
    assert.deepEqual(error.errors, [signalError, firstDenied]);
    return true;
  });
  assert.equal(probes, 2);
  assert.equal(timing.clock(), 500);
});

test("a lone group error or cancellation keeps its exact identity and code", async () => {
  const shutdown = createShutdownSignals({ signalGroup: () => {} });
  shutdown.signalAll([original]);
  const groupError = Object.assign(new Error("original group observation failure"), { code: "EIO" });
  await assert.rejects(verifyShutdownGroups([original], shutdown, {
    assertGone: () => { throw groupError; }
  }), error => error === groupError && error.code === "EIO");
  const controller = new AbortController();
  const cancellation = Object.assign(new Error("original lifecycle interruption"), { code: "DEV_STACK_OPERATION_CANCELLED" });
  controller.abort(cancellation);
  await assert.rejects(verifyShutdownGroups([original], shutdown, {
    signal: controller.signal, assertGone: () => assert.fail("cancelled verification must not probe")
  }), error => error === cancellation && error.code === "DEV_STACK_OPERATION_CANCELLED");
});

test("persistent groups still time out, sleep is clamped, and unknown probe failures propagate", async () => {
  const timing = virtualGroupWait();
  await assert.rejects(waitGroupsGone([original], { ...timing, timeoutMs: 510,
    assertGone: records => assertGroupsGone(records, { kill: () => {} }) }), /Timed out waiting for child shutdown/);
  assert.deepEqual(timing.sleeps, [250, 250, 10]);
  for (const failure of [Object.assign(new Error("unknown"), { code: "EIO" }), new Error("Invalid managed process group.")]) {
    const immediate = virtualGroupWait();
    await assert.rejects(waitGroupsGone([original], { ...immediate, assertGone: () => { throw failure; } }), error => error === failure);
    assert.deepEqual(immediate.sleeps, []);
  }
  await assert.rejects(waitGroupsGone([original], { timeoutMs: 10_001 }), /Invalid owned group wait/);
});

test("group wait observes cancellation without probing or turning it into absence", async () => {
  const controller = new AbortController(), interruption = new Error("owned fixture interruption");
  controller.abort(interruption);
  await assert.rejects(waitGroupsGone([original], { signal: controller.signal,
    assertGone: () => assert.fail("no probe after cancellation") }), error => error === interruption);
});
