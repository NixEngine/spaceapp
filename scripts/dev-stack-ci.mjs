#!/usr/bin/env node
import { spawn, execFileSync } from "node:child_process";
import { openSync, closeSync, readFileSync, existsSync, readlinkSync, readdirSync } from "node:fs";
import { join, resolve, sep } from "node:path";
import { tmpdir } from "node:os";
import { performance } from "node:perf_hooks";
import { readState } from "./dev-stack-state.mjs";
import { processIdentity, signalOwnedGroup, assertGroupsGone } from "./dev-stack-process.mjs";
import { runAcceptance } from "./dev-stack-acceptance.mjs";

// Explicit isolated Linux CI only. This is not an operator-host diagnostic.
if (process.platform !== "linux" || process.env.CI !== "true") {
  throw new Error("Run this full-stack mutation proof only in an isolated Linux CI checkout.");
}
const root = resolve(import.meta.dirname, "..");
if (existsSync(join(root, ".dev-stack"))) throw new Error("CI proof requires fresh absent dev-stack state.");
const logPath = join(process.env.RUNNER_TEMP || tmpdir(), `spaceapp-dev-stack-${process.pid}.txt`);
const descriptor = openSync(logPath, "wx", 0o600);
const supervisor = spawn(process.execPath, ["scripts/dev-stack.mjs"], {
  cwd: root, env: process.env, detached: true, stdio: ["ignore", descriptor, descriptor]
});
closeSync(descriptor);
let exit;
let startError;
supervisor.once("error", () => { startError = new Error("CI source supervisor could not start."); });
supervisor.once("exit", (code, signal) => { exit = { code, signal }; });
const pause = () => new Promise(done => setTimeout(done, 500));
async function until(predicate, timeoutMs, label, requireAlive = true) {
  const deadline = performance.now() + timeoutMs;
  while (performance.now() < deadline) {
    if (startError) throw startError;
    if (requireAlive && exit) throw new Error(`Supervisor exited before ${label}; inspect the captured source log.`);
    if (await predicate()) return;
    await pause();
  }
  throw new Error(`CI timed out at ${label}.`);
}
function leftovers(state) {
  const found = [];
  for (const name of readdirSync("/proc")) {
    if (!/^\d+$/.test(name)) continue;
    try {
      const cwd = readlinkSync(`/proc/${name}/cwd`);
      if (cwd === state.stateDir || cwd.startsWith(`${state.stateDir}${sep}`)) found.push(Number(name));
    } catch (error) {
      if (!["ENOENT", "ESRCH", "EACCES"].includes(error.code)) throw error;
    }
  }
  return found;
}
function reset() {
  execFileSync(process.execPath, ["scripts/dev-stack.mjs", "reset"], {
    cwd: root, env: process.env, stdio: "inherit", timeout: 120_000
  });
}
let state;
let receipts = [];
let proof;
try {
  await until(async () => {
    if (!existsSync(join(root, ".dev-stack", "owner.json"))) return false;
    try {
      state = readState(root);
      const response = await fetch(`http://127.0.0.1:${state.ports.api}/readyz?strict=1`, { signal: AbortSignal.timeout(3000) });
      const body = await response.json();
      return response.status === 200 && body.ok === true && body.dependencies?.worker === "RUNNING";
    } catch { return false; }
  }, 15 * 60_000, "strict source startup");
  proof = await runAcceptance({ state });
  const runtime = JSON.parse(readFileSync(join(state.stateDir, "runtime.json"), "utf8"));
  receipts = runtime.children;
  const worker = receipts.find(record => record.name === "worker");
  if (!worker || !processIdentity(worker.pid)) throw new Error("No running owned worker to test the failure path.");
  signalOwnedGroup(worker);
  await until(() => exit !== undefined, 60_000, "visible worker failure shutdown", false);
  if (exit.code === 0 || !/worker exited unexpectedly/.test(readFileSync(logPath, "utf8"))) {
    throw new Error("Worker failure did not produce an explicit failing supervisor outcome.");
  }
  assertGroupsGone(receipts);
  if (leftovers(state).length) throw new Error("Processes still have their cwd in owned state; cleanup is incomplete.");
  reset();
  if (existsSync(state.stateDir)) throw new Error("Reset left the owned state directory.");
  for (const kind of ["container", "volume", "network"]) {
    const remaining = execFileSync("docker", [kind, "ls", "--quiet", ...(kind === "container" ? ["--all"] : []),
      "--filter", `label=com.docker.compose.project=${state.project}`], { encoding: "utf8", timeout: 30_000 }).trim();
    if (remaining) throw new Error(`Reset left owned ${kind} resources.`);
  }
  console.log(JSON.stringify({
    schema: "spaceapp.dev-stack-ci.v1", passed: true, platform: process.platform,
    node: process.version, acceptance: proof, explicitWorkerFailureVerified: true,
    ownedProcessGroupsGone: true, stateCwdProcessesGone: true, resetStateGone: true,
    ownedContainersVolumesNetworksGone: true,
    browserUiVerified: false, hotReloadVerified: false, secondPlatformVerified: false,
    completeIssueAcceptance: false
  }, null, 2));
} finally {
  if (!exit && supervisor.pid) {
    // Only the actual child handle just created by this proof; never a historic PID.
    supervisor.kill("SIGTERM");
    await until(() => exit !== undefined, 45_000, "proof supervisor cleanup", false).catch(() => {});
  }
  // A failed cleanup remains a failed job. Do not suppress reset/resource errors
  // or declare a clean environment merely because the leader is gone.
  if (state && existsSync(state.stateDir)) reset();
  console.log(`Source-stack log: ${logPath}`);
}
