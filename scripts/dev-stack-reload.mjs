/** Real source-change proofs, restricted to this isolated CI checkout. */
import { randomUUID } from "node:crypto";
import { readFileSync, writeFileSync, lstatSync } from "node:fs";
import { join, resolve } from "node:path";
import { performance } from "node:perf_hooks";
import { assertReadiness } from "./dev-stack-acceptance.mjs";

const root = resolve(import.meta.dirname, "..");
const pause = () => new Promise(done => setTimeout(done, 250));
const apiAnchor = 'service: "space-api",\n    uptimeSeconds:';

function requireCondition(value, code) {
  if (!value) throw new Error(`DEV_STACK_RELOAD_${code}`);
}

export function changedApiSource(original, marker) {
  requireCondition(Buffer.isBuffer(original) && /^DEV_STACK_API_[a-f0-9]{32}$/u.test(marker), "API_INPUT");
  const text = original.toString("utf8");
  requireCondition(Buffer.from(text).equals(original) && text.split(apiAnchor).length === 2, "API_ANCHOR");
  return Buffer.from(text.replace(apiAnchor, `service: "${marker}",\n    uptimeSeconds:`));
}

export function changedPackageSource(original, marker) {
  requireCondition(Buffer.isBuffer(original) && /^DEV_STACK_PACKAGE_[a-f0-9]{32}$/u.test(marker), "PACKAGE_INPUT");
  const text = original.toString("utf8");
  requireCondition(Buffer.from(text).equals(original) && text.length > 0 && !text.includes(marker), "PACKAGE_SOURCE");
  return Buffer.concat([original, Buffer.from(`\n// Temporary isolated CI rebuild observation; restored in finally.\nconsole.log("${marker}");\n`)]);
}

function sourceFile(state, parts) {
  requireCondition(process.env.CI === "true" && ["linux", "darwin"].includes(process.platform)
    && state?.repoRoot === root && state.stateDir === join(root, ".dev-stack"), "ISOLATED_CI_ONLY");
  const path = join(root, ...parts);
  const info = lstatSync(path);
  requireCondition(info.isFile() && !info.isSymbolicLink() && info.nlink === 1
    && info.size > 0 && info.size < 1024 * 1024, "SOURCE_FILE");
  return { path, original: readFileSync(path) };
}

async function until(predicate, label, timeoutMs = 120_000) {
  const end = performance.now() + timeoutMs;
  do {
    if (await predicate()) return;
    await pause();
  } while (performance.now() < end);
  requireCondition(false, label);
}

async function request(state, path) {
  try {
    const response = await fetch(`http://127.0.0.1:${state.ports.api}${path}`, {
      signal: AbortSignal.timeout(3000), redirect: "error",
    });
    const text = await response.text();
    if (Buffer.byteLength(text) > 65536) return null;
    return { status: response.status, body: JSON.parse(text) };
  } catch { return null; } // Transient refusal during an actual watch restart.
}

async function ready(state) {
  const response = await request(state, "/readyz?strict=1");
  if (!response) return false;
  try { return assertReadiness(response); } catch { return false; }
}

/** Edit the original live route, observe tsx watch, then restore and observe again. */
export async function runApiReloadProof({ state }) {
  const { path, original } = sourceFile(state, ["apps", "api", "src", "health-routes.ts"]);
  const before = await request(state, "/livez");
  requireCondition(before?.status === 200 && before.body?.ok === true && before.body.service === "space-api",
    "API_BASELINE");
  const marker = `DEV_STACK_API_${randomUUID().replaceAll("-", "")}`;
  const changed = changedApiSource(original, marker);
  try {
    writeFileSync(path, changed);
    await until(async () => {
      const response = await request(state, "/livez");
      return response?.status === 200 && response.body?.ok === true && response.body.service === marker
        && await ready(state);
    }, "API_CHANGE_NOT_OBSERVED");
  } finally {
    writeFileSync(path, original);
    requireCondition(readFileSync(path).equals(original), "API_RESTORE_BYTES");
    await until(async () => {
      const response = await request(state, "/livez");
      return response?.status === 200 && response.body?.ok === true && response.body.service === "space-api"
        && await ready(state);
    }, "API_RESTORE_NOT_OBSERVED");
  }
  return { schema: "spaceapp.dev-stack-api-reload.v1", passed: true,
    originalSourceEdited: true, liveRouteChanged: true, sourceBytesRestored: true,
    originalRouteRestored: true, strictReadinessRestored: true,
    mechanism: "Original health-routes.ts under the source API's tsx watch" };
}

/** Prove a workspace package really rebuilds and is loaded by the new worker. */
export async function runPackageRebuildProof({ state, restart, readLog }) {
  const { path, original } = sourceFile(state, ["packages", "runtime", "src", "index.ts"]);
  requireCondition(typeof restart === "function" && typeof readLog === "function", "REBUILD_CALLBACKS");
  const marker = `DEV_STACK_PACKAGE_${randomUUID().replaceAll("-", "")}`;
  requireCondition(!readLog().includes(marker), "PACKAGE_BASELINE");
  try {
    writeFileSync(path, changedPackageSource(original, marker));
    const result = await restart(); // The caller must use the documented rebuild command.
    requireCondition(result?.oldSupervisorExited === true && result.newSupervisorVerified === true
      && result.projectAndSecretsPreserved === true, "REBUILD_RECEIPT");
    await until(() => readLog().includes(`[worker] ${marker}\n`), "NEW_WORKER_PACKAGE_NOT_OBSERVED");
  } finally {
    writeFileSync(path, original);
    requireCondition(readFileSync(path).equals(original), "PACKAGE_RESTORE_BYTES");
  }
  return { schema: "spaceapp.dev-stack-package-rebuild.v1", passed: true,
    originalPackageSourceEdited: true, freshWorkerLoadedRebuiltPackage: true,
    sourceBytesRestored: true, projectAndSecretsPreserved: true,
    mechanism: "Documented dev:stack rebuild; new worker imports compiled @space/runtime",
    limits: ["Temporary probe remains in this isolated runner's compiled dist until disposal; tracked source was restored.",
      "This is a package rebuild proof, not package automatic hot reload."] };
}
