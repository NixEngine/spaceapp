import assert from "node:assert/strict";
import {
  chmodSync, existsSync, linkSync, lstatSync, mkdirSync, mkdtempSync, readFileSync,
  realpathSync, renameSync, rmSync, symlinkSync, unlinkSync, writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { acquireLifecycleLock, releaseLifecycleLock } from "../dev-stack-lifecycle.mjs";

function fixture(t) {
  const base = mkdtempSync(join(tmpdir(), "space-lifecycle-"));
  const repo = join(base, "checkout");
  mkdirSync(repo);
  t.after(() => rmSync(base, { recursive: true, force: true }));
  return { base, repo };
}

function linkOrSkip(t, target, path, directory = false) {
  try { symlinkSync(target, path, directory ? (process.platform === "win32" ? "junction" : "dir") : "file"); }
  catch (error) {
    if (process.platform === "win32" && ["EPERM", "EACCES", "ENOTSUP"].includes(error.code)) {
      t.skip("Host does not permit the symlink fixture.");
      return false;
    }
    throw error;
  }
  return true;
}

test("acquires and releases one fixed canonical-root lease outside resettable state", (t) => {
  const { repo } = fixture(t);
  const lease = acquireLifecycleLock(repo);
  assert.equal(lease.repoRoot, realpathSync(repo));
  assert.equal(lease.path, join(realpathSync(repo), ".dev-stack-control.lock"));
  assert.equal(lease.ownerPath, join(lease.path, "owner.json"));
  assert.match(lease.token, /^[a-f0-9]{64}$/u);
  const owner = JSON.parse(readFileSync(lease.ownerPath, "utf8"));
  assert.deepEqual(owner, { schema: lease.schema, repoRoot: lease.repoRoot, token: lease.token });
  assert.deepEqual(releaseLifecycleLock(lease), { released: true, repoRoot: lease.repoRoot, path: lease.path });
  assert.equal(existsSync(lease.path), false);
});

test("exclusive acquisition cannot adopt even a valid lock and does not change its token", (t) => {
  const { repo } = fixture(t);
  const first = acquireLifecycleLock(repo);
  const before = readFileSync(first.ownerPath);
  assert.throws(() => acquireLifecycleLock(repo), { code: "DEV_STACK_LIFECYCLE_LOCKED" });
  assert.deepEqual(readFileSync(first.ownerPath), before);
  releaseLifecycleLock(first);
  const next = acquireLifecycleLock(repo);
  assert.notEqual(next.token, first.token);
  releaseLifecycleLock(next);
});

test("deleting .dev-stack cannot release the separate lifecycle lock", (t) => {
  const { repo } = fixture(t);
  const lease = acquireLifecycleLock(repo);
  const state = join(repo, ".dev-stack");
  mkdirSync(state);
  writeFileSync(join(state, "owned.txt"), "fixture");
  rmSync(state, { recursive: true });
  assert.throws(() => acquireLifecycleLock(repo), { code: "DEV_STACK_LIFECYCLE_LOCKED" });
  assert.equal(existsSync(lease.ownerPath), true);
  releaseLifecycleLock(lease);
});

test("empty or apparently stale unknown locks are never automatically recovered", (t) => {
  const { repo } = fixture(t);
  const lock = join(repo, ".dev-stack-control.lock");
  mkdirSync(lock, { mode: 0o700 });
  assert.throws(() => acquireLifecycleLock(repo), { code: "DEV_STACK_LIFECYCLE_LOCKED" });
  const owner = join(lock, "owner.json");
  writeFileSync(owner, '{"pid":99999999,"createdAt":"1970-01-01"}', { mode: 0o600 });
  assert.throws(() => acquireLifecycleLock(repo), { code: "DEV_STACK_LIFECYCLE_LOCKED" });
  assert.equal(readFileSync(owner, "utf8"), '{"pid":99999999,"createdAt":"1970-01-01"}');
});

test("an existing ordinary file at the lock path is left untouched", (t) => {
  const { repo } = fixture(t);
  const path = join(repo, ".dev-stack-control.lock");
  writeFileSync(path, "unrelated user file");
  assert.throws(() => acquireLifecycleLock(repo), { code: "DEV_STACK_LIFECYCLE_LOCKED" });
  assert.equal(readFileSync(path, "utf8"), "unrelated user file");
});

test("a mismatched lease token cannot release the actual owner", (t) => {
  const { repo } = fixture(t);
  const lease = acquireLifecycleLock(repo);
  const altered = { ...lease, token: "0".repeat(64) === lease.token ? "1".repeat(64) : "0".repeat(64) };
  assert.throws(() => releaseLifecycleLock(altered), { code: "DEV_STACK_LIFECYCLE_FOREIGN" });
  assert.equal(existsSync(lease.ownerPath), true);
  releaseLifecycleLock(lease);
});

test("a replaced persisted token or foreign root refuses release without deleting anything", (t) => {
  const { base, repo } = fixture(t);
  const lease = acquireLifecycleLock(repo);
  const other = join(base, "other");
  mkdirSync(other);
  const owner = JSON.parse(readFileSync(lease.ownerPath, "utf8"));
  for (const changed of [{ ...owner, token: "f".repeat(64) === owner.token ? "e".repeat(64) : "f".repeat(64) },
    { ...owner, repoRoot: realpathSync(other) }]) {
    writeFileSync(lease.ownerPath, JSON.stringify(changed));
    assert.throws(() => releaseLifecycleLock(lease), { code: "DEV_STACK_LIFECYCLE_FOREIGN" });
    assert.equal(existsSync(lease.ownerPath), true);
  }
});

test("foreign checkout paths cannot be substituted into an acquired lease", (t) => {
  const { base, repo } = fixture(t);
  const lease = acquireLifecycleLock(repo);
  const other = join(base, "other");
  mkdirSync(other);
  assert.throws(() => releaseLifecycleLock({ ...lease, repoRoot: realpathSync(other) }), {
    code: "DEV_STACK_LIFECYCLE_FOREIGN",
  });
  assert.equal(existsSync(lease.ownerPath), true);
  releaseLifecycleLock(lease);
});

test("a missing owner file or missing lock is not a successful release", (t) => {
  const { repo } = fixture(t);
  const lease = acquireLifecycleLock(repo);
  unlinkSync(lease.ownerPath);
  assert.throws(() => releaseLifecycleLock(lease), { code: "DEV_STACK_LIFECYCLE_MISSING" });
  assert.equal(existsSync(lease.path), true);
  rmSync(lease.path, { recursive: true });
  assert.throws(() => releaseLifecycleLock(lease), { code: "DEV_STACK_LIFECYCLE_MISSING" });
});

test("an owner file replaced with identical bytes is not the original lease file", (t) => {
  const { base, repo } = fixture(t);
  const lease = acquireLifecycleLock(repo);
  const raw = readFileSync(lease.ownerPath);
  renameSync(lease.ownerPath, join(base, "retained-owner.json"));
  writeFileSync(lease.ownerPath, raw, { mode: 0o600 });
  assert.throws(() => releaseLifecycleLock(lease), { code: "DEV_STACK_LIFECYCLE_CHANGED" });
  assert.deepEqual(readFileSync(lease.ownerPath), raw);
});

test("a replacement directory with the same token cannot be released by an old lease", (t) => {
  const { base, repo } = fixture(t);
  const lease = acquireLifecycleLock(repo);
  const raw = readFileSync(lease.ownerPath);
  renameSync(lease.path, join(base, "retained-lock"));
  mkdirSync(lease.path, { mode: 0o700 });
  writeFileSync(lease.ownerPath, raw, { mode: 0o600 });
  assert.throws(() => releaseLifecycleLock(lease), { code: "DEV_STACK_LIFECYCLE_CHANGED" });
  assert.deepEqual(readFileSync(lease.ownerPath), raw);
});

test("unexpected lock contents refuse release before unlinking the owner", (t) => {
  const { repo } = fixture(t);
  const lease = acquireLifecycleLock(repo);
  const sentinel = join(lease.path, "keep.txt");
  writeFileSync(sentinel, "keep");
  assert.throws(() => releaseLifecycleLock(lease), { code: "DEV_STACK_LIFECYCLE_UNSAFE" });
  assert.equal(existsSync(lease.ownerPath), true);
  assert.equal(readFileSync(sentinel, "utf8"), "keep");
});

test("malformed owner JSON refuses release without deleting the owner record", (t) => {
  const { repo } = fixture(t);
  const lease = acquireLifecycleLock(repo);
  writeFileSync(lease.ownerPath, "malformed");
  assert.throws(() => releaseLifecycleLock(lease), { code: "DEV_STACK_LIFECYCLE_OWNER" });
  assert.equal(readFileSync(lease.ownerPath, "utf8"), "malformed");
});

test("hard-linked owner records cannot be released", (t) => {
  const { base, repo } = fixture(t);
  const lease = acquireLifecycleLock(repo);
  const outside = join(base, "linked-owner.json");
  linkSync(lease.ownerPath, outside);
  assert.throws(() => releaseLifecycleLock(lease), { code: "DEV_STACK_LIFECYCLE_UNSAFE" });
  assert.equal(existsSync(lease.ownerPath), true);
  assert.equal(existsSync(outside), true);
});

test("symlink owner record is neither followed nor deleted", (t) => {
  const { base, repo } = fixture(t);
  const lease = acquireLifecycleLock(repo);
  const outside = join(base, "actual-owner.json");
  renameSync(lease.ownerPath, outside);
  if (!linkOrSkip(t, outside, lease.ownerPath)) return;
  assert.throws(() => releaseLifecycleLock(lease), { code: "DEV_STACK_LIFECYCLE_UNSAFE" });
  assert.equal(lstatSync(lease.ownerPath).isSymbolicLink(), true);
  assert.equal(existsSync(outside), true);
});

test("symlink lock directory is not followed, adopted or released", (t) => {
  const { base, repo } = fixture(t);
  const lease = acquireLifecycleLock(repo);
  const outside = join(base, "actual-lock");
  renameSync(lease.path, outside);
  if (!linkOrSkip(t, outside, lease.path, true)) return;
  assert.throws(() => acquireLifecycleLock(repo), { code: "DEV_STACK_LIFECYCLE_LOCKED" });
  assert.throws(() => releaseLifecycleLock(lease), { code: "DEV_STACK_LIFECYCLE_UNSAFE" });
  assert.equal(existsSync(join(outside, "owner.json")), true);
});

test("a canonical checkout alias resolves to the same exclusive lock", (t) => {
  const { base, repo } = fixture(t);
  const alias = join(base, "checkout-alias");
  if (!linkOrSkip(t, repo, alias, true)) return;
  const lease = acquireLifecycleLock(alias);
  assert.equal(lease.repoRoot, realpathSync(repo));
  assert.throws(() => acquireLifecycleLock(repo), { code: "DEV_STACK_LIFECYCLE_LOCKED" });
  releaseLifecycleLock(lease);
});

test("invalid lease objects cannot select arbitrary removal paths", (t) => {
  const { repo } = fixture(t);
  const lease = acquireLifecycleLock(repo);
  for (const invalid of [null, {}, { ...lease, token: "short" }, { ...lease, extra: true }]) {
    assert.throws(() => releaseLifecycleLock(invalid), { code: "DEV_STACK_LIFECYCLE_LEASE" });
    assert.equal(existsSync(lease.ownerPath), true);
  }
  assert.throws(() => releaseLifecycleLock({ ...lease, path: repo }), { code: "DEV_STACK_LIFECYCLE_FOREIGN" });
  releaseLifecycleLock(lease);
  assert.throws(() => releaseLifecycleLock(lease), { code: "DEV_STACK_LIFECYCLE_MISSING" });
});

test("private POSIX permissions are generated and required before release", {
  skip: process.platform === "win32" ? "POSIX mode checks are not Windows ACL enforcement." : false,
}, (t) => {
  const { repo } = fixture(t);
  const lease = acquireLifecycleLock(repo);
  assert.equal(lstatSync(lease.path).mode & 0o777, 0o700);
  assert.equal(lstatSync(lease.ownerPath).mode & 0o777, 0o600);
  chmodSync(lease.path, 0o755);
  assert.throws(() => releaseLifecycleLock(lease), { code: "DEV_STACK_LIFECYCLE_PERMISSIONS" });
  chmodSync(lease.path, 0o700);
  chmodSync(lease.ownerPath, 0o644);
  assert.throws(() => releaseLifecycleLock(lease), { code: "DEV_STACK_LIFECYCLE_PERMISSIONS" });
  assert.equal(existsSync(lease.ownerPath), true);
});
