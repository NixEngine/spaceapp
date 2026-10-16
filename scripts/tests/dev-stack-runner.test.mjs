import test from "node:test";
import assert from "node:assert/strict";
import { waitUntil, assertComposeMatches } from "../dev-stack.mjs";
import { composeConfig } from "../dev-stack-config.mjs";
import { resolve, join } from "node:path";

test("bounded readiness wait checks the predicate rather than trusting elapsed wall-clock labels", async () => {
  let checked = 0;
  await waitUntil(() => ++checked === 3, { timeoutMs: 1000, intervalMs: 1, label: "synthetic predicate" });
  assert.equal(checked, 3);
});

test("negative readiness is a failure, not a successful timeout", async () => {
  await assert.rejects(waitUntil(() => false, { timeoutMs: 5, intervalMs: 1, label: "missing worker" }), /Timed out waiting for missing worker/);
});

test("predicate failures propagate rather than being counted as readiness", async () => {
  await assert.rejects(waitUntil(() => { throw new Error("worker exited"); }), /worker exited/);
});

test("cleanup rejects a compose swap naming a foreign volume, service or image", () => {
  const repoRoot = resolve("synthetic-repo");
  const state = { repoRoot, stateDir: join(repoRoot, ".dev-stack"), project: `space-dev-${"1".repeat(24)}`,
    ports: { api: 5910, web: 5911, postgres: 55432, temporal: 57233 } };
  const images = { postgres: `test/pg@sha256:${"a".repeat(64)}`, temporal: `test/temporal@sha256:${"b".repeat(64)}` };
  const expected = composeConfig(state, images);
  assert.doesNotThrow(() => assertComposeMatches(JSON.stringify(expected), state, images));
  for (const alter of [
    value => { value.volumes.postgres.name = "foreign-production-database"; },
    value => { value.services.foreign = { image: images.postgres }; },
    value => { value.services.postgres.image = `other/pg@sha256:${"c".repeat(64)}`; }
  ]) {
    const changed = structuredClone(expected); alter(changed);
    assert.throws(() => assertComposeMatches(JSON.stringify(changed), state, images), /differs/);
  }
  assert.throws(() => assertComposeMatches("not JSON", state, images), /valid JSON/);
});
