import test from "node:test";
import assert from "node:assert/strict";
import { changedApiSource, changedPackageSource, runApiReloadProof } from "../dev-stack-reload.mjs";

const apiMarker = `DEV_STACK_API_${"a".repeat(32)}`;
const packageMarker = `DEV_STACK_PACKAGE_${"b".repeat(32)}`;

test("API probe changes only the unique original live-route service literal", () => {
  const original = Buffer.from('service: "space-api";\nservice: "space-api",\n    uptimeSeconds: 1;\n');
  const snapshot = Buffer.from(original);
  const changed = changedApiSource(original, apiMarker).toString();
  assert.equal(changed, `service: "space-api";\nservice: "${apiMarker}",\n    uptimeSeconds: 1;\n`);
  assert.deepEqual(original, snapshot);
});

test("missing or ambiguous original API anchors fail instead of patching arbitrary source", () => {
  const source = Buffer.from('service: "space-api",\n    uptimeSeconds: 1;\n');
  assert.throws(() => changedApiSource(Buffer.from("not the original route"), apiMarker), /API_ANCHOR/u);
  assert.throws(() => changedApiSource(Buffer.concat([source, source]), apiMarker), /API_ANCHOR/u);
  assert.throws(() => changedApiSource(source, '"; throw new Error()'), /API_INPUT/u);
  assert.throws(() => changedApiSource(Buffer.from([0xff, 0xfe]), apiMarker), /API_ANCHOR/u);
});

test("package probe appends a fixed-shape nonce without replacing existing exports", () => {
  const original = Buffer.from('export * from "./original.js";\n');
  const changed = changedPackageSource(original, packageMarker);
  assert.ok(changed.subarray(0, original.length).equals(original));
  assert.ok(changed.toString().endsWith(`console.log("${packageMarker}");\n`));
  assert.throws(() => changedPackageSource(changed, packageMarker), /PACKAGE_SOURCE/u);
  assert.throws(() => changedPackageSource(original, "unsafe"), /PACKAGE_INPUT/u);
});

test("live source changes are refused outside the exact isolated CI checkout", async () => {
  await assert.rejects(runApiReloadProof({ state: { repoRoot: "/unowned", stateDir: "/unowned/.dev-stack" } }),
    /ISOLATED_CI_ONLY/u);
});
