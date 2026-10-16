import assert from "node:assert/strict";
import { join, resolve } from "node:path";
import test from "node:test";
import { assertUiObservation, browserArtifactRootAllowed, browserUrlAllowed, inspectPng, mutateBadgeSource } from "../dev-stack-browser.mjs";

const state = { ports: { api: 5910, web: 5911 } };
const observation = () => ({ paneCount: 1, badgeVisible: true, roomObserved: true,
  status: "attached", loading: "false", hasError: "false", hasSession: "true", hasWebsocket: "true",
  width: 800, height: 600, screenWidth: 800, screenHeight: 600, canvasCount: 1, rowCount: 0 });

test("URL guard permits only the owned application HTTP/WS ports and nonnetwork documents", () => {
  for (const url of ["http://127.0.0.1:5910/api/auth/login", "http://127.0.0.1:5911/", "ws://127.0.0.1:5911/",
    "ws://127.0.0.1:5910/api/panes/synthetic/cli/terminal?token=synthetic", "about:blank",
    "data:image/png;base64,synthetic", "blob:http://127.0.0.1:5911/synthetic"]) assert.equal(browserUrlAllowed(url, state), true, url);
  assert.equal(browserUrlAllowed("http://127.0.0.1:80/", { ports: { api: 80, web: 5911 } }), true);
});

test("URL guard rejects external destinations, credentials, wrong ports and privileged schemes", () => {
  for (const url of ["https://example.com/", "ws://example.com/", "wss://127.0.0.1:5911/", "https://127.0.0.1:5910/",
    "http://127.0.0.1:4910/", "http://127.0.0.2:5911/", "http://localhost:5911/", "http://127.0.0.1:5912/",
    "http://127.0.0.1.evil.test:5911/", "http://user:password@127.0.0.1:5911/", "file:///etc/passwd",
    "javascript:alert(1)", "blob:https://example.com/id", "not a url", undefined]) assert.equal(browserUrlAllowed(url, state), false);
});

test("artifact root permits a fresh direct child, never a root or a nested uncontrolled path", () => {
  const owned = resolve("synthetic-checkout", ".dev-stack");
  const temporary = resolve("synthetic-runner-temp");
  assert.equal(browserArtifactRootAllowed(join(owned, "browser-proof"), owned), true);
  assert.equal(browserArtifactRootAllowed(join(temporary, "spaceapp-dev-stack-browser-123"), owned, temporary, "true"), true);
  for (const [candidate, ci] of [[owned, "true"], [temporary, "true"],
    [join(temporary, "arbitrary"), "true"], [join(temporary, "spaceapp-dev-stack-browser-123"), "false"],
    [join(temporary, "nested", "spaceapp-dev-stack-browser-123"), "true"], ["relative", "true"]]) {
    assert.equal(browserArtifactRootAllowed(candidate, owned, temporary, ci), false);
  }
});

test("real UI guard expects attached source status with visible rendered xterm geometry", () => {
  assert.equal(assertUiObservation(observation()), true);
  assert.equal(assertUiObservation({ ...observation(), canvasCount: 0, rowCount: 30 }), true);
});

test("HTTP/session RUNNING labels, missing render and error flags cannot become browser PASS", () => {
  for (const change of [{ status: "RUNNING" }, { status: "connecting" }, { hasError: "true" }, { loading: "true" },
    { paneCount: 0 }, { paneCount: 2 }, { badgeVisible: false }, { roomObserved: false },
    { hasSession: "false" }, { hasWebsocket: "false" }, { width: 0 }, { height: 0 },
    { screenWidth: 0 }, { canvasCount: 0, rowCount: 0 }]) {
    assert.throws(() => assertUiObservation({ ...observation(), ...change }), /DEV_STACK_BROWSER_UI_TERMINAL/u);
  }
});

test("HMR mutation changes the one original literal and preserves every other byte", () => {
  const original = Buffer.from("// UTF8:\u00b7\r\n<span className=\"space-instance-badge-label\">DEV</span>\r\n");
  const nonce = "11111111-2222-3333-4444-555555555555";
  const changed = mutateBadgeSource(original, nonce);
  assert.equal(changed.toString("utf8"), original.toString("utf8").replace(">DEV<", `>DEV HMR-${nonce}<`));
  assert.ok(original.equals(Buffer.from("// UTF8:\u00b7\r\n<span className=\"space-instance-badge-label\">DEV</span>\r\n")));
});

test("HMR fails closed on unknown source, duplicate literals or unsafe marker", () => {
  const nonce = "11111111-2222-3333-4444-555555555555";
  for (const source of ["no literal", ">DEV<>DEV<"]) assert.throws(() => mutateBadgeSource(Buffer.from(source), nonce), /HMR_LITERAL/u);
  assert.throws(() => mutateBadgeSource(Buffer.from(">DEV<"), "<script>"), /HMR_INPUT/u);
});

function syntheticPng(width = 1440, height = 1000, length = 5000) {
  const value = Buffer.alloc(length);
  Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]).copy(value);
  value.write("IHDR", 12, "ascii");
  value.writeUInt32BE(width, 16); value.writeUInt32BE(height, 20);
  return value;
}

test("PNG guard reports dimensions/hash only, not a fabricated visual interpretation", () => {
  const value = inspectPng(syntheticPng());
  assert.equal(value.width, 1440); assert.equal(value.height, 1000); assert.equal(value.byteSize, 5000);
  assert.match(value.sha256, /^[a-f0-9]{64}$/u);
  assert.equal(value.uiVerified, undefined);
});

test("empty, undersized, wrong-signature or excessively sized screenshots fail", () => {
  for (const value of [Buffer.alloc(0), Buffer.alloc(5000), syntheticPng(10, 10), syntheticPng(5000, 1000), syntheticPng(1440, 1000, 4000)]) {
    assert.throws(() => inspectPng(value), /DEV_STACK_BROWSER_SCREENSHOT/u);
  }
});
