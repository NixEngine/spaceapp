/**
 * Opt-in, live HTTP/CLI acceptance for the isolated source development stack.
 * This mutates only that stack: it claims its owner once and attaches its real
 * OpenCode pane. No terminal input, provider challenge or completion is sent.
 * Pure assertions below are also used by dependency-free negative tests.
 */
import { createHmac, randomUUID } from "node:crypto";
import { isAbsolute, join } from "node:path";
import { performance } from "node:perf_hooks";
import { stripVTControlCharacters } from "node:util";

const RUNTIME = "cli:opencode";
const MAX_HTTP_BYTES = 512 * 1024;
const delay = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));

function requireCondition(condition, code) {
  if (!condition) {
    // Never include response bodies, URLs containing tickets, credentials or
    // terminal output in errors that the runner may print.
    const error = new Error(`DEV_STACK_ACCEPTANCE_${code}`);
    error.code = `DEV_STACK_ACCEPTANCE_${code}`;
    throw error;
  }
}

function nonempty(value) {
  return typeof value === "string" && value.length > 0;
}

/** HTTP 200 alone is deliberately insufficient, including with ?strict=1. */
export function assertReadiness({ status, body }) {
  const dependencies = body?.dependencies;
  requireCondition(status === 200 && body?.ok === true
    && dependencies?.store === "postgres" && dependencies.runtimeStore === "postgres"
    && dependencies.database === "RUNNING" && dependencies.worker === "RUNNING"
    && dependencies.cliHost === "RUNNING", "NOT_READY");
  // The temporal label tracks enableDummyTurns, not actual worker pollers.
  // worker=RUNNING is the source's workflow+activity poller check; this does
  // not assert that a workflow or provider task has been executed.
  return true;
}

/** Reentry derives a separate strong synthetic password; no extra secret file. */
export function acceptanceOwner(state) {
  requireCondition(/^space-dev-[a-f0-9]{24}$/u.test(state?.project ?? "")
    && /^[a-f0-9]{64}$/u.test(state?.secrets?.sessionSecret ?? ""), "INVALID_OWNER_STATE");
  return {
    email: `acceptance+${state.project.slice(10)}@spaceapp.invalid`,
    password: `DevStack-Aa1!${createHmac("sha256", Buffer.from(state.secrets.sessionSecret, "hex"))
      .update(`spaceapp.dev-stack.acceptance-owner.v1:${state.project}`).digest("base64url")}`,
  };
}

export function assertOwner({ status, body }, email) {
  requireCondition(status === 200 && body?.isAuthenticated === true
    && body.isSetupRequired === false && body.user?.id === "user:owner"
    && body.user.role === "ADMIN" && body.user.email === email
    && !body.user.proofScope && !body.user.automationScope, "OWNER_AUTH");
  return body.user.id;
}

export function assertStarterRoom({ status, body }, expectedRoomId) {
  const room = body?.room;
  requireCondition(status === 200 && nonempty(room?.id)
    && room.name === "Getting Started" && room.kind === "WORKSPACE"
    && room.archivedAt === null && room.ownerUserId === "user:owner"
    && body.onboarding?.starterRoomId === room.id
    && (!expectedRoomId || expectedRoomId === room.id), "STARTER_ROOM");
  return room.id;
}

export function selectStarterPane({ status, body }, roomId) {
  requireCondition(status === 200 && Array.isArray(body?.data), "PANE_LIST");
  const panes = body.data.filter(pane => pane.roomId === roomId && pane.mode === "TERMINAL"
    && pane.terminalRuntimeId === RUNTIME && pane.title === "OpenCode CLI" && pane.isClosed === false);
  requireCondition(panes.length === 1 && nonempty(panes[0].id), "STARTER_PANE");
  return panes[0];
}

/** Allocation is normally IDLE. Only the post-attach check requires RUNNING. */
export function assertSession({ status, body }, expected, { requireRunning = false } = {}) {
  const session = body?.session;
  const runtime = body?.runtime;
  requireCondition(status === 200 && nonempty(session?.sessionId)
    && session.paneId === expected.paneId && session.roomId === expected.roomId
    && session.runtimeId === RUNTIME && session.purpose === "NORMAL" && session.isActive === true
    && session.cwd === expected.cwd && session.endedAt === null && session.exitCode === null
    && (requireRunning ? session.status === "RUNNING" : ["IDLE", "RUNNING"].includes(session.status))
    && (!expected.sessionId || session.sessionId === expected.sessionId)
    && runtime?.id === RUNTIME && runtime.capabilities?.includes("CLI")
    && nonempty(runtime.detectedCommandPath) && Array.isArray(body.transcript)
    && body.transcript.length === 0, "CLI_SESSION");
  const ticket = body.websocket;
  requireCondition(ticket?.paneId === session.paneId && ticket.sessionId === session.sessionId
    && typeof ticket.token === "string" && /^[A-Za-z0-9_-]{24,512}$/u.test(ticket.token)
    && Number.isFinite(Date.parse(ticket.expiresAt)) && !ticket.proofScope, "CLI_TICKET");
  return { sessionId: session.sessionId, paneId: session.paneId, roomId: session.roomId };
}

/** Build one WS v2 attachment; the server consumes this ticket on first use. */
export function terminalUrl(apiOrigin, body) {
  requireCondition(/^http:\/\/127\.0\.0\.1:\d+$/u.test(apiOrigin), "NONLOCAL_ORIGIN");
  const url = new URL(`/api/panes/${encodeURIComponent(body.session.paneId)}/cli/terminal`, apiOrigin);
  url.protocol = "ws:";
  const identity = {
    clientId: randomUUID(), browserClientId: randomUUID(),
    tabLineageId: randomUUID(), pageClientId: randomUUID(),
  };
  for (const [key, value] of Object.entries({
    sessionId: body.session.sessionId, token: body.websocket.token, protocolVersion: "2",
    clientMode: "INTERACTIVE", initialCols: "100", initialRows: "30", ...identity,
  })) url.searchParams.set(key, value);
  return { url, identity };
}

/**
 * Bounded native transport observations, not an xterm/browser UI assertion.
 * Existing sessions can replay PTY output: counts do not imply a fresh render.
 * The probe never substitutes output from its own synthetic test fixtures.
 */
export function createTerminalObservation(expected, { maxOutputBytes = 256 * 1024, maxMessages = 2000 } = {}) {
  requireCondition(Number.isInteger(maxOutputBytes) && maxOutputBytes > 0
    && Number.isInteger(maxMessages) && maxMessages > 0, "INVALID_LIMITS");
  let ready = false;
  let running = false;
  let pong = false;
  let leaseId = null;
  let heartbeatIntervalMs = 5000;
  let messages = 0;
  let outputBytes = 0;
  let outputFrames = 0;
  let output = "";
  let failure = null;
  const validStatuses = ["IDLE", "RUNNING", "INTERRUPTING", "EXITED", "ERROR"];

  function observe(raw, isBinary = false) {
    try {
      requireCondition(!failure, "TERMINAL_FAILED");
      requireCondition(!isBinary && ++messages <= maxMessages, "TERMINAL_MESSAGE_LIMIT");
      requireCondition(Buffer.byteLength(raw) <= maxOutputBytes + 4096, "TERMINAL_FRAME_LIMIT");
      let message;
      try { message = JSON.parse(String(raw)); }
      catch { requireCondition(false, "TERMINAL_JSON"); }
      requireCondition(message && typeof message === "object" && !Array.isArray(message), "TERMINAL_SHAPE");
      switch (message.type) {
        case "ready":
          requireCondition(!ready && message.paneId === expected.paneId
            && message.sessionId === expected.sessionId && message.runtimeId === RUNTIME
            && message.protocolVersion === 2 && message.clientMode === "INTERACTIVE"
            && message.controlState === "CONTROLLER" && nonempty(message.leaseId), "TERMINAL_READY");
          requireCondition(Number.isInteger(message.heartbeatIntervalMs)
            && message.heartbeatIntervalMs >= 1000 && message.heartbeatIntervalMs <= 300000,
          "TERMINAL_HEARTBEAT");
          ready = true;
          leaseId = message.leaseId;
          heartbeatIntervalMs = message.heartbeatIntervalMs;
          break;
        case "output":
          requireCondition(ready && ["stdout", "stderr"].includes(message.stream)
            && typeof message.data === "string", "TERMINAL_OUTPUT");
          outputBytes += Buffer.byteLength(message.data);
          requireCondition(outputBytes <= maxOutputBytes, "TERMINAL_OUTPUT_LIMIT");
          outputFrames++;
          output += message.data;
          // Known source proof fixtures are not a real OpenCode terminal.
          requireCondition(!/SPACE_(?:WARM_READY|CLI_RENDER_PROOF)|SIMULATED_RUNTIME/u.test(output),
            "TERMINAL_SYNTHETIC_OUTPUT");
          break;
        case "status":
          requireCondition(ready && validStatuses.includes(message.status), "TERMINAL_STATUS");
          requireCondition(message.status === "RUNNING" || (!running && message.status === "IDLE"),
            "TERMINAL_NOT_RUNNING");
          requireCondition(message.exitCode == null, "TERMINAL_EXIT_CODE");
          if (message.status === "RUNNING") running = true;
          break;
        case "pong":
          requireCondition(ready, "TERMINAL_PONG");
          pong = true;
          break;
        case "control_state":
          requireCondition(ready && message.controlState === "CONTROLLER" && message.leaseId === leaseId,
            "TERMINAL_CONTROL");
          break;
        case "control_granted":
          requireCondition(ready && message.leaseId === leaseId, "TERMINAL_CONTROL");
          break;
        default:
          // Includes error, session_replaced, control_denied and control_revoked.
          requireCondition(false, "TERMINAL_EVENT");
      }
    } catch (error) {
      failure ??= error;
      throw failure;
    }
  }

  function snapshot() {
    if (failure) throw failure;
    const printable = stripVTControlCharacters(output).replace(/[\u0000-\u001f\u007f-\u009f]/gu, "").trim();
    return {
      ready, running, pong, leaseId, heartbeatIntervalMs, messages, outputBytes, outputFrames,
      printableCharacters: printable.length,
      openCodeBrandingObserved: /\bopencode\b/iu.test(printable),
      complete: ready && running && pong && outputFrames > 0 && printable.length >= 8,
    };
  }
  return { observe, snapshot };
}

function validateState(state, timeoutMs) {
  requireCondition(state && typeof state.repoRoot === "string" && isAbsolute(state.repoRoot)
    && state.stateDir === join(state.repoRoot, ".dev-stack")
    && /^[a-f0-9]{64}$/u.test(state.secrets?.setupToken ?? ""), "INVALID_STATE");
  acceptanceOwner(state);
  const ports = ["api", "web", "postgres", "temporal"].map(key => state.ports?.[key]);
  requireCondition(ports.every(port => Number.isInteger(port) && port > 0 && port <= 65535
    && port !== 4910 && port !== 4911) && new Set(ports).size === 4, "INVALID_PORTS");
  requireCondition(Number.isInteger(timeoutMs) && timeoutMs >= 1000 && timeoutMs <= 600000, "INVALID_TIMEOUT");
}

async function readBoundedText(response) {
  const reader = response.body?.getReader();
  requireCondition(reader, "HTTP_BODY_MISSING");
  const chunks = [];
  let length = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.byteLength;
      requireCondition(length <= MAX_HTTP_BYTES, "HTTP_BODY_LIMIT");
      chunks.push(value);
    }
    return Buffer.concat(chunks).toString("utf8");
  } finally {
    await reader.cancel().catch(() => {});
    reader.releaseLock();
  }
}

function sessionCookie(headers) {
  const values = headers.getSetCookie().map(value => value.split(";", 1)[0]);
  const candidates = values.filter(value => /^space_session(?:_dev)?=[^;\s]+$/u.test(value));
  requireCondition(candidates.length === 1, "SESSION_COOKIE");
  return candidates[0];
}

async function attachTerminal(body, apiOrigin, cookie, remaining) {
  let WebSocket;
  try { ({ default: WebSocket } = await import("ws")); }
  catch { requireCondition(false, "WS_DEPENDENCY_MISSING"); }
  const { url } = terminalUrl(apiOrigin, body);
  const observation = createTerminalObservation({ paneId: body.session.paneId, sessionId: body.session.sessionId });
  let socket;
  try {
    socket = new WebSocket(url, { headers: { Cookie: cookie },
      handshakeTimeout: Math.min(15000, remaining()), maxPayload: 260 * 1024,
      followRedirects: false, perMessageDeflate: false });
  } catch { requireCondition(false, "WS_CONNECT"); }
  let failure = null;
  let expectedClose = false;
  let heartbeat;
  let ownLeaseId = null;
  let closePromise = null;
  const failed = code => {
    try { requireCondition(false, code); }
    catch (error) { failure ??= error; }
  };
  socket.on("error", () => failed("WS_TRANSPORT"));
  socket.on("close", () => { if (!expectedClose) failed("WS_CLOSED"); });
  socket.on("message", (raw, isBinary) => {
    if (expectedClose) return;
    try {
      observation.observe(raw, isBinary);
      const state = observation.snapshot();
      if (state.ready && !heartbeat) {
        ownLeaseId = state.leaseId;
        socket.send(JSON.stringify({ type: "ping" }));
        heartbeat = setInterval(() => {
          if (socket.readyState === WebSocket.OPEN) {
            socket.send(JSON.stringify({ type: "control_heartbeat", leaseId: state.leaseId }));
          }
        }, state.heartbeatIntervalMs);
      }
    } catch (error) { failure ??= error; }
  });

  async function performClose() {
    expectedClose = true;
    clearInterval(heartbeat);
    // Release only our own control lease. A bare disconnect starts a reconnect
    // grace period and would make an immediate second verification conflict.
    let leaseReleased = false;
    if (socket.readyState === WebSocket.OPEN && ownLeaseId) {
      leaseReleased = await new Promise(resolve => {
        let timer;
        const finish = released => {
          clearTimeout(timer);
          socket.off("message", releasedMessage);
          socket.off("close", closed);
          resolve(released);
        };
        const releasedMessage = (raw, binary) => {
          if (binary) return;
          try {
            const message = JSON.parse(String(raw));
            if (message.type === "control_state" && message.controlState === "AVAILABLE"
              && message.leaseId == null) finish(true);
          } catch { /* Cleanup cannot expose malformed payload text. */ }
        };
        const closed = () => finish(false);
        socket.on("message", releasedMessage);
        socket.once("close", closed);
        timer = setTimeout(() => finish(false), 1000);
        socket.send(JSON.stringify({ type: "control_release", leaseId: ownLeaseId }), error => {
          if (error) finish(false);
        });
      });
    }
    // Do not interrupt the CLI or send shell/provider input. The runner owns
    // CLI teardown; close only the socket opened by this probe.
    if (socket.readyState === WebSocket.CLOSED) return leaseReleased;
    await new Promise(resolve => {
      const timer = setTimeout(() => { socket.terminate(); resolve(); }, 1500);
      socket.once("close", () => { clearTimeout(timer); resolve(); });
      if (socket.readyState === WebSocket.OPEN) socket.close(1000, "acceptance complete");
      else socket.terminate();
    });
    return leaseReleased;
  }
  function close() {
    closePromise ??= performClose();
    return closePromise;
  }

  try {
    let completeSince = null;
    for (;;) {
      remaining();
      if (failure) throw failure;
      const current = observation.snapshot();
      if (current.complete) {
        completeSince ??= performance.now();
        // Reject early error/exit immediately following an initial ready frame.
        if (performance.now() - completeSince >= 500) break;
      }
      await delay(Math.min(50, remaining()));
    }
    return {
      snapshot() {
        if (failure) throw failure;
        requireCondition(socket.readyState === WebSocket.OPEN, "WS_CLOSED");
        const result = observation.snapshot();
        requireCondition(result.complete, "TERMINAL_INCOMPLETE");
        return result;
      },
      close,
    };
  } catch (error) { await close(); throw error; }
}

/** Real stack only. Callers must first initialize/read their own checkout state. */
export async function runAcceptance({ state, timeoutMs = 180000 }) {
  validateState(state, timeoutMs);
  const started = performance.now();
  const remaining = () => {
    const value = Math.ceil(timeoutMs - (performance.now() - started));
    requireCondition(value > 0, "TIMEOUT");
    return value;
  };
  const apiOrigin = `http://127.0.0.1:${state.ports.api}`;
  const webOrigin = `http://127.0.0.1:${state.ports.web}`;
  let cookie = null;
  let csrfToken = null;

  async function request(path, { origin = apiOrigin, method = "GET", body, json = true } = {}) {
    const headers = {};
    if (cookie) headers.Cookie = cookie;
    if (body !== undefined) headers["content-type"] = "application/json";
    if (method !== "GET" && csrfToken) headers["x-space-csrf-token"] = csrfToken;
    let response;
    try {
      response = await fetch(new URL(path, origin), { method, headers,
        body: body === undefined ? undefined : JSON.stringify(body), redirect: "error",
        signal: AbortSignal.timeout(Math.min(15000, remaining())) });
      const text = await readBoundedText(response);
      if (!json) return { status: response.status, body: text, headers: response.headers };
      requireCondition(response.headers.get("content-type")?.includes("application/json"), "HTTP_NOT_JSON");
      let parsed;
      try { parsed = JSON.parse(text); }
      catch { requireCondition(false, "HTTP_JSON"); }
      return { status: response.status, body: parsed, headers: response.headers };
    } catch (error) {
      if (error.code?.startsWith("DEV_STACK_ACCEPTANCE_")) throw error;
      requireCondition(false, "HTTP_TRANSPORT");
    }
  }

  for (;;) {
    try { assertReadiness(await request("/readyz?strict=1")); break; }
    catch (error) {
      if (!["DEV_STACK_ACCEPTANCE_NOT_READY", "DEV_STACK_ACCEPTANCE_HTTP_TRANSPORT"].includes(error.code)) throw error;
      await delay(Math.min(500, remaining()));
    }
  }

  const owner = acceptanceOwner(state);
  const setup = await request("/api/setup/status");
  requireCondition(setup.status === 200 && typeof setup.body?.setupRequired === "boolean", "SETUP_STATUS");
  let expectedRoomId = null;
  const ownerClaimedNow = setup.body.setupRequired;
  if (ownerClaimedNow) {
    // At most one claim attempt: never retry/reset a consumed token or replace
    // an owner. A later run can authenticate with this checkout's derived key.
    const claim = await request("/api/setup/claim", { method: "POST", body: {
      token: state.secrets.setupToken, email: owner.email, password: owner.password,
    } });
    assertOwner(claim, owner.email);
    requireCondition(nonempty(claim.body.starterRoomId), "CLAIM_STARTER_ROOM");
    expectedRoomId = claim.body.starterRoomId;
  }
  const login = await request("/api/auth/login", { method: "POST", body: owner });
  assertOwner(login, owner.email);
  cookie = sessionCookie(login.headers);
  assertOwner(await request("/api/auth/me"), owner.email);
  const csrf = await request("/api/auth/csrf");
  requireCondition(csrf.status === 200 && csrf.body?.headerName === "x-space-csrf-token"
    && typeof csrf.body.csrfToken === "string" && csrf.body.csrfToken.length >= 16
    && csrf.body.csrfToken.length <= 512, "CSRF");
  csrfToken = csrf.body.csrfToken;

  const starter = await request("/api/setup/starter-room", { method: "POST", body: {} });
  const roomId = assertStarterRoom(starter, expectedRoomId);
  const pane = selectStarterPane(await request(`/api/panes?roomId=${encodeURIComponent(roomId)}`), roomId);
  const cwd = join(state.stateDir, "workspaces");
  const expected = { roomId, paneId: pane.id, cwd };
  const allocation = await request(`/api/panes/${encodeURIComponent(pane.id)}/cli/session`, {
    method: "POST", body: { runtimeId: RUNTIME, cwd, includeTranscript: false },
  });
  Object.assign(expected, assertSession(allocation, expected));

  const web = await request("/", { origin: webOrigin, json: false });
  requireCondition(web.status === 200 && /<div\s+id=["']root["']/u.test(web.body)
    && /<script\b[^>]*type=["']module["']/u.test(web.body), "WEB_SHELL");
  // This catches a dev web server whose /api proxy silently targets stable.
  assertOwner(await request("/api/auth/me", { origin: webOrigin }), owner.email);

  const terminal = await attachTerminal(allocation.body, apiOrigin, cookie, remaining);
  try {
    const active = await request(`/api/panes/${encodeURIComponent(pane.id)}/cli/session?includeTranscript=false`);
    assertSession(active, expected, { requireRunning: true });
    assertReadiness(await request("/readyz?strict=1"));
    const observed = terminal.snapshot();
    requireCondition(await terminal.close(), "LEASE_RELEASE_NOT_ACKNOWLEDGED");
    return {
      schema: "spaceapp.dev-stack-acceptance.v1", passed: true,
      scope: "OWNER_HTTP_CLI_WEBSOCKET_ONLY", project: state.project,
      elapsedMs: Math.round(performance.now() - started), ownerClaimedNow,
      ownerLoginVerified: true, csrfMutationVerified: true,
      postgresReady: true, temporalWorkerPollersReady: true, cliHostReady: true,
      starterRoomId: roomId, paneId: pane.id, sessionId: expected.sessionId, runtimeId: RUNTIME,
      sessionStatus: "RUNNING", workspaceCwdVerified: true,
      webShellServed: true, webApiProxyAuthVerified: true,
      websocketProtocol: 2, websocketReady: true, websocketPong: true,
      terminalOutputBytes: observed.outputBytes, terminalOutputFrames: observed.outputFrames,
      terminalPrintableCharacters: observed.printableCharacters,
      openCodeBrandingObserved: observed.openCodeBrandingObserved,
      terminalOutputMayIncludeReplay: true, terminalInputSent: false,
      terminalControlLeaseReleased: true,
      browserUiVerified: false, providerCompletionVerified: false,
      completeIssueAcceptance: false, cliSessionLeftRunning: true,
      limitations: ["No browser was automated; xterm layout and full OpenCode TUI are not certified.",
        "PTY output may include replay; branding is an observation, not independent binary attestation.",
        "No workflow execution or provider completion was requested or verified."],
    };
  } finally { await terminal.close(); }
}
