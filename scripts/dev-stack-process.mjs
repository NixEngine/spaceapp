import { readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";

const digest = value => createHash("sha256").update(value).digest("hex");

/** Local process ownership, not authorization against a hostile same-user writer. */
export function processIdentity(pid) {
  if (!Number.isSafeInteger(pid) || pid <= 1) throw new Error("Invalid managed process PID.");
  try {
    if (process.platform === "linux") {
      const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
      const fields = stat.slice(stat.lastIndexOf(")") + 1).trim().split(/\s+/);
      if (fields[0] === "Z") return null;
      const boot = readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim();
      return { pid, pgid: Number(fields[2]), startId: `${boot}:${fields[19]}` };
    }
    if (process.platform === "darwin") {
      const output = execFileSync("ps", ["-p", String(pid), "-o", "pgid=", "-o", "lstart=", "-o", "command="], {
        encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], timeout: 3000
      }).trim();
      const match = /^(\d+)\s+(.{24})\s+(.+)$/.exec(output);
      if (!match) throw new Error("Cannot establish process creation identity.");
      return { pid, pgid: Number(match[1]), startId: `${match[2]}:${digest(match[3])}` };
    }
    throw new Error("The dev stack uses Unix process groups; run Windows inside WSL2.");
  } catch (error) {
    if (error.code === "ENOENT" || (process.platform === "darwin" && error.status === 1)) return null;
    throw error;
  }
}

export function sameProcess(record, observed) {
  return Boolean(record && observed && Number.isSafeInteger(record.pid) && record.pid > 1 &&
    record.pid === observed.pid && record.pgid === record.pid && observed.pgid === record.pgid &&
    typeof record.startId === "string" && record.startId.length > 0 && record.startId === observed.startId);
}

/** Supervisor shares its caller's group: signal only its positively identified PID. */
export function signalOwnedProcess(record, signal = "SIGTERM", { inspect = processIdentity, kill = process.kill } = {}) {
  if (!["SIGTERM", "SIGKILL"].includes(signal)) throw new Error("Unsupported teardown signal.");
  const current = inspect(record?.pid);
  if (!current) return false;
  if (!Number.isSafeInteger(record.pid) || record.pid <= 1 || record.pid !== current.pid ||
      record.pgid !== current.pgid || !record.startId || record.startId !== current.startId) {
    throw new Error("Supervisor creation identity changed; refusing to signal it.");
  }
  try { kill(record.pid, signal); }
  catch (error) { if (error.code !== "ESRCH") throw error; }
  return true;
}

/** Never signal a numeric PID/PGID based solely on a persisted PID file. */
export function signalOwnedGroup(record, signal = "SIGTERM", { inspect = processIdentity, kill = process.kill } = {}) {
  if (!["SIGTERM", "SIGKILL"].includes(signal)) throw new Error("Unsupported teardown signal.");
  const current = inspect(record?.pid);
  if (!current) return false;
  if (!sameProcess(record, current)) throw new Error("Managed process identity changed; refusing to signal it.");
  try { kill(-record.pgid, signal); }
  catch (error) { if (error.code !== "ESRCH") throw error; }
  return true;
}

/** A dead group leader does not prove its descendants are gone. Never hide remnants. */
export function assertGroupsGone(records, { kill = process.kill } = {}) {
  for (const record of records) {
    if (!Number.isSafeInteger(record?.pgid) || record.pgid <= 1 || record.pgid !== record.pid) {
      throw new Error("Invalid managed process group.");
    }
    try { kill(-record.pgid, 0); }
    catch (error) { if (error.code === "ESRCH") continue; throw error; }
    throw new Error("Managed process group remains; cleanup is incomplete.");
  }
}
