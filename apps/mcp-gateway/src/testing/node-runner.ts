import { spawn } from "node:child_process";

type NodeRunOptions = Readonly<{
  entrypoint: string;
  cwd: string;
  env?: NodeJS.ProcessEnv;
  args?: readonly string[];
  input?: string;
  timeoutMs?: number;
}>;

export type NodeRunResult = Readonly<{
  pid: number | undefined;
  code: number | null;
  signal: NodeJS.Signals | null;
  reaped: boolean;
  stdout: Buffer;
  stderr: Buffer;
}>;

type Failure = "timeout" | "stdout-overflow" | "stderr-overflow" | "spawn" | "io";

export class NodeRunError extends Error {
  constructor(readonly reason: Failure, readonly result: NodeRunResult, readonly cleanupTimedOut = false) {
    super(`node test child ${reason}${cleanupTimedOut ? "; cleanup deadline exceeded" : ""}`);
    this.name = "NodeRunError";
  }
}

/** Directly owns Node, never a CLI launcher. This test helper is not a process-
 * tree supervisor for entrypoints that deliberately spawn detached children. */
export async function runNode(options: NodeRunOptions): Promise<NodeRunResult> {
  const timeoutMs = options.timeoutMs ?? 5000;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 5000) {
    throw new RangeError("node test child timeout is outside its safe bound");
  }
  const child = spawn(process.execPath,
    ["--import", "tsx", options.entrypoint, ...options.args ?? []],
    { cwd: options.cwd, env: options.env, stdio: "pipe", windowsHide: true });
  return new Promise((resolve, reject) => {
    // Copy into fixed byte buffers, never concatenate strings or retain chunks.
    const stdout = Buffer.alloc(16384), stderr = Buffer.alloc(16384);
    let stdoutLength = 0, stderrLength = 0;
    let code: number | null = null;
    let signal: NodeJS.Signals | null = null;
    let reaped = false, settled = false;
    let failure: Failure | undefined;
    let executionTimer: NodeJS.Timeout | undefined;
    let forceTimer: NodeJS.Timeout | undefined;
    let cleanupTimer: NodeJS.Timeout | undefined;
    const terminate = (requested: NodeJS.Signals) => {
      if (!reaped && child.pid !== undefined) {
        try { child.kill(requested); } catch { /* Cleanup deadline still governs. */ }
      }
    };
    function finish(cleanupTimedOut = false): void {
      if (settled) return;
      settled = true;
      clearTimeout(executionTimer); clearTimeout(forceTimer); clearTimeout(cleanupTimer);
      child.stdin.destroy(); child.stdout.destroy(); child.stderr.destroy();
      // A failed OS kill must be visible without retaining handles indefinitely.
      if (!reaped) child.unref();
      const result = { pid: child.pid, code, signal, reaped,
        stdout: stdout.subarray(0, stdoutLength), stderr: stderr.subarray(0, stderrLength) };
      if (failure) reject(new NodeRunError(failure, result, cleanupTimedOut));
      else resolve(result);
    }
    function fail(reason: Failure): void {
      if (failure || settled) return;
      failure = reason; // A later zero exit never converts a deadline into success.
      clearTimeout(executionTimer);
      child.stdin.destroy();
      forceTimer = setTimeout(() => terminate("SIGKILL"), 100);
      cleanupTimer = setTimeout(() => { terminate("SIGKILL"); finish(true); }, 1000);
      terminate("SIGTERM");
    }
    function capture(stream: "stdout" | "stderr", chunk: Buffer): void {
      if (settled || failure) return;
      const target = stream === "stdout" ? stdout : stderr;
      const length = stream === "stdout" ? stdoutLength : stderrLength;
      const kept = Math.min(chunk.byteLength, target.byteLength - length);
      chunk.copy(target, length, 0, kept);
      if (stream === "stdout") stdoutLength += kept;
      else stderrLength += kept;
      if (chunk.byteLength > kept) fail(`${stream}-overflow`);
    }
    child.stdout.on("data", (chunk: Buffer) => capture("stdout", chunk));
    child.stderr.on("data", (chunk: Buffer) => capture("stderr", chunk));
    child.stdin.on("error", error => { if ((error as NodeJS.ErrnoException).code !== "EPIPE") fail("io"); });
    child.stdout.on("error", () => fail("io")); child.stderr.on("error", () => fail("io"));
    child.once("error", () => { fail("spawn"); if (child.pid === undefined) finish(); });
    child.once("exit", (value, received) => { reaped = true; code = value; signal = received; });
    child.once("close", () => finish());
    executionTimer = setTimeout(() => fail("timeout"), timeoutMs);
    child.stdin.end(options.input ?? "");
  });
}
