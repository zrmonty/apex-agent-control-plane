import { spawn as nodeSpawn } from "node:child_process";
import { EventEmitter } from "node:events";
import path from "node:path";

import { GatewayError } from "../contracts.js";
import type { ProxyRevisionConfig } from "./config.js";

const VALUE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,255}$/;
const ENVIRONMENT_NAME_PATTERN = /^[A-Z][A-Z0-9_]{0,63}$/;
const MAX_INPUT_BYTES = 64 * 1024;
const SECRET_KEY_PATTERN = /pass(word)?|secret|token|credential|private|authorization/i;

export type CliResult = Readonly<{
  exitCode: number;
  stdout: unknown;
  stderrBytes: number;
  durationMs: number;
}>;

export interface CliRunner {
  run(profileId: string, input: unknown): Promise<CliResult>;
}

export interface SpawnedCliProcess extends EventEmitter {
  readonly stdout: EventEmitter;
  readonly stderr: EventEmitter;
  kill(signal?: NodeJS.Signals): boolean | void;
}

type SpawnOptions = Readonly<{
  cwd: string;
  env: NodeJS.ProcessEnv;
  shell: false;
  stdio: ["ignore", "pipe", "pipe"];
}>;

export type CliRunnerOptions = Readonly<{
  sandboxRoot: string;
  environment?: NodeJS.ProcessEnv;
  executableAllowlist?: ReadonlyMap<string, Readonly<{ path: string; digest: string }>>;
  spawn?: (command: string, args: readonly string[], options: SpawnOptions) => SpawnedCliProcess;
}>;

export class FixedCliRunner implements CliRunner {
  private readonly profiles = new Map<string, ProxyRevisionConfig["cliProfiles"][number]>();
  private readonly spawn: NonNullable<CliRunnerOptions["spawn"]>;

  constructor(
    config: Pick<ProxyRevisionConfig, "cliProfiles">,
    private readonly options: CliRunnerOptions,
  ) {
    this.spawn = options.spawn ?? defaultSpawn;
    for (const profile of config.cliProfiles) {
      validateProfile(profile, options.executableAllowlist);
      if (this.profiles.has(profile.profileId)) {
        throw invalid();
      }
      this.profiles.set(profile.profileId, profile);
    }
  }

  async run(profileId: string, input: unknown): Promise<CliResult> {
    const profile = this.profiles.get(profileId);
    if (profile === undefined) {
      throw invalid();
    }
    const args = buildArguments(profile, input);
    const executable = this.options.executableAllowlist?.get(profile.executableRef);
    if (executable === undefined) {
      throw invalid();
    }
    const environment = allowlistedEnvironment(profile.environmentAllowlist, this.options.environment ?? {});
    const cwd = sandboxWorkingDirectory(this.options.sandboxRoot, profile.workingDirectory);
    const startedAt = performance.now();
    const child = this.spawn(executable.path, args, {
      cwd,
      env: environment,
      shell: false,
      stdio: ["ignore", "pipe", "pipe"],
    });
    const stdout: Buffer[] = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let settled = false;
    let timeout: NodeJS.Timeout | undefined;

    return new Promise<CliResult>((resolve, reject) => {
      const fail = (error: GatewayError): void => {
        if (settled) return;
        settled = true;
        if (timeout !== undefined) clearTimeout(timeout);
        child.kill("SIGKILL");
        reject(error);
      };
      const succeed = (exitCode: number | null): void => {
        if (settled) return;
        settled = true;
        if (timeout !== undefined) clearTimeout(timeout);
        const code = exitCode ?? -1;
        if (!profile.allowedExitCodes.includes(code)) {
          reject(executionFailed());
          return;
        }
        let output: unknown;
        try {
          output = parseAndFilterOutput(Buffer.concat(stdout).toString("utf8"));
        } catch {
          reject(executionFailed());
          return;
        }
        resolve({
          exitCode: code,
          stdout: output,
          stderrBytes,
          durationMs: Math.max(0, Math.round(performance.now() - startedAt)),
        });
      };
      child.stdout.on("data", (chunk: Buffer | string) => {
        const bytes = Buffer.byteLength(chunk);
        stdoutBytes += bytes;
        if (stdoutBytes > profile.maxOutputBytes) {
          fail(executionFailed());
          return;
        }
        stdout.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
      });
      child.stderr.on("data", (chunk: Buffer | string) => {
        stderrBytes += Buffer.byteLength(chunk);
        if (stderrBytes > profile.maxOutputBytes) {
          fail(executionFailed());
        }
      });
      child.once("error", () => fail(executionFailed()));
      child.once("close", (code: number | null) => succeed(code));
      timeout = setTimeout(() => fail(executionFailed()), profile.timeoutMs);
    });
  }
}

function validateProfile(
  profile: ProxyRevisionConfig["cliProfiles"][number],
  allowlist: CliRunnerOptions["executableAllowlist"],
): void {
  if (
    profile.shell !== false ||
    profile.filesystemPolicy !== "read-only" ||
    profile.networkPolicy !== "declared-egress" ||
    !profile.executableDigest.startsWith("sha256:") ||
    allowlist?.get(profile.executableRef)?.digest !== profile.executableDigest ||
    !profile.workingDirectory.startsWith("/tmp/") ||
    profile.allowedExitCodes.length === 0 ||
    profile.fixedArgv.some((argument) => !VALUE_PATTERN.test(argument)) ||
    profile.environmentAllowlist.some((name) => !ENVIRONMENT_NAME_PATTERN.test(name))
  ) {
    throw invalid();
  }
}

function buildArguments(
  profile: ProxyRevisionConfig["cliProfiles"][number],
  input: unknown,
): readonly string[] {
  if (!isRecord(input)) {
    throw invalid();
  }
  let serialized: string;
  try {
    serialized = JSON.stringify(input);
  } catch {
    throw invalid();
  }
  if (Buffer.byteLength(serialized, "utf8") > MAX_INPUT_BYTES) {
    throw invalid();
  }
  const allowedNames = new Set(profile.argvSchema.fields.map((field) => field.name));
  for (const key of Object.keys(input)) {
    if (!allowedNames.has(key)) throw invalid();
  }
  const values: string[] = [];
  for (const field of profile.argvSchema.fields) {
    const value = input[field.name];
    if (value === undefined) {
      if (field.required) throw invalid();
      continue;
    }
    if ((typeof value !== "string" && typeof value !== "number" && typeof value !== "boolean") || String(value).length === 0 || !VALUE_PATTERN.test(String(value))) {
      throw invalid();
    }
    values.push(String(value));
  }
  return [...profile.fixedArgv, ...values];
}

function allowlistedEnvironment(
  names: readonly string[],
  source: NodeJS.ProcessEnv,
): NodeJS.ProcessEnv {
  const environment: NodeJS.ProcessEnv = {};
  for (const name of names) {
    const value = source[name];
    if (value !== undefined && !SECRET_KEY_PATTERN.test(name)) {
      environment[name] = value;
    }
  }
  return environment;
}

function sandboxWorkingDirectory(root: string, configured: string): string {
  const relative = configured.slice("/tmp/".length);
  if (relative.length === 0 || relative.includes("..") || path.isAbsolute(relative)) {
    throw invalid();
  }
  const resolvedRoot = path.resolve(root);
  const resolved = path.resolve(resolvedRoot, relative);
  if (resolved !== resolvedRoot && !resolved.startsWith(`${resolvedRoot}${path.sep}`)) {
    throw invalid();
  }
  return resolved;
}

function parseAndFilterOutput(serialized: string): unknown {
  let output: unknown;
  try {
    output = JSON.parse(serialized);
  } catch {
    throw executionFailed();
  }
  return filterOutput(output, 0);
}

function filterOutput(value: unknown, depth: number): unknown {
  if (depth > 8 || value === null || typeof value === "boolean" || typeof value === "number") {
    return value;
  }
  if (typeof value === "string") {
    return value.length <= 4096 ? value : "[redacted]";
  }
  if (Array.isArray(value)) {
    return value.slice(0, 128).map((item) => filterOutput(item, depth + 1));
  }
  if (isRecord(value)) {
    const output: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(value).slice(0, 128)) {
      if (!SECRET_KEY_PATTERN.test(key)) {
        output[key] = filterOutput(item, depth + 1);
      }
    }
    return output;
  }
  throw executionFailed();
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function defaultSpawn(command: string, args: readonly string[], options: SpawnOptions): SpawnedCliProcess {
  return nodeSpawn(command, [...args], options) as SpawnedCliProcess;
}

function invalid(): GatewayError {
  return new GatewayError("INVALID_INPUT", "CLI invocation rejected safely");
}

function executionFailed(): GatewayError {
  return new GatewayError("ADAPTER_FAILED", "CLI execution failed safely");
}
