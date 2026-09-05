import { spawn } from 'node:child_process';

// No shell, stderr retention, descendant shell, or unbounded output allocation.
// Killing a Docker CLI is not cancellation of its daemon operation: the harness
// must separately recover ownership and clean up after an uncertain response.
export async function runBounded(file, args, { timeoutMs = 15_000, maxBytes = 65_536 } = {}) {
  const failed = { ok: false, code: 'COMMAND_FAILED', stdout: '' };
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 60_000 ||
      !Number.isInteger(maxBytes) || maxBytes < 1 || maxBytes > 65_536) return failed;
  return new Promise((resolve) => {
    let child;
    try {
      child = spawn(file, args, { shell: false, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
    } catch { resolve(failed); return; }
    let done = false;
    let failure;
    let bytes = 0;
    let output = [];
    let killDeadline;
    const finish = (exitCode) => {
      if (done) return;
      done = true;
      clearTimeout(deadline);
      clearTimeout(killDeadline);
      child.stdout.destroy();
      child.stderr.destroy();
      child.unref();
      resolve({ ok: failure === undefined && exitCode === 0,
        code: failure ?? (exitCode === 0 ? 'OK' : 'COMMAND_FAILED'),
        stdout: failure === undefined ? Buffer.concat(output).toString('utf8') : '' });
      output = [];
    };
    const stop = (code) => {
      if (failure !== undefined || done) return;
      failure = code;
      output = [];
      try { child.kill('SIGKILL'); } catch { /* Still return bounded failure. */ }
      killDeadline = setTimeout(() => finish(null), 500);
    };
    const deadline = setTimeout(() => stop('COMMAND_TIMEOUT'), timeoutMs);
    const consume = (chunk, stdout) => {
      if (done || failure !== undefined) return;
      bytes += chunk.length;
      if (bytes > maxBytes) { stop('COMMAND_OUTPUT_LIMIT'); return; }
      if (stdout) output.push(chunk);
    };
    child.stdout.on('data', (chunk) => consume(chunk, true));
    child.stderr.on('data', (chunk) => consume(chunk, false));
    child.on('error', () => { failure = 'COMMAND_FAILED'; finish(null); });
    child.on('close', finish);
  });
}
