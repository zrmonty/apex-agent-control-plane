import { startGuardProcess } from "./process.js";

// Image-owned guard entry only. Agent launch/inspection supplies the fixed stage;
// this process never reads gateway keys, Docker sockets or caller-selected code.
const owner = startGuardProcess({ env: process.env, onFatal() {
  try { process.stderr.write("managed guard cleanup uncertain\n"); }
  finally { process.exit(70); }
} });
let interrupted = false;
const stop = () => { interrupted = true; owner.cancel(); };
process.once("SIGINT", stop); process.once("SIGTERM", stop);
try { await owner.result; process.stdout.write("managed guard ready\n"); }
catch { process.stderr.write("managed guard refused safely\n"); process.exitCode = 1; }
await owner.closed;
process.off("SIGINT", stop); process.off("SIGTERM", stop);
if (!interrupted) process.exitCode = 1;
