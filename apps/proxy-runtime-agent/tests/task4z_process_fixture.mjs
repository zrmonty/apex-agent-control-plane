// Explicitly unsigned native process fixture, never a production gateway.
// Exit before staying alive unless the configured workload user can read every
// sealed file. No stage contents, credentials or proof leave this process.
import fs from 'node:fs';
import path from 'node:path';
if (process.getuid() !== 10001 || process.getgid() !== 10001) process.exit(90);
const root = '/apex/runtime';
const files = [];
function inspect(dir) {
  const stat = fs.lstatSync(dir);
  if (!stat.isDirectory() || stat.uid !== 10001 || stat.gid !== 10001 ||
      (stat.mode & 0o7777) !== 0o500) process.exit(91);
  for (const name of fs.readdirSync(dir)) {
    const file = path.join(dir, name);
    const entry = fs.lstatSync(file);
    if (entry.isDirectory()) { inspect(file); continue; }
    if (!entry.isFile() || entry.nlink !== 1 || entry.uid !== 10001 ||
        entry.gid !== 10001 || (entry.mode & 0o7777) !== 0o400) process.exit(92);
    const bytes = fs.readFileSync(file);
    if (!bytes.length) process.exit(93);
    bytes.fill(0);
    files.push(path.relative(root, file));
  }
}
inspect(root);
const guard = process.argv[1].endsWith('/guard/main.js');
if (guard ? files.length !== 1 || files[0] !== 'guard-config.json'
          : !files.includes('instance-proof') || !files.includes('runtime-revision.json')) process.exit(94);
// The fixed fixture marker contains filenames and mode checks only, never data.
fs.writeFileSync('/tmp/task4z-readable.json', JSON.stringify({uid: 10001, gid: 10001, files}), {mode: 0o600});
// Fixed public process metadata is observable without exec or copying tmpfs.
process.title = guard ? 'task4z-read-guard' : 'task4z-read-gateway';
setInterval(() => {}, 1000);
