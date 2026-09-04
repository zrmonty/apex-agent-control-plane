import { spawnSync } from "node:child_process";
import { readdir } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const packageRoot = path.resolve(scriptDir, "..");
const explicitFiles = process.argv.slice(2).filter((argument) => argument !== "--");
const tsxCli = path.join(packageRoot, "node_modules", "tsx", "dist", "cli.mjs");

async function findTestFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];

  for (const entry of entries) {
    const absolutePath = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      files.push(...(await findTestFiles(absolutePath)));
      continue;
    }

    if (entry.isFile() && entry.name.endsWith(".test.ts")) {
      files.push(path.relative(packageRoot, absolutePath));
    }
  }

  return files.sort();
}

const testFiles = explicitFiles.length > 0 ? explicitFiles : await findTestFiles(path.join(packageRoot, "src"));
const result = spawnSync(process.execPath, [tsxCli, "--test", ...testFiles], {
  cwd: packageRoot,
  stdio: "inherit",
});

if (result.error) {
  console.error(result.error);
}

process.exit(result.status ?? 1);
