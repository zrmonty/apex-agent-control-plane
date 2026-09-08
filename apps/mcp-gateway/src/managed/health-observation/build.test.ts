import test from "node:test";
import assert from "node:assert/strict";
import ts from "typescript";
import { mkdtemp, readFile, readdir, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

test("production build ships the separate fixed health executable and its graph, never test helpers", async () => {
  const root = fileURLToPath(new URL("../../../", import.meta.url));
  const out = await mkdtemp(join(tmpdir(), "apex-health-build-"));
  try {
    const config = ts.readConfigFile(join(root, "tsconfig.build.json"), ts.sys.readFile);
    assert.equal(config.error, undefined);
    const parsed = ts.parseJsonConfigFileContent(config.config, ts.sys, root);
    const program = ts.createProgram(parsed.fileNames, { ...parsed.options, outDir: out });
    assert.deepEqual(ts.getPreEmitDiagnostics(program).map(d => ts.flattenDiagnosticMessageText(d.messageText, "\n")), []);
    assert.equal(program.emit().emitSkipped, false);
    const entry = join(out, "managed/health-process.js");
    assert.equal((await stat(entry)).isFile(), true);
    const visited = new Set<string>();
    async function visit(path: string): Promise<void> {
      if (visited.has(path)) return; visited.add(path);
      const source = await readFile(path, "utf8");
      for (const item of ts.preProcessFile(source).importedFiles) {
        if (item.fileName.startsWith(".")) await visit(resolve(dirname(path), item.fileName));
      }
    }
    await visit(entry);
    for (const required of ["health-probe.js", "managed/health-observation/owner.js", "managed/bootstrap/stage-owner.js"]) {
      assert.ok(visited.has(join(out, required)), required);
    }
    for (const file of await readdir(out, { recursive: true })) {
      assert.doesNotMatch(file.replaceAll("\\", "/"), /(?:\.test\.js$|isolated-transport\.js$|(?:^|\/)(?:fixture|testing)\.js$|health-testing\/)/);
    }
  } finally { await rm(out, { recursive: true, force: true }); }
});
