import { mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generate } from "./generate.mjs";
import { buf, withInput, generatedRoot, contractsRoot } from "./tooling.mjs";
function files(root, prefix = "") {
  return readdirSync(join(root, prefix), { withFileTypes: true }).flatMap(entry => {
    const path = prefix ? prefix + "/" + entry.name : entry.name;
    return entry.isDirectory() ? files(root, path) : [path];
  }).sort();
}
const temporary = mkdtempSync(join(tmpdir(), "apex-contract-verify-"));
try {
  generate(temporary);
  const expected = files(temporary), actual = files(generatedRoot);
  if (JSON.stringify(expected) !== JSON.stringify(actual)) throw new Error("generated file inventory drift");
  for (const file of expected) {
    if (!readFileSync(join(temporary, file)).equals(readFileSync(join(generatedRoot, file)))) throw new Error("generated drift: " + file);
  }
  withInput(input => buf(["breaking", input, "--against", join(contractsRoot, "compatibility-baseline.binpb")]));
  console.log("Generated artifacts match; existing protobuf fields and services remain compatible.");
} finally {
  rmSync(temporary, { recursive: true, force: true });
}
