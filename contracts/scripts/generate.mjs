import { mkdirSync, readFileSync, writeFileSync, readdirSync } from "node:fs";
import { createHash } from "node:crypto";
import { resolve, join } from "node:path";
import { pathToFileURL } from "node:url";
import { fromBinary } from "@bufbuild/protobuf";
import { FileDescriptorSetSchema } from "@bufbuild/protobuf/wkt";
import { buf, withInput, generatedRoot, plugin } from "./tooling.mjs";
export function generate(destination = generatedRoot) {
  mkdirSync(destination, { recursive: true });
  withInput(input => {
    buf(["build", input, "--as-file-descriptor-set", "--exclude-source-info", "-o", join(destination, "descriptor.binpb")]);
    buf(["generate", input, "--template", JSON.stringify({ version: "v2", plugins: [{
      local: [process.execPath, plugin], out: destination, opt: ["target=js+dts", "import_extension=js"]
    }] })]);
  });
  const descriptor = fromBinary(FileDescriptorSetSchema, readFileSync(join(destination, "descriptor.binpb")));
  const approved = new Set(["apex.v1.McpProxyService"]);
  const methods = descriptor.file.flatMap(file => file.service.flatMap(service => {
    const fullName = file.package + "." + service.name;
    if (!approved.has(fullName)) return [];
    return service.method.filter(method => !method.clientStreaming && !method.serverStreaming).map(method => ({
      service: fullName, method: method.name,
      path: "/api/apex/v1/" + service.name + "/" + method.name,
      input: method.inputType.slice(1), output: method.outputType.slice(1),
    }));
  })).sort((a, b) => a.path.localeCompare(b.path, "en"));
  writeFileSync(join(destination, "browser-rpcs.json"), JSON.stringify(methods, null, 2) + "\n");
  const files = {};
  for (const entry of readdirSync(join(destination, "apex/v1")).sort()) {
    const name = "apex/v1/" + entry;
    // Proto comments can preserve checkout line endings. Canonicalize generated
    // text before hashing so Windows and Linux produce identical artifacts.
    const path = join(destination, name);
    writeFileSync(path, readFileSync(path, "utf8")
      .replace(/\r\n/g, "\n").replace(/[ \t]+$/gm, "").trimEnd() + "\n");
    files[name] = createHash("sha256").update(readFileSync(join(destination, name))).digest("hex");
  }
  writeFileSync(join(destination, "manifest.json"), JSON.stringify({ generator: "protoc-gen-es@2.14.1", files }, null, 2) + "\n");
}
if (import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  generate(process.argv[2] ? resolve(process.argv[2]) : generatedRoot);
}
