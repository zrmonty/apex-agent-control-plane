import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import test from "node:test";
import { fromBinary } from "@bufbuild/protobuf";
import { FileDescriptorSetSchema } from "@bufbuild/protobuf/wkt";
const root = new URL("../../packages/apex-contracts-ts/src/gen/", import.meta.url);

test("frozen event envelope has an independently generated decoder without management namespace collision", async () => {
  const file = new URL("event/apex/v1/event_pb.js", root);
  assert.equal(existsSync(file), true, "event decoder must be generated in its own namespace tree");
  const generated = await import(file.href);
  assert.equal(generated.EventEnvelopeSchema.typeName, "apex.v1.EventEnvelope");
  assert.equal(generated.EventIngest.method.ingest.name, "Ingest");
  const management = fromBinary(FileDescriptorSetSchema, readFileSync(new URL("descriptor.binpb", root)));
  const events = fromBinary(FileDescriptorSetSchema, readFileSync(new URL("event/descriptor.binpb", root)));
  assert.ok(!management.file.some(file => file.name === "apex/v1/event.proto"));
  assert.ok(events.file.some(file => file.name === "apex/v1/event.proto"));
  assert.ok(!events.file.some(file => file.name === "apex/v1/control.proto"));
  const browser = JSON.parse(readFileSync(new URL("browser-rpcs.json", root), "utf8"));
  assert.ok(browser.every(method => !method.service.includes("EventIngest")));
});
