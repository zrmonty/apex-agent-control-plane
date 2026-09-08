// Private unsigned fixture. Actual application root and packaged health child;
// authority/evidence peers remain synthetic and never select SERVE.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { startManagedApplication } from "../application.js";
import { nativeServices } from "./native-services.js";
import { bounded, cleanupFixture } from "./native-observation.js";

assert.equal(process.platform, "linux"); assert.equal(process.getuid!(), 10001);
const client = JSON.parse(await readFile("/fixture/client.json", "utf8")) as { env: NodeJS.ProcessEnv };
for (const [key, value] of Object.entries(client.env)) assert.equal(process.env[key], value);
const services = await nativeServices();
let fatals = 0;
const owner = startManagedApplication({ env: process.env, onFatal() { fatals++; } });
const stop = new Promise<void>(resolve => {
  process.once("SIGTERM", () => resolve()); process.once("SIGINT", () => resolve());
});
try {
  await owner.result;
  console.log("owned daemon health gateway ready");
  await bounded(stop, 45000, "external daemon health fixture deadline");
  owner.cancel(); await bounded(owner.closed, 4500, "gateway physical close");
  assert.deepEqual(await owner.completionHandoff, []);
  assert.equal(fatals, 0); assert.equal(services.stats().toolCalls, 0);
  assert.equal(services.stats().event, undefined);
  assert.ok(services.methods.every(method => !method.includes("ManagedCall")));
  console.log("owned daemon health gateway closed without business admission");
} finally {
  assert.equal(await cleanupFixture(owner, services.close), "fixture-cleaned");
}
