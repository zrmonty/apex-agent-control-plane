import test from "node:test";
import assert from "node:assert/strict";
import { ingressFixture, send, pki } from "./fixture.js";
import { upstreamClient } from "../bootstrap/runtime-materials/client-fixture.js";

test("HTTPS metadata requires a chain-valid edge with the exact protected leaf pin", async t => {
  const f = await ingressFixture(t);
  const request = { method: "GET", path: "/.well-known/oauth-protected-resource", token: null };
  assert.equal((await send(f.address.port, request)).status, 200);
  for (const cert of [null, pki.evidence, pki.reissued, upstreamClient]) {
    await assert.rejects(send(f.address.port, { ...request, cert }));
  }
  await assert.rejects(send(f.address.port, { ...request, servername: "wrong.test" }));
});
