import assert from "node:assert/strict";
import test from "node:test";

import { normalizeGrpcTarget } from "./grpc.js";

test("normalizes HTTPS endpoints without exposing URL credentials", () => {
  assert.equal(normalizeGrpcTarget("https://control-plane-api:9443/"), "control-plane-api:9443");
  assert.throws(
    () => normalizeGrpcTarget("https://user:password@control-plane-api:9443/"),
    /GOVERNANCE_UNAVAILABLE/,
  );
});

test("rejects endpoint URL components that grpc would silently discard", () => {
  assert.throws(() => normalizeGrpcTarget("https://control-plane-api:9443/rpc"), /GOVERNANCE_UNAVAILABLE/);
  assert.throws(() => normalizeGrpcTarget("https://control-plane-api:9443/?token=secret"), /GOVERNANCE_UNAVAILABLE/);
  assert.throws(() => normalizeGrpcTarget("https://control-plane-api:9443/#secret"), /GOVERNANCE_UNAVAILABLE/);
  assert.throws(() => normalizeGrpcTarget("https://control-plane-api:9443/%2e%2e"), /GOVERNANCE_UNAVAILABLE/);
  assert.throws(() => normalizeGrpcTarget("https://control\n-plane-api:9443/"), /GOVERNANCE_UNAVAILABLE/);
  assert.throws(() => normalizeGrpcTarget("https://control\\plane-api:9443/"), /GOVERNANCE_UNAVAILABLE/);
  assert.throws(() => normalizeGrpcTarget(" https://control-plane-api:9443/"), /GOVERNANCE_UNAVAILABLE/);
  assert.throws(() => normalizeGrpcTarget("https://control-plane-api:9443/ "), /GOVERNANCE_UNAVAILABLE/);
});
