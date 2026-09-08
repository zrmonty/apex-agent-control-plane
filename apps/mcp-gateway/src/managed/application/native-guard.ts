// Bounded relay on a newly owned internal fixture network. This is NOT the
// production guard policy/outer topology or a signed-deployment acceptance.
import assert from "node:assert/strict";
import { GuardEgressRelay } from "../guard/relay-server.js";
assert.equal(process.platform, "linux");
const relay = new GuardEgressRelay({ bindAddress: "10.248.245.3", port: 18080,
  gatewayAddress: "10.248.245.2", outboundAddress: "10.248.245.3",
  lookup(host, done) {
    assert.equal(host, "gateway.test"); done(null, [{ address: "10.248.245.2", family: 4 }]);
  }, policy: { select(host, port) {
    assert.equal(host, "gateway.test"); assert.ok([41001, 41002, 41003].includes(port));
    return { host, port, pin: () => ({ host, port, address: "10.248.245.2", family: 4 }) };
  } } });
await relay.listen(); process.stdout.write("owned application fixture guard listening\n");
for (const signal of ["SIGINT", "SIGTERM"] as const) process.once(signal, () => { void relay.close(); });
