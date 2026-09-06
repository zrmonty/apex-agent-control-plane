import assert from "node:assert/strict";
import test from "node:test";
import { create } from "@bufbuild/protobuf";
import { RuntimeNetworkGrantSchema } from "@apex/contracts";
import { compileGuardEgressPolicy } from "./egress-policy.js";

const excluded = ["10.77.0.0/16", "172.30.0.0/16"];
function grant(cidrs: string[], privateDestination = false, host = "api.example.test", port = 443) {
  return create(RuntimeNetworkGrantSchema, { grantId: "approved", host, port,
    privateDestination, approvedCidrs: cidrs });
}

// Removing host-policy intersection would permit .9.9; returning a DNS name
// instead of the checked numeric address would permit a later DNS rebind.
test("public declaration is narrowed by protected host CIDRs and returns a numeric pin", () => {
  const declared = grant([]), host = grant(["8.8.8.0/24"]);
  const policy = compileGuardEgressPolicy([declared], [host], excluded);
  const route = policy.select("api.example.test", 443);
  const pin = route.pin(["8.8.8.8"]);
  assert.deepEqual(pin, { host: "api.example.test", port: 443, address: "8.8.8.8", family: 4 });
  assert.ok(Object.isFrozen(pin));
  assert.throws(() => route.pin(["8.8.9.9"]), /guard egress refused safely/);
});

test("both CIDR restrictions apply and mixed permitted and denied DNS answers refuse", () => {
  const policy = compileGuardEgressPolicy([grant(["8.8.8.128/25"])], [grant(["8.8.8.0/24"])], excluded);
  const route = policy.select("api.example.test", 443);
  assert.equal(route.pin(["8.8.8.129"]).address, "8.8.8.129");
  for (const addresses of [["8.8.8.127"], ["8.8.8.129", "8.8.8.127"], [], ["api.example.test"]]) {
    assert.throws(() => route.pin(addresses), /guard egress refused safely/);
  }
});

test("private access requires matching independent grants and excludes future proxy pools", () => {
  const declared = grant(["10.0.0.0/8"], true), host = grant(["10.0.0.0/8"], true);
  const policy = compileGuardEgressPolicy([declared], [host], excluded);
  const route = policy.select("api.example.test", 443);
  assert.equal(route.pin(["10.20.30.40"]).family, 4);
  for (const address of ["10.77.0.2", "10.77.255.254", "169.254.169.254", "127.0.0.1"]) {
    assert.throws(() => route.pin([address]), /guard egress refused safely/);
  }
  assert.throws(() => compileGuardEgressPolicy([declared], [grant(["8.8.8.0/24"])], excluded), /guard egress refused safely/);
});

test("selection rejects unknown host or port before a resolver can be chosen", () => {
  const policy = compileGuardEgressPolicy([grant([])], [grant(["8.8.8.0/24"])], excluded);
  for (const [host, port] of [["other.example.test", 443], ["api.example.test", 80],
    ["API.EXAMPLE.TEST", 443], ["api.example.test.", 443]] as const) {
    assert.throws(() => policy.select(host, port), /guard egress refused safely/);
  }
  const route = policy.select("api.example.test", 443);
  assert.ok(Object.isFrozen(route));
  assert.deepEqual([route.host, route.port], ["api.example.test", 443]);
});

test("policy snapshots do not follow later mutations of caller-owned grants or exclusions", () => {
  const declared = grant([]), host = grant(["8.8.8.0/24"]), blocked = [...excluded];
  const policy = compileGuardEgressPolicy([declared], [host], blocked);
  declared.host = "other.example.test";
  host.approvedCidrs.splice(0, 1, "9.9.9.0/24");
  blocked.push("8.8.8.0/24");
  const route = policy.select("api.example.test", 443);
  assert.equal(route.pin(["8.8.8.8"]).address, "8.8.8.8");
  assert.throws(() => route.pin(["9.9.9.9"]), /guard egress refused safely/);
});

test("IPv6 ranges intersect without conversion through Number and IPv4-mapped bypass refuses", () => {
  const route = compileGuardEgressPolicy([grant(["2606:4700::/32"])],
    [grant(["2606:4700:4700::/48"])], excluded).select("api.example.test", 443);
  assert.deepEqual(route.pin(["2606:4700:4700::1111"]), {
    host: "api.example.test", port: 443, address: "2606:4700:4700::1111", family: 6,
  });
  for (const value of ["2606:4700:4701::1", "::ffff:8.8.8.8", "fe80::1%eth0", "::1", "fc00::1"]) {
    assert.throws(() => route.pin([value]), /guard egress refused safely/);
  }
  const privateRoute = compileGuardEgressPolicy([grant(["fd00::/8"], true)],
    [grant(["fd12::/16"], true)], ["fd12:7700::/32"]).select("api.example.test", 443);
  assert.equal(privateRoute.pin(["fd12:2200::1"]).family, 6);
  assert.throws(() => privateRoute.pin(["fd12:7700::2"]), /guard egress refused safely/);
});

test("a literal selector cannot be redirected to another allowed address", () => {
  const value = grant(["8.8.8.0/24"], false, "8.8.8.8");
  const route = compileGuardEgressPolicy([value], [value], excluded).select("8.8.8.8", 443);
  assert.equal(route.pin(["8.8.8.8"]).address, "8.8.8.8");
  assert.throws(() => route.pin(["8.8.8.9"]), /guard egress refused safely/);
});

test("invalid unselected entries, empty pin authority and ambiguous selectors refuse at compile", () => {
  const valid = grant(["8.8.8.0/24"]);
  const invalid = [
    grant([]), grant(["0.0.0.0/0"]), grant(["8.8.8.1/24"]), grant(["127.0.0.0/8"]),
    grant(["169.254.0.0/16"], true), grant(["8.8.8.0/24"], false, "localhost"),
    grant(["8.8.8.0/24"], false, "API.EXAMPLE.TEST"),
  ];
  for (const candidate of invalid) {
    assert.throws(() => compileGuardEgressPolicy([grant([])], [candidate], excluded), /guard egress refused safely/);
  }
  const unrelatedBad = grant(["127.0.0.0/8"], false, "other.example.test");
  unrelatedBad.grantId = "unrelated";
  assert.throws(() => compileGuardEgressPolicy([grant([])], [valid, unrelatedBad], excluded), /guard egress refused safely/);
  assert.throws(() => compileGuardEgressPolicy([grant([])], [valid, { ...valid, grantId: "second" }], excluded), /guard egress refused safely/);
  assert.throws(() => compileGuardEgressPolicy([grant([])], [valid], []), /guard egress refused safely/);
  assert.throws(() => compileGuardEgressPolicy([grant([])], [valid], ["8.8.8.0/24"]), /guard egress refused safely/);
  assert.throws(() => compileGuardEgressPolicy([grant(["9.9.9.0/24"])], [valid], excluded), /guard egress refused safely/);
});

test("passive data bounds reject accessors, proxies, oversized answers and unknown generated fields", () => {
  let invoked = 0;
  const accessor = grant(["8.8.8.0/24"]);
  Object.defineProperty(accessor, "host", { enumerable: true, get() { invoked++; return "api.example.test"; } });
  const proxy = new Proxy(grant(["8.8.8.0/24"]), { ownKeys() { invoked++; return []; } });
  for (const host of [accessor, proxy, { ...grant(["8.8.8.0/24"]), extra: true }]) {
    assert.throws(() => compileGuardEgressPolicy([grant([])], [host], excluded), /guard egress refused safely/);
  }
  assert.equal(invoked, 0);
  const route = compileGuardEgressPolicy([grant([])], [grant(["8.8.8.0/24"])], excluded).select("api.example.test", 443);
  assert.throws(() => route.pin(Array(33).fill("8.8.8.8")), /guard egress refused safely/);
  assert.throws(() => route.pin(["8".repeat(65)]), /guard egress refused safely/);
  const excessive = Array.from({ length: 67 }, (_, i) => ({ ...grant(["8.8.8.0/24"], false, `api${i}.example.test`), grantId: `id${i}` }));
  assert.throws(() => compileGuardEgressPolicy(excessive, excessive, excluded), /guard egress refused safely/);
});
