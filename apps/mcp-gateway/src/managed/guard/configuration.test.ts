import assert from "node:assert/strict";
import { test } from "node:test";
import { parseGuardConfiguration } from "./configuration.js";
import { fixture, expected, now } from "./configuration/fixture.js";

const parse = (value = fixture(), time = now) => parseGuardConfiguration(Buffer.from(JSON.stringify(value)), expected, time);
const rejects = (value: ReturnType<typeof fixture>) => assert.throws(() => parse(value),
  error => error instanceof Error && error.message === "guard configuration refused safely" && error.cause === undefined);

test("guard configuration binds separate identity and compiles derived topology/egress", () => {
  const config = parseGuardConfiguration(Buffer.from(JSON.stringify(fixture())), expected, now);
  assert.equal(config.installationId, expected.installationId);
  assert.equal(config.processInstanceId, expected.processInstanceId);
  assert.equal(config.notAfterUnixUs, now + 1000000n);
  assert.deepEqual(config.addresses, { internalSubnet: "10.88.0.16/29", ipamGateway: "10.88.0.17",
    gateway: "10.88.0.18", guardInternal: "10.88.0.19", guardOuter: "10.89.0.18",
    outerGateway: "10.89.0.1", edge: "10.89.0.2", ingressPort: 8080, egressPort: 18080 });
  assert.equal(config.policy.select("api.example", 443).pin(["8.8.8.8"]).address, "8.8.8.8");
});

for (const field of ["not_before_unix_us", "not_after_unix_us"] as const)
  test(`timestamp ${field} must reject a trailing newline`, () => {
    const value = fixture(); value[field] += "\n";
    assert.throws(() => parseGuardConfiguration(Buffer.from(JSON.stringify(value)), expected, now), /guard configuration refused safely/);
  });
for (const field of ["internal_pool", "outer_subnet"] as const)
  test(`topology ${field} must reject a trailing newline`, () => {
    const value = fixture(); value.topology[field] += "\n";
    assert.throws(() => parseGuardConfiguration(Buffer.from(JSON.stringify(value)), expected, now), /guard configuration refused safely/);
  });
test("route CIDRs must reject a trailing newline", () => {
  const value = fixture(); value.routes[0].declared_cidrs[0] += "\n";
  assert.throws(() => parseGuardConfiguration(Buffer.from(JSON.stringify(value)), expected, now), /guard configuration refused safely/);
});

for (const [name, change] of Object.entries({
  schema: { schema_version: 2 }, profile: { profile: "network-none" }, secret: { token: "PRIVATE-CANARY" },
  installation: { installation_id: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e03" },
  instance: { process_instance_id: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e04" },
  "uuidv4": { process_instance_id: "018f3d4a-8b9c-4d0e-8f12-3a4b5c6d7e02" },
  "binding": { network_binding_sha256: "c".repeat(64) }, "topology hash": { network_topology_sha256: "c".repeat(64) },
  "uppercase hash": { network_binding_sha256: "A".repeat(64) }, "missing time": { not_before_unix_us: undefined },
  "numeric time": { not_before_unix_us: Number(now - 1n) }, "zero time": { not_before_unix_us: "0" },
  "negative time": { not_before_unix_us: "-1" }, "padded time": { not_before_unix_us: "01" },
  "exponent time": { not_before_unix_us: "1e3" }, "fraction time": { not_before_unix_us: "1.1" },
  "out of SQL range": { not_after_unix_us: "9223372036854775808" },
  "empty interval": { not_after_unix_us: (now - 1n).toString() }, "expired": { not_after_unix_us: now.toString() },
  "future": { not_before_unix_us: (now + 1n).toString() },
})) test(`guard document refuses ${name}`, () => { const v = fixture(); Object.assign(v, change); rejects(v); });

for (const [name, change] of Object.entries({
  "public inner": { internal_pool: "8.8.8.0/24" }, "IPv6": { internal_pool: "fd00::/64" },
  "inner too wide": { internal_pool: "10.88.0.0/21" }, "inner too narrow": { internal_pool: "10.88.0.0/30" },
  "noncanonical inner": { internal_pool: "10.88.0.1/22" }, "alias inner": { internal_pool: "012.88.0.0/22" },
  "capacity overflow": { capacity: 129 }, "zero capacity": { capacity: 0 }, "capacity fraction": { capacity: 1.1 },
  "string slot": { slot: "2" }, "negative slot": { slot: -1 }, "out of bounds slot": { slot: 128 },
  "insufficient pool": { internal_pool: "10.88.0.0/29" }, "overlap": { outer_subnet: "10.88.1.0/24" },
  "public outer": { outer_subnet: "8.8.8.0/24" }, "outer too wide": { outer_subnet: "10.89.0.0/23" },
  "outer too narrow": { outer_subnet: "10.89.0.0/25" }, "derived override": { gateway_address: "10.1.2.3" },
  "outer reserved base": { outer_gateway: "10.89.0.0" }, "outer allocation slot": { outer_gateway: "10.89.0.16" },
  "foreign edge": { edge_address: "10.90.0.2" }, "edge aliases gateway": { edge_address: "10.89.0.1" },
})) test(`guard topology refuses ${name}`, () => { const v = fixture(); Object.assign(v.topology, change); rejects(v); });

for (const [name, change] of Object.entries({
  "empty host": { host: "" }, "uppercase host": { host: "API.example" }, "numeric alias": { host: "0x7f.1" },
  "overflow alias": { host: "99999999999999" }, "literal": { host: "8.8.8.8" },
  "metadata": { host: "metadata.google.internal", private_destination: true, declared_cidrs: ["10.9.0.0/16"], protected_cidrs: ["10.9.0.0/16"] },
  "zero port": { port: 0 }, "overflow port": { port: 65536 }, "fraction port": { port: 443.1 },
  "string boolean": { private_destination: "false" }, "secret field": { password: "PRIVATE-CANARY" },
  "empty protected": { protected_cidrs: [] }, "no intersection": { protected_cidrs: ["9.9.0.0/16"] },
  "duplicate protected": { protected_cidrs: ["8.8.0.0/16", "8.8.0.0/16"] },
  "IPv6 CIDR": { protected_cidrs: ["2001:4860::/32"] }, "reserved CIDR": { protected_cidrs: ["127.0.0.0/8"] },
  "empty CIDR": { protected_cidrs: [""] }, "zero prefix": { protected_cidrs: ["0.0.0.0/0"] },
  "wrong private flag": { private_destination: true },
  "mixed ranges": { protected_cidrs: ["8.8.0.0/16", "10.9.0.0/16"] },
  "private missing declaration": { private_destination: true, declared_cidrs: [], protected_cidrs: ["10.9.0.0/16"] },
})) test(`guard route refuses ${name}`, () => { const v = fixture(); Object.assign(v.routes[0], change); rejects(v); });

test("time comparisons preserve individual microseconds above 2^53", () => {
  const v = fixture(); v.not_before_unix_us = now.toString(); v.not_after_unix_us = (now + 7n).toString();
  assert.throws(() => parse(v, now - 1n));
  for (const offset of [0n, 1n, 6n]) assert.equal(parse(v, now + offset).notAfterUnixUs - now, 7n);
  assert.throws(() => parse(v, now + 7n)); assert.throws(() => parse(v, now + 999n));
  for (const invalid of [0n, -1n, 9223372036854775808n, 9007199254740992, undefined])
    assert.throws(() => parseGuardConfiguration(Buffer.from(JSON.stringify(v)), expected, invalid as bigint));
});

test("compact original JSON rejects duplicate keys, exponent/fraction rounding, BOM and malformed UTF8", () => {
  const raw = JSON.stringify(fixture());
  for (const text of [raw + "\n", raw.replace('"schema_version":1', '"schema_version":1,"schema_version":1'),
    raw.replace('"schema_version":1', '"schema_version":1.0000000000000001'), raw.replace('"slot":2', '"slot":2e0'),
    raw.replace('"capacity":128', '"capacity":128.0'), '\ufeff' + raw, raw.replace('"routes":', '"routes":null,"routes":')])
    assert.throws(() => parseGuardConfiguration(Buffer.from(text), expected, now));
  for (const bytes of [Buffer.alloc(0), Buffer.alloc(262145), Buffer.from([0xff]), new Uint8Array(new SharedArrayBuffer(4)),
    new Proxy(Buffer.from(raw), {})]) assert.throws(() => parseGuardConfiguration(bytes, expected, now));
});

test("caller-provided byte accessors and expectation hooks are never executed", () => {
  let called = 0;
  const bytes = Buffer.from(JSON.stringify(fixture()));
  Object.defineProperties(bytes, { byteLength: { get() { called++; return 0; } },
    buffer: { get() { called++; return new SharedArrayBuffer(4); } }, [Symbol.iterator]: { get() { called++; throw new Error(); } } });
  parseGuardConfiguration(bytes, expected, now);
  for (const e of [new Proxy(expected, { ownKeys() { called++; return []; } }), Object.create(expected),
    Object.defineProperty({ ...expected }, "installationId", { get() { called++; return expected.installationId; } }),
    { ...expected, extra: "PRIVATE-CANARY" }]) assert.throws(() => parseGuardConfiguration(bytes, e, now));
  assert.equal(called, 0);
});

test("shared selectors refuse rather than widen purpose permissions; route bound is 66", () => {
  const v = fixture(); v.routes.push({ ...v.routes[0] }); rejects(v);
  v.routes = Array.from({ length: 66 }, (_, index) => ({ ...v.routes[0], host: `route-${index}.example` }));
  const config = parse(v); assert(config.policy.select("route-65.example", 443));
  v.routes.push({ ...v.routes[0], host: "extra.example" }); rejects(v);
  v.routes = []; rejects(v);
});

test("CIDR set caps are independent and exact", () => {
  const v = fixture(); v.routes[0].declared_cidrs = Array.from({ length: 64 }, (_, i) => `8.8.8.${i}/32`);
  v.routes[0].protected_cidrs = Array.from({ length: 32 }, (_, i) => `8.8.8.${i * 2}/31`);
  assert(parse(v).policy.select("api.example", 443).pin(["8.8.8.63"]));
  v.routes[0].declared_cidrs.push("8.8.8.64/32"); rejects(v); v.routes[0].declared_cidrs.pop();
  v.routes[0].protected_cidrs.push("8.8.8.64/31"); rejects(v);
});

test("compiled policy owns copies, intersects either narrower set and checks every DNS answer", () => {
  const v = fixture(), config = parse(v), route = config.policy.select("api.example", 443);
  v.routes[0].declared_cidrs[0] = "9.9.9.0/24"; v.routes[0].host = "changed.example";
  assert.equal(route.pin(["8.8.8.8"]).address, "8.8.8.8");
  for (const answers of [["8.8.8.8", "8.8.9.1"], ["10.88.0.2"], [], Array(33).fill("8.8.8.8")])
    assert.throws(() => route.pin(answers));
  assert.throws(() => config.policy.select("changed.example", 443));
  const reverse = fixture(); reverse.routes[0].declared_cidrs = ["8.8.0.0/16"];
  reverse.routes[0].protected_cidrs = ["8.8.8.0/24"];
  assert(parse(reverse).policy.select("api.example", 443).pin(["8.8.8.9"]));
  reverse.routes[0].declared_cidrs = [];
  assert.throws(() => parse(reverse).policy.select("api.example", 443).pin(["8.8.9.9"]));
  assert(Object.isFrozen(config)); assert(Object.isFrozen(config.addresses)); assert(Object.isFrozen(config.policy));
});

test("private host policy cannot reach ANY proxy pool slot or the outer pool", () => {
  const v = fixture(); Object.assign(v.routes[0], { private_destination: true,
    declared_cidrs: ["10.0.0.0/8"], protected_cidrs: ["10.0.0.0/8"] });
  const route = parse(v).policy.select("api.example", 443);
  assert.equal(route.pin(["10.90.0.1"]).address, "10.90.0.1");
  for (const target of ["10.88.0.0", "10.88.0.2", "10.88.3.255", "10.89.0.1", "10.89.0.254"])
    assert.throws(() => route.pin(["10.90.0.1", target]));
  v.routes[0].protected_cidrs = ["10.88.0.0/22"]; rejects(v);
});

test("derived address geometry matches independent integer oracle across private families and every slot", () => {
  let checked = 0;
  for (const [base, outer] of [["10.88.0.0", "10.89.0.0"], ["172.19.0.0", "172.20.0.0"], ["192.168.64.0", "192.168.80.0"]])
    for (let prefix = 22; prefix <= 29; prefix++) {
      const capacity = Math.min(128, 2 ** (29 - prefix));
      for (let slot = 0; slot < capacity; slot++) {
        const v = fixture(); Object.assign(v.topology, { internal_pool: `${base}/${prefix}`, outer_subnet: `${outer}/24`,
          capacity, slot, outer_gateway: outer.slice(0, -1) + "1", edge_address: outer.slice(0, -1) + "2" });
        const a = parse(v).addresses, octets = base.split(".").map(Number);
        const offset = slot * 8; octets[2] += Math.floor(offset / 256); octets[3] += offset % 256;
        assert.equal(a.internalSubnet, octets.join(".") + "/29");
        octets[3] += 2; assert.equal(a.gateway, octets.join("."));
        octets[3]++; assert.equal(a.guardInternal, octets.join("."));
        assert.equal(a.guardOuter, outer.slice(0, -1) + String(16 + slot)); checked++;
      }
    }
  assert.equal(checked, 765);
});
