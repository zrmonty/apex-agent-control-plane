import assert from "node:assert/strict";
import test from "node:test";

import { RuntimeConfigurationSchema, decodeStrict, type RuntimeConfiguration } from "@apex/contracts";
import { toJson, type JsonValue } from "@bufbuild/protobuf";

import { parseRuntimeConfiguration, runtimeManifestHash } from "./runtime-config.js";
import {
  artifactPath, artifactText, artifactSha256, rustManifestHash, source, message,
  field, setField, leaves, resign, rejectsSafely, assertFrozen, object,
} from "./runtime-config/test-support.js";
import { invalidMetadata } from "./runtime-config/test-security-cases.js";

test("consumes the actual Rust export without dropping any generated field", context => {
  const config = parseRuntimeConfiguration(artifactText);
  assert.deepEqual(toJson(RuntimeConfigurationSchema, structuredClone(config) as RuntimeConfiguration), source());
  assert.equal(config.runtimeManifestHash, rustManifestHash);
  assert.equal(config.configHash, "a".repeat(64));
  assert.notEqual(config.configHash, config.runtimeManifestHash);
  assert.equal(config.auth?.audience, config.resourceUrl);
  assert.notEqual(config.resourceUrl, config.spec?.upstreams[0].endpointOrCommandRef);
  assert.equal(config.memoryBytes, 268435456n);
  assert.equal(config.telemetry?.maxExportQueueBytes, 8388608n);
  context.diagnostic(`Rust artifact: ${artifactPath}; source SHA-256: ${artifactSha256}`);
});

test("manifest hash matches Rust and excludes only runtimeManifestHash", () => {
  const config = message();
  assert.equal(runtimeManifestHash(config), rustManifestHash);
  config.runtimeManifestHash = "b".repeat(64);
  assert.equal(runtimeManifestHash(config), rustManifestHash);
  config.configHash = "c".repeat(64);
  assert.notEqual(runtimeManifestHash(config), rustManifestHash);
});

test("returns a separate deeply frozen generated message preserving bigint", () => {
  const input = source();
  const config = parseRuntimeConfiguration(input);
  assertFrozen(config);
  assert.equal(config.generation, 1n);
  assert.ok(!Object.isFrozen(input));
  setField(input, "/auth/issuer", "https://changed.example.test");
  assert.equal(config.auth?.issuer, "https://issuer.example.test");
  assert.equal(Reflect.set(config, "generation", 2n), false);
  assert.equal(Reflect.set(config.auth!.requiredScopes, "0", "mcp:other"), false);
  assert.equal(Reflect.set(config.spec!.runtimeProfile!, "rootless", false), false);
  assert.equal(runtimeManifestHash(config), rustManifestHash);
});

test("preserves generation above JavaScript's safe integer range exactly", () => {
  const input = source();
  input.generation = "9007199254740993";
  const config = parseRuntimeConfiguration(resign(input));
  assert.equal(config.generation, 9007199254740993n);
  assert.equal(config.configHash, "a".repeat(64));
  assert.notEqual(config.runtimeManifestHash, rustManifestHash);
  assert.equal(runtimeManifestHash(config), input.runtimeManifestHash);
  assert.equal(object(toJson(RuntimeConfigurationSchema, structuredClone(config) as RuntimeConfiguration)).generation, "9007199254740993");
});

test("every exported leaf and each integrity hash is protected against tampering", () => {
  parseRuntimeConfiguration(artifactText);
  const original = source();
  const settings = leaves(original);
  assert.ok(settings.length >= 60, "use the complete Rust artifact, not a reduced lookalike");
  for (const [pointer, value] of settings) {
    const changed = source();
    const replacement = typeof value === "boolean" ? !value
      : typeof value === "number" ? value + 1 : `${String(value)}SENSITIVE`;
    setField(changed, pointer, replacement);
    rejectsSafely(() => parseRuntimeConfiguration(changed), pointer);
  }
});

test("schema body changes and schema hashes cannot hide behind profile references", () => {
  parseRuntimeConfiguration(artifactText);
  for (const [pointer, value] of [
    ["/toolSchemas/0/inputSchemaJson", '{"type":"object","additionalProperties":true}'],
    ["/toolSchemas/0/outputSchemaJson", '{"type":"object","properties":{"SENSITIVE":{"type":"string"}}}'],
    ["/toolSchemas/0/schemaHash", "c".repeat(64)],
    ["/toolSchemas/0/outputProfileId", "different-profile"],
    ["/spec/upstreams/0/toolCatalogHash", "d".repeat(64)],
  ] as const) {
    const input = source();
    setField(input, pointer, value);
    rejectsSafely(() => parseRuntimeConfiguration(input), pointer);
  }
});

test("rejects malformed security metadata even after an independently recomputed manifest", () => {
  parseRuntimeConfiguration(artifactText);
  for (const [pointer, replacement] of invalidMetadata) {
    const input = source();
    setField(input, pointer, replacement);
    resign(input);
    rejectsSafely(() => parseRuntimeConfiguration(input), pointer);
  }
});

test("checks declared secret and network unions against independently hashed additions", () => {
  parseRuntimeConfiguration(artifactText);
  for (const pointer of ["/secretRefs", "/networkGrants", "/toolSchemas", "/spec/upstreams", "/spec/exposedTools"] as const) {
    const input = source();
    const existing = field(input, pointer);
    assert.ok(Array.isArray(existing));
    setField(input, pointer, [...existing, structuredClone(existing[0])]);
    rejectsSafely(() => parseRuntimeConfiguration(resign(input)), pointer);
  }
  const extraSecret = source();
  setField(extraSecret, "/secretRefs", ["secret://vault/upstreams/portfolio-reader", "secret://vault/unrelated"]);
  rejectsSafely(() => parseRuntimeConfiguration(resign(extraSecret)), "extra reference");
  const wrongGrant = source();
  setField(wrongGrant, "/networkGrants/0/host", "other.apex.test");
  rejectsSafely(() => parseRuntimeConfiguration(resign(wrongGrant)), "undeclared host");
});

test("generated decoding rejects unknown fields, enum drift and schema versions", () => {
  parseRuntimeConfiguration(artifactText);
  for (const pointer of ["/surprise", "/spec/ingress/surprise", "/toolSchemas/0/surprise", "/auth/surprise", "/telemetry/surprise"]) {
    const input = source();
    setField(input, pointer, "SENSITIVE");
    rejectsSafely(() => parseRuntimeConfiguration(input), pointer);
  }
  for (const [pointer, replacement] of [
    ["/schemaVersion", 2], ["/approvalMode", 999], ["/spec/ingress/transport", 999],
    ["/spec/ingress/exposure", 999], ["/spec/exposedTools/0/classification", 999],
    ["/spec/runtimeProfile/egressDestinations/0/privateDestinationAllowance", 999],
  ] as const) {
    const input = source();
    setField(input, pointer, replacement);
    rejectsSafely(() => parseRuntimeConfiguration(input), pointer);
  }
});

test("original JSON text rejects duplicates, alias collisions and unsafe numeric input", () => {
  parseRuntimeConfiguration(artifactText);
  for (const prefix of [
    '"generation":"2",', '"schema_version":1,', '"runtimeManifestHash":null,',
    '"auth":null,', '"work\\u0073paceId":"other",',
  ]) {
    rejectsSafely(() => parseRuntimeConfiguration("{" + prefix + artifactText.slice(artifactText.indexOf("{") + 1)));
  }
  for (const replacement of [1, 9007199254740992, "01", "+1", "1e3", "-1", "18446744073709551616", null]) {
    const input = source();
    input.generation = replacement;
    rejectsSafely(() => parseRuntimeConfiguration(input));
  }
});

test("rejects excessive input sizes, field counts and depth with static errors", () => {
  parseRuntimeConfiguration(artifactText);
  const oversized = source();
  setField(oversized, "/toolSchemas/0/inputSchemaJson", "SENSITIVE".repeat(40_000));
  rejectsSafely(() => parseRuntimeConfiguration(oversized));
  const wide = source();
  setField(wide, "/auth/requiredScopes", Array.from({ length: 8193 }, (_, i) => `mcp:${i}`));
  rejectsSafely(() => parseRuntimeConfiguration(wide));
  rejectsSafely(() => parseRuntimeConfiguration("[".repeat(65) + "0" + "]".repeat(65)));
  rejectsSafely(() => parseRuntimeConfiguration('{"SENSITIVE":'));
});

test("hashing unknown top-level and nested generated enums fails without leaking input", () => {
  assert.equal(runtimeManifestHash(message()), rustManifestHash);
  const top = message();
  top.approvalMode = 999 as typeof top.approvalMode;
  rejectsSafely(() => runtimeManifestHash(top));
  const nested = message();
  const ingress = nested.spec!.ingress!;
  ingress.transport = 999 as typeof ingress.transport;
  rejectsSafely(() => runtimeManifestHash(nested));
});

test("hashing never silently drops extra properties on a generated message", () => {
  assert.equal(runtimeManifestHash(message()), rustManifestHash);
  const config = message();
  Object.assign(config.auth!, { hiddenCredential: "SENSITIVE" });
  rejectsSafely(() => runtimeManifestHash(config));
});

test("valid nested arrays and explicit defaults preserve generated semantics", () => {
  const input = source();
  setField(input, "/auth/requiredScopes", ["mcp:tools", "portfolio:read"]);
  setField(input, "/spec/ingress/allowedOrigins", ["https://console.apex.test", "https://ops.apex.test"]);
  setField(input, "/networkGrants/0/approvedCidrs", ["8.8.8.8/32", "8.8.4.4/32"]);
  setField(input, "/networkGrants/0/privateDestination", false);
  const config = parseRuntimeConfiguration(resign(input));
  assert.deepEqual(config.auth?.requiredScopes, ["mcp:tools", "portfolio:read"]);
  assert.deepEqual(config.networkGrants[0].approvedCidrs, ["8.8.8.8/32", "8.8.4.4/32"]);
  assert.deepEqual(
    toJson(RuntimeConfigurationSchema, structuredClone(config) as RuntimeConfiguration),
    toJson(RuntimeConfigurationSchema, decodeStrict(RuntimeConfigurationSchema, input)),
  );
  assertFrozen(config);
});

test("rejects unsafe objects before invoking accessors or JSON coercion", () => {
  parseRuntimeConfiguration(artifactText);
  let invoked = 0;
  const accessor = source();
  Object.defineProperty(accessor, "auth", { enumerable: true, get() { invoked++; throw new Error("SENSITIVE"); } });
  rejectsSafely(() => parseRuntimeConfiguration(accessor));
  const coercion = source();
  Object.defineProperty(coercion, "toJSON", { value() { invoked++; return source(); } });
  rejectsSafely(() => parseRuntimeConfiguration(coercion));
  assert.equal(invoked, 0, "no input accessors or coercion hooks may execute");
  const inherited = source();
  Object.setPrototypeOf(inherited, { inheritedSecurity: "SENSITIVE" });
  rejectsSafely(() => parseRuntimeConfiguration(inherited));
  const symbol = source();
  Object.defineProperty(symbol, Symbol("hidden"), { value: "SENSITIVE" });
  rejectsSafely(() => parseRuntimeConfiguration(symbol));
  for (const input of [new String(artifactText), new Date(), new Map(), new Set(), new Uint8Array([1]), new Proxy(source(), {})]) {
    rejectsSafely(() => parseRuntimeConfiguration(input));
  }
});

test("approval string and generated enum must agree without defaulting", () => {
  for (const [mode, enumeration] of [["none", "PROXY_APPROVAL_MODE_NONE"], ["operator", "PROXY_APPROVAL_MODE_OPERATOR"], ["dual-operator", "PROXY_APPROVAL_MODE_DUAL_OPERATOR"]]) {
    const input = source();
    setField(input, "/spec/governanceBinding/approvalMode", mode);
    input.approvalMode = enumeration;
    const config = parseRuntimeConfiguration(resign(input));
    assert.equal(config.spec?.governanceBinding?.approvalMode, mode);
    setField(input, "/spec/governanceBinding/approvalMode", "unknown");
    rejectsSafely(() => parseRuntimeConfiguration(input));
  }
});

test("rehashed network metadata retains literal/CIDR confinement for IPv4 and IPv6", () => {
  function network(host: string, cidrs: string[], privateDestination: boolean) {
    const input = source();
    setField(input, "/spec/upstreams/0/endpointOrCommandRef", `https://${host}/mcp`);
    setField(input, "/spec/runtimeProfile/egressDestinations/0/host", host);
    setField(input, "/spec/runtimeProfile/egressDestinations/0/privateDestinationAllowance",
      privateDestination ? "MCP_PROXY_PRIVATE_DESTINATION_ALLOWANCE_ALLOWED" : "MCP_PROXY_PRIVATE_DESTINATION_ALLOWANCE_DENIED");
    setField(input, "/networkGrants/0/host", host);
    setField(input, "/networkGrants/0/approvedCidrs", cidrs);
    setField(input, "/networkGrants/0/privateDestination", privateDestination);
    return resign(input);
  }
  for (const [host, cidrs, privateDestination] of [
    ["8.8.8.8", ["8.8.8.0/24"], false], ["10.1.2.3", ["10.0.0.0/8"], true],
    ["[2606:4700:4700::1111]", ["2606:4700::/32"], false], ["[fd12::1]", ["fd12::/16"], true],
  ] as const) {
    const input = network(host, [...cidrs], privateDestination);
    const config = parseRuntimeConfiguration(input);
    assert.equal(config.networkGrants[0].host, host);
    assert.equal(config.networkGrants[0].privateDestination, privateDestination);
    assert.equal(runtimeManifestHash(config), input.runtimeManifestHash);
  }
  for (const [host, cidrs, privateDestination] of [
    ["8.8.8.8", ["8.8.4.0/24"], false], ["10.1.2.3", [], false], ["10.1.2.3", [], true],
    ["10.1.2.3", ["8.8.8.0/24"], true], ["8.8.8.8", ["8.8.8.1/24"], false],
    ["8.8.8.8", ["8.8.8.8/32", "8.8.8.8/32"], false],
    ["8.8.8.8", ["8.8.8.8/033"], false], ["8.8.8.8", ["8.0.0.0/6"], false],
    ["127.1", [], false], ["2130706433", [], false], ["localhost", [], false],
    ["gateway.docker.internal", ["10.0.0.0/8"], true], ["private.local", [], false],
    ["169.254.169.254", ["169.254.169.254/32"], true],
    ["[::ffff:127.0.0.1]", [], false], ["[2001:db8::1]", [], false],
    ["[2002::1]", [], false], ["[3fff::1]", [], false], ["[::1]", ["::1/128"], true],
    ["[2606:4700:4700::1111]", ["2000::/3"], false],
  ] as const) {
    rejectsSafely(() => parseRuntimeConfiguration(network(host, [...cidrs], privateDestination)), host);
  }
});

test("rehashed auth bindings and additional secret references preserve the exact union", () => {
  const input = source();
  setField(input, "/spec/authBindings", [{
    bindingId: "service", inboundSubject: "gateway-worker", outboundCredentialRef: "secret://vault/auth/worker",
    scopes: ["mcp:tools"],
  }]);
  setField(input, "/spec/upstreams/0/secretRefs", ["secret://vault/upstreams/extra"]);
  setField(input, "/secretRefs", [
    "secret://vault/upstreams/portfolio-reader", "secret://vault/upstreams/extra", "secret://vault/auth/worker",
  ]);
  const config = parseRuntimeConfiguration(resign(input));
  assert.deepEqual(toJson(RuntimeConfigurationSchema, structuredClone(config) as RuntimeConfiguration), input);
  const mutations: [string, JsonValue][] = [
    ["/spec/authBindings/0/outboundCredentialRef", "SENSITIVE"],
    ["/spec/authBindings/0/bindingId", ""], ["/spec/authBindings/0/inboundSubject", ""],
    ["/spec/authBindings/0/scopes", ["mcp:tools", "mcp:tools"]],
    ["/spec/upstreams/0/secretRefs", ["secret://vault/not-in-union"]],
  ];
  for (const [pointer, replacement] of mutations) {
    const changed = structuredClone(input);
    setField(changed, pointer, replacement);
    rejectsSafely(() => parseRuntimeConfiguration(resign(changed)), pointer);
  }
});

test("rehashed schema metadata rejects nested references, duplicate escapes and parser bounds", () => {
  for (const schema of [
    '{"type":"object","properties":{"x":{"$dynamicRef":"SENSITIVE"}}}',
    '{"type":"object","$recursiveRef":"#"}', '{"type":"object","$id":"SENSITIVE"}',
    '{"type":"object","t\\u0079pe":"object"}', '{"type":"object","maximum":1e400}',
    '{"type":"object","title":"\\ud800"}',
    '{"type":"object","x":' + '['.repeat(33) + '0' + ']'.repeat(33) + '}',
    JSON.stringify({ type: "object", enum: Array(2048).fill("x") }),
  ]) {
    const input = source();
    setField(input, "/toolSchemas/0/inputSchemaJson", schema);
    rejectsSafely(() => parseRuntimeConfiguration(resign(input)));
  }
});

test("hash input rejects nested accessors, proxies, hidden properties and malformed scalar types", () => {
  let invoked = 0;
  const accessor = message();
  Object.defineProperty(accessor.auth!, "issuer", { enumerable: true, get() { invoked++; throw new Error("SENSITIVE"); } });
  rejectsSafely(() => runtimeManifestHash(accessor));
  const proxy = message();
  proxy.auth = new Proxy(proxy.auth!, { ownKeys() { invoked++; throw new Error("SENSITIVE"); } });
  rejectsSafely(() => runtimeManifestHash(proxy));
  const hidden = message();
  Object.defineProperty(hidden.telemetry!, "hidden", { value: "SENSITIVE" });
  rejectsSafely(() => runtimeManifestHash(hidden));
  const incorrect = message();
  Object.assign(incorrect, { generation: "9007199254740993" });
  rejectsSafely(() => runtimeManifestHash(incorrect));
  const unknown = message();
  Object.assign(unknown.spec!.runtimeProfile!, { $unknown: [] });
  rejectsSafely(() => runtimeManifestHash(unknown));
  assert.equal(invoked, 0);
});
