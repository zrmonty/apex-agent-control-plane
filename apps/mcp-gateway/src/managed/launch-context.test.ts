import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { RuntimeLaunchContextSchema, encodeJson, type RuntimeLaunchContext } from "@apex/contracts";
import type { JsonValue } from "@bufbuild/protobuf";
import { launchContextHash, parseRuntimeLaunchContext } from "./launch-context.js";
import { config, fence, generated, referenceHash, rejectsSafely, resign, source } from "./launch-context/test-support.js";
import { artifactPath, artifactText, artifactSha256, assertFrozen, leaves, object, setField } from "./runtime-config/test-support.js";

test("actual Rust v1 export binds synthetic launch metadata with an exact >2^53 fence", () => {
  const input = source();
  const parsed = parseRuntimeLaunchContext(JSON.stringify(input), config);
  assert.deepEqual(encodeJson(RuntimeLaunchContextSchema, parsed as RuntimeLaunchContext), input);
  assert.equal(parsed.target?.fencingToken, 9007199254740993n);
  assert.equal(parsed.target?.generation, config.generation);
  assert.equal(config.schemaVersion, 1);
  assert.equal(config.runtimeManifestHash, "db5ddc4670e5f901240e1c2910d9f78dd8a65237c86f197d13938be967afe5da");
  assert.deepEqual(config.secretRefs, ["secret://vault/upstreams/portfolio-reader"]);
  assert.equal(artifactSha256, "970cfd7a059a4761fc8b4ad6f8f9d5dd4f4f4f4c4f2d16995cde807d20fdd554");
  assert.equal(readFileSync(artifactPath, "utf8"), artifactText);
});

test("launch hash matches independent generated-JSON canonicalization and ignores only itself", () => {
  const input = source();
  assert.equal(launchContextHash(generated(input)), referenceHash(input));
  input.launchContextHash = "f".repeat(64);
  assert.equal(launchContextHash(generated(input)), referenceHash(source()));
});
test("object key order and valid protobuf aliases do not change the digest", () => {
  const input = source();
  const reversed = Object.fromEntries(Object.entries(input).reverse());
  reversed.target = Object.fromEntries(Object.entries(object(input.target)).reverse());
  reversed.launch_context_hash = reversed.launchContextHash;
  delete reversed.launchContextHash;
  assert.equal(parseRuntimeLaunchContext(reversed, config).launchContextHash, source().launchContextHash);
  assert.equal(launchContextHash(generated(input)), launchContextHash(generated(Object.fromEntries(Object.entries(input).reverse()))));
});
test("array order stays significant while valid non-health CA sharing is representable", () => {
  const input = source();
  const materials = input.materials as JsonValue[];
  materials.push({ role: "RUNTIME_MATERIAL_ROLE_EVIDENCE_CA", reference: "secret://deployment/authority-ca", version: "v1" });
  resign(input);
  assert.equal(parseRuntimeLaunchContext(input, config).materials.length, 3);
  const prior = launchContextHash(generated(input));
  materials.reverse();
  assert.notEqual(launchContextHash(generated(input)), prior);
  rejectsSafely(() => parseRuntimeLaunchContext(input, config));
  resign(input);
  assert.equal(parseRuntimeLaunchContext(input, config).materials.length, 3);
});
for (const [pointer, value] of leaves(source()).filter(([pointer]) => pointer !== "/launchContextHash")) {
  test(`hash binds the generated launch field ${pointer}`, () => {
    const input = source();
    const replacement = pointer.endsWith("/role") ? "RUNTIME_MATERIAL_ROLE_EVIDENCE_KEY"
      : typeof value === "number" ? value + 1
      : pointer.endsWith("/generation") || pointer.endsWith("/fencingToken") ? "7"
      : `${value}-changed`;
    setField(input, pointer, replacement);
    assert.notEqual(launchContextHash(generated(input)), referenceHash(source()));
    assert.equal(launchContextHash(generated(input)), referenceHash(input));
  });
}

const invalidMetadata: readonly (readonly [string, JsonValue | undefined])[] = [
  ["/schemaVersion", 0], ["/schemaVersion", 2], ["/target", undefined],
  ["/target/workspaceId", "other"], ["/target/namespaceId", "other"],
  ["/target/proxyId", "0191b7f1-7f2c-7c13-9a61-2f29f2be1004"],
  ["/target/revisionId", "0191b7f1-7f2c-7c13-9a61-2f29f2be1004"],
  ["/target/generation", "2"], ["/target/generation", "0"], ["/target/fencingToken", "0"],
  ["/configHash", "b".repeat(64)], ["/configHash", "A".repeat(64)],
  ["/runtimeManifestHash", "b".repeat(64)], ["/runtimeManifestHash", "not-a-digest"],
  ["/imageRef", "registry.example.test/apex/other@sha256:" + "c".repeat(64)],
  ["/processInstanceId", "0191b7f1-7f2c-4c13-9a61-2f29f2be1003"],
  ["/processInstanceId", "0191B7F1-7F2C-7C13-9A61-2F29F2BE1003"], ["/processInstanceId", ""],
  ["/authorityProfileRef", ""], ["/authorityProfileRef", "https://LAUNCH_CANARY.invalid"],
  ["/authorityProfileRef", "../profile"], ["/authorityProfileRef", "x".repeat(129)],
  ["/authorityProfileVersion", ""], ["/authorityProfileVersion", "v 1"], ["/authorityProfileVersion", "x".repeat(129)],
  ["/health", undefined], ["/health/port", 0], ["/health/port", 8080],
  ["/health/credentialRef", ""], ["/health/credentialRef", "secret://deployment/other"],
  ["/materials", []], ["/materials/0/role", "RUNTIME_MATERIAL_ROLE_UNSPECIFIED"],
  ["/materials/0/role", "RUNTIME_MATERIAL_ROLE_EVIDENCE_CERT"],
  ["/materials/1/role", "RUNTIME_MATERIAL_ROLE_HEALTH_TOKEN"],
  ["/materials/0/reference", "secret://deployment/other"],
  ["/materials/1/reference", "secret://deployment/health"],
  ["/materials/1/reference", config.secretRefs[0]],
  ["/materials/1/version", ""], ["/materials/1/version", "v..1"],
  ["/materials/1/version", "x".repeat(129)],
];
for (const [pointer, value] of invalidMetadata) {
  test(`independently re-signed invalid metadata rejected: ${pointer} ${JSON.stringify(value)?.slice(0, 48)}`, () => {
    const input = source();
    setField(input, pointer, value);
    resign(input); // Reject semantics, not an accidentally stale digest.
    rejectsSafely(() => parseRuntimeLaunchContext(input, config));
  });
}
for (const ref of ["LAUNCH_CANARY", "/tmp/key", "C:/key", "https://remote.invalid", "secret://", "secret://a/../b", "secret://a//b", "secret://a/", "secret://a\\b", "secret://" + "x".repeat(504)]) {
  test(`reject invalid provider reference ${ref.slice(0, 36)}`, () => {
    const input = source();
    setField(input, "/health/credentialRef", ref);
    setField(input, "/materials/0/reference", ref);
    resign(input);
    rejectsSafely(() => parseRuntimeLaunchContext(input, config));
    setField(input, "/materials/1/reference", ref);
    resign(input);
    rejectsSafely(() => parseRuntimeLaunchContext(input, config));
  });
}
test("health cannot reuse a revision reference even when its role agrees", () => {
  const input = source();
  setField(input, "/health/credentialRef", config.secretRefs[0]);
  setField(input, "/materials/0/reference", config.secretRefs[0]);
  rejectsSafely(() => parseRuntimeLaunchContext(resign(input), config));
});
test("duplicate non-health role and 14-material inventory are rejected", () => {
  const input = source();
  (input.materials as JsonValue[]).push({ ...object((input.materials as JsonValue[])[1]) });
  rejectsSafely(() => parseRuntimeLaunchContext(resign(input), config));
  input.materials = Array(14).fill(object((input.materials as JsonValue[])[1]));
  rejectsSafely(() => parseRuntimeLaunchContext(resign(input), config));
});
test("one health role is sufficient metadata; other operational role completeness is not claimed", () => {
  const input = source();
  input.materials = [(input.materials as JsonValue[])[0]];
  input.authorityProfileRef = "unverified-but-shaped-profile";
  setField(input, "/target/fencingToken", "18446744073709551615");
  assert.equal(parseRuntimeLaunchContext(resign(input), config).materials.length, 1);
});
test("13 unique roles and identifier/reference maxima are representable metadata", () => {
  const input = source();
  input.materials = Array.from({ length: 13 }, (_, index) => ({
    role: index + 1, reference: index === 0 ? "secret://deployment/health" : `secret://deployment/role-${index}`,
    version: "v".repeat(128),
  }));
  input.authorityProfileRef = "p".repeat(128);
  input.authorityProfileVersion = "v".repeat(128);
  setField(input, "/materials/1/reference", "secret://" + "x".repeat(503));
  assert.equal(parseRuntimeLaunchContext(resign(input), config).materials.length, 13);
});
test("changed valid material, version, profile and process require a matching digest", () => {
  for (const [pointer, value] of [
    ["/materials/1/reference", "secret://deployment/new-ca"], ["/materials/1/version", "v2"],
    ["/authorityProfileVersion", "v2"], ["/processInstanceId", "0191b7f1-7f2c-7c13-9a61-2f29f2be1004"],
    ["/target/fencingToken", "7"],
  ] as const) {
    const input = source();
    setField(input, pointer, value);
    rejectsSafely(() => parseRuntimeLaunchContext(input, config));
    assert.doesNotThrow(() => parseRuntimeLaunchContext(resign(input), config));
  }
});
for (const digest of ["", "A".repeat(64), "a".repeat(63), "0".repeat(64)]) {
  test(`invalid or mismatched launch digest rejected (${digest.length} bytes)`, () => {
    const input = source();
    input.launchContextHash = digest;
    rejectsSafely(() => parseRuntimeLaunchContext(input, config));
  });
}
test("returned generated snapshot is independently decoded and deeply frozen", () => {
  const input = source();
  const result = parseRuntimeLaunchContext(input, config);
  assertFrozen(result);
  setField(input, "/target/fencingToken", "7");
  setField(input, "/health/credentialRef", "secret://deployment/changed");
  setField(input, "/materials/0/version", "changed");
  assert.equal(result.target?.fencingToken, BigInt(fence));
  assert.equal(result.health?.credentialRef, "secret://deployment/health");
  assert.equal(result.materials[0].version, "v1");
  assert.equal(Reflect.set(result.materials[0], "version", "changed"), false);
});

for (const ending of ["\n", "\r", "\r\n", "\u2028", "\u2029"]) {
  test(`canonical launch identifiers reject terminal line separator ${JSON.stringify(ending)}`, () => {
    for (const pointer of ["/processInstanceId", "/authorityProfileRef", "/authorityProfileVersion", "/materials/1/version"]) {
      const input = source();
      const prior = pointer.startsWith("/materials") ? "v1" : input[pointer.slice(1)];
      setField(input, pointer, `${prior}${ending}`);
      rejectsSafely(() => parseRuntimeLaunchContext(resign(input), config));
    }
  });
  test(`canonical provider refs reject terminal line separator ${JSON.stringify(ending)}`, () => {
    const input = source();
    const ref = `secret://deployment/health${ending}`;
    setField(input, "/health/credentialRef", ref);
    setField(input, "/materials/0/reference", ref);
    rejectsSafely(() => parseRuntimeLaunchContext(resign(input), config));
    const other = source();
    setField(other, "/materials/1/reference", `secret://deployment/ca${ending}`);
    rejectsSafely(() => parseRuntimeLaunchContext(resign(other), config));
  });
}
