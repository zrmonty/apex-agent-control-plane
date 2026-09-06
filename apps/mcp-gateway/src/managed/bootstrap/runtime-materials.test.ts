import { test } from "node:test";
import assert from "node:assert/strict";
import { createManagedRuntimeMaterials, runtimeTokenMaterial, disposeRuntimeMaterials, runtimeTlsMaterial,
  runtimeUpstreamMaterial, runtimeJwksMaterial, type RuntimeMaterials, type RuntimeTlsPurpose } from "./runtime-materials.js";
import { disposeStageOwner, copyStageRole, type StageOwner } from "./stage-owner.js";
import { materialFixture, now } from "./runtime-materials/fixture.js";
import { fixture as pki } from "./tls-role-fixture.js";
import { upstreamClient } from "./runtime-materials/client-fixture.js";
const refused = /^Error: managed runtime materials refused safely$/;
test("joined genuine stage becomes independently owned purpose-separated runtime material", async () => {
  const f = await materialFixture();
  try {
    const owner = createManagedRuntimeMaterials(f.stageOwner, now);
    assert.deepEqual(owner.binding, f.stageOwner.documents.binding);
    assert.ok(owner.notAfterUnixUs > now); assert.ok(Object.isFrozen(owner));
    assert.deepEqual(owner.upstreamReferences, f.selection.toolSecretReferences);
    disposeStageOwner(f.stageOwner); await f.bootstrap.closed;
    assert.equal(runtimeTokenMaterial(owner, "governance").toString(), "synthetic-dedicated-governance-token");
    disposeRuntimeMaterials(owner); disposeRuntimeMaterials(owner);
    assert.throws(() => runtimeTokenMaterial(owner, "governance"), /managed runtime materials refused safely/);
  } finally { disposeStageOwner(f.stageOwner); await f.bootstrap.closed; }
});

test("separate upstream mTLS identity is allowed without exporting issuer/key metadata", async () => {
  const f = await materialFixture(f => {
    for (const entry of f.tools.entries) f.stage.files[entry.filename] = Buffer.from(JSON.stringify({ schema_version: 1,
      authentication: "mtls_bearer", server_ca: pki.ca, client: upstreamClient, token: "distinct-upstream-bearer" }));
  });
  let owner: RuntimeMaterials | undefined;
  try {
    owner = createManagedRuntimeMaterials(f.stageOwner, now);
    const material = runtimeUpstreamMaterial(owner, owner.upstreamReferences[0]);
    assert.equal(material.clientKey?.toString(), upstreamClient.key);
    assert.equal(material.token?.toString(), "distinct-upstream-bearer");
    assert.equal(new Set(Object.values(owner.tls).map(value => value.publicKeySha256)).size, 3);
    assert.ok(Object.isFrozen(owner.tls)); for (const value of Object.values(owner.tls)) assert.ok(Object.isFrozen(value));
    const serial = JSON.stringify(owner, (_, value) => typeof value === "bigint" ? String(value) : value);
    assert.equal(/PRIVATE KEY|distinct-upstream-bearer|BEGIN CERTIFICATE/.test(serial), false);
    for (const bytes of Object.values(material)) bytes.fill(0);
  } finally { if (owner) disposeRuntimeMaterials(owner); disposeStageOwner(f.stageOwner); await f.bootstrap.closed; }
});

for (const failure of ["zero-proof", "short-proof", "health-alias-proof", "malformed-health", "short-bearer", "bearer-newline",
  "same-authority-token", "authority-health-token", "authority-proof-token", "same-role-key", "reissued-role-key",
  "wrong-key", "wrong-purpose", "wrong-server-name", "invalid-ca", "bad-upstream", "upstream-governance-token",
  "upstream-evidence-token", "upstream-health-token", "upstream-proof-token", "upstream-critical-key"]) {
  test(`material composition refuses ${failure} and leaves source stage caller-owned`, async () => {
    const f = await materialFixture(f => {
      const files = f.stage.files;
      if (failure === "zero-proof") files["instance-proof"] = Buffer.alloc(32);
      if (failure === "short-proof") files["instance-proof"] = Buffer.alloc(31, 7);
      if (failure === "health-alias-proof") files["health-token"] = Buffer.from(files["instance-proof"].toString("base64url"));
      if (failure === "malformed-health") files["health-token"] = Buffer.from("!".repeat(43));
      if (failure === "short-bearer") files["governance-token"] = Buffer.from("short");
      if (failure === "bearer-newline") files["governance-token"] = Buffer.from("valid-synthetic-token\n");
      if (failure === "same-authority-token") files["evidence-token"] = Buffer.from(files["governance-token"]);
      if (failure === "authority-health-token") files["governance-token"] = Buffer.from(files["health-token"]);
      if (failure === "authority-proof-token") {
        files["instance-proof"] = Buffer.alloc(32, 65); files["governance-token"] = Buffer.from(files["instance-proof"]);
      }
      if (failure === "same-role-key" || failure === "reissued-role-key") {
        files["evidence-key"] = Buffer.from(pki.governance.key);
        files["evidence-cert"] = Buffer.from(failure === "same-role-key" ? pki.governance.cert : pki.reissued.cert);
      }
      if (failure === "wrong-key") files["governance-key"] = Buffer.from(pki.evidence.key);
      if (failure === "wrong-purpose") {
        files["workload-key"] = Buffer.from(pki.governance.key); files["workload-cert"] = Buffer.from(pki.governance.cert);
      }
      if (failure === "wrong-server-name") {
        f.value.profile.managed.ingress.tls_server_name = "wrong.test"; files["authority-profile.json"] = f.bytes();
      }
      if (failure === "invalid-ca") files["governance-ca"] = Buffer.from("invalid-pem");
      if (failure === "bad-upstream") files[f.tools.entries[0].filename] = Buffer.from("legacy-raw-bearer-token");
      if (failure.startsWith("upstream-")) {
        if (failure === "upstream-proof-token") files["instance-proof"] = Buffer.alloc(32, 65);
        const role = failure.slice("upstream-".length).replace("proof-token", "instance-proof");
        const credential = failure === "upstream-critical-key" ?
          { schema_version: 1, authentication: "mtls", server_ca: pki.ca, client: { ca: pki.ca, ...pki.governance } } :
          { schema_version: 1, authentication: "bearer", server_ca: pki.ca, token: files[role].toString() };
        files[f.tools.entries[0].filename] = Buffer.from(JSON.stringify(credential));
      }
    });
    try {
      const before = copyStageRole(f.stageOwner, "instance-proof");
      assert.throws(() => createManagedRuntimeMaterials(f.stageOwner, now), refused);
      assert.equal(f.counts.disposals, 0);
      assert.deepEqual(copyStageRole(f.stageOwner, "instance-proof"), before); before.fill(0);
    } finally { disposeStageOwner(f.stageOwner); await f.bootstrap.closed; }
  });
}

test("all material helpers return isolated copies with fixed selectors and revoke after disposal", async () => {
  const f = await materialFixture(), owner = createManagedRuntimeMaterials(f.stageOwner, now);
  try {
    for (const purpose of ["governance", "evidence", "health", "instance-proof"]) {
      const a = runtimeTokenMaterial(owner, purpose), b = runtimeTokenMaterial(owner, purpose);
      const original = Buffer.from(b); a.fill(0); assert.deepEqual(runtimeTokenMaterial(owner, purpose), original); b.fill(0); original.fill(0);
    }
    for (const purpose of ["governance", "evidence", "ingress"] as const) {
      const a = runtimeTlsMaterial(owner, purpose), b = runtimeTlsMaterial(owner, purpose);
      a.key.fill(0); assert.ok(b.key.includes("PRIVATE KEY"));
      for (const buffer of [...Object.values(a), ...Object.values(b)]) buffer.fill(0);
    }
    const jwks = runtimeJwksMaterial(owner); jwks.fill(0); assert.equal(runtimeJwksMaterial(owner).toString(), '{"keys":[]}');
    for (const value of ["unknown", "__proto__", "constructor", "governance-key", "/apex/runtime/governance-key", new String("governance")]) {
      assert.throws(() => runtimeTokenMaterial(owner, value as string), refused);
      assert.throws(() => runtimeTlsMaterial(owner, value as RuntimeTlsPurpose), refused);
      assert.throws(() => runtimeUpstreamMaterial(owner, value as string), refused);
    }
    const selected = runtimeUpstreamMaterial(owner, owner.upstreamReferences[0]); selected.token!.fill(0);
    assert.equal(runtimeUpstreamMaterial(owner, owner.upstreamReferences[0]).token?.toString(), "synthetic-dedicated-upstream-token");
    disposeRuntimeMaterials(owner);
    for (const call of [() => runtimeTokenMaterial(owner, "health"), () => runtimeJwksMaterial(owner),
      () => runtimeTlsMaterial(owner, "ingress"), () => runtimeUpstreamMaterial(owner, owner.upstreamReferences[0])]) assert.throws(call, refused);
    assert.ok(copyStageRole(f.stageOwner, "governance-token").length > 0); // Runtime disposal does not dispose caller's stage.
  } finally { disposeRuntimeMaterials(owner); disposeStageOwner(f.stageOwner); await f.bootstrap.closed; }
});

test("stage and runtime handle imitation invokes no attacker metadata hooks", async () => {
  let hooks = 0;
  const fakeStage = { get documents() { hooks++; throw new Error("canary"); } };
  for (const fake of [fakeStage, new Proxy(fakeStage, { get() { hooks++; throw new Error("canary"); } })]) {
    assert.throws(() => createManagedRuntimeMaterials(fake as unknown as StageOwner, now), refused);
  }
  const f = await materialFixture(), owner = createManagedRuntimeMaterials(f.stageOwner, now);
  try {
    for (const fake of [{ ...owner }, new Proxy(owner, { get() { hooks++; throw new Error("canary"); } }), null]) {
      assert.throws(() => runtimeJwksMaterial(fake as RuntimeMaterials), refused);
      assert.throws(() => runtimeTlsMaterial(fake as RuntimeMaterials, "ingress"), refused);
    }
    disposeStageOwner(f.stageOwner); assert.throws(() => createManagedRuntimeMaterials(f.stageOwner, now), refused);
    assert.equal(hooks, 0);
  } finally { disposeRuntimeMaterials(owner); disposeStageOwner(f.stageOwner); await f.bootstrap.closed; }
});

test("invalid/expired trusted clock cannot produce a material owner", async () => {
  const f = await materialFixture();
  try {
    for (const at of [-1n, 0n, 253402300800000000n, Number(now), 1.1, { valueOf() { throw new Error("canary"); } }]) {
      assert.throws(() => createManagedRuntimeMaterials(f.stageOwner, at as bigint), refused);
    }
  } finally { disposeStageOwner(f.stageOwner); await f.bootstrap.closed; }
});
