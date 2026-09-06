import assert from "node:assert/strict";
import test from "node:test";
import { fromBinary, toBinary } from "@bufbuild/protobuf";
import * as contracts from "../../packages/apex-contracts-ts/src/index.js";

test("installed attestation is additive digest-only evidence, not a caller proof credential", () => {
  const field = contracts.RuntimeObservationSchema.fields.find(f => f.name === "launch_attestation");
  assert.equal(field?.number, 12);
  assert.equal(field?.message?.typeName, "apex.v1.RuntimeLaunchAttestation");
  assert.deepEqual(contracts.RuntimeLaunchAttestationSchema.fields.map(f => [f.number, f.name]), [
    [1, "schema_version"], [2, "installation_id"], [3, "launch"],
    [4, "instance_proof_sha256"], [5, "staged_manifest_sha256"], [6, "image_id"],
  ]);
  const input = { schemaVersion: 1, installationId: "installation", launch: {
    target: { generation: "9007199254740993", fencingToken: "9007199254740995" },
    processInstanceId: "instance", configHash: "a".repeat(64), launchContextHash: "b".repeat(64),
  }, instanceProofSha256: "c".repeat(64), stagedManifestSha256: "d".repeat(64), imageId: `sha256:${"e".repeat(64)}` };
  const schema = contracts.RuntimeLaunchAttestationSchema;
  const decoded = contracts.decodeStrict(schema, JSON.stringify(input));
  assert.equal(decoded.launch.target.fencingToken, 9007199254740995n);
  assert.deepEqual(contracts.encodeJson(schema, fromBinary(schema, toBinary(schema, decoded))), input);
  assert.throws(() => contracts.decodeStrict(schema, '{"instanceProof":"never-on-the-wire"}'));
});
