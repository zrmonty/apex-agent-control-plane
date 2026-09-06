import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { fromBinary, toBinary, ScalarType } from "@bufbuild/protobuf";
import * as contracts from "../../packages/apex-contracts-ts/src/index.js";

test("production reconciliation is one additive unary method outside the unchanged browser allowlist", () => {
  assert.deepEqual(contracts.RuntimeExecutionService.methods.map(m => [m.name, m.methodKind, m.input.typeName, m.output.typeName]),
    [["ReconcileRuntime", "unary", "apex.v1.RuntimeReconcileRequest", "apex.v1.RuntimeReconcileResponse"]]);
  const browser = JSON.parse(readFileSync(new URL("../../packages/apex-contracts-ts/src/gen/browser-rpcs.json", import.meta.url)));
  assert.equal(browser.length, 22);
  assert.ok(browser.every(m => m.service === "apex.v1.McpProxyService"));
  for (const [name, fields] of Object.entries({
    RuntimeReconcileRequest: [[1,"schema_version","UINT32"],[2,"target","apex.v1.RuntimeTarget"],[3,"operation_id","STRING"],[4,"command_id","STRING"],[5,"config_hash","STRING"]],
    RuntimeReconcileResponse: [[1,"schema_version","UINT32"],[2,"claims","apex.v1.RuntimeReconcileRequest"],[3,"observed_state","apex.v1.ProxyObservedState"],[4,"runtime","apex.v1.RuntimeObservation"],[5,"error_code","STRING"]],
  })) assert.deepEqual(contracts[`${name}Schema`].fields.map(f => [f.number,f.name,f.message?.typeName ?? f.enum?.typeName ?? ScalarType[f.scalar]]), fields);
});

test("current claims and immutable installed/readiness targets preserve distinct >2^53 fences", () => {
  // Wire preservation only: none of these decoded examples are trusted ownership.
  const installed = { workspaceId:"work",namespaceId:"ns",proxyId:"0191b7f1-7f2c-7c13-9a61-2f29f2be1001",revisionId:"0191b7f1-7f2c-7c13-9a61-2f29f2be1002",generation:"9007199254740993",fencingToken:"9007199254740995" };
  const current = { ...installed,generation:"9007199254740994",fencingToken:"9007199254740999" };
  const value = { schemaVersion:1,claims:{schemaVersion:1,target:current,operationId:"0191b7f1-7f2c-7c13-9a61-2f29f2be1003",commandId:"0191b7f1-7f2c-7c13-9a61-2f29f2be1004",configHash:"a".repeat(64)},observedState:"PROXY_OBSERVED_STATE_NOT_SERVING",runtime:{target:installed,readiness:{target:installed}},errorCode:"RUNTIME_NOT_SERVING" };
  const schema=contracts.RuntimeReconcileResponseSchema;
  const decoded=contracts.decodeStrict(schema,JSON.stringify(value));
  assert.equal(decoded.claims.target.fencingToken,9007199254740999n);
  assert.equal(decoded.runtime.target.fencingToken,9007199254740995n);
  assert.equal(decoded.runtime.readiness.target.fencingToken,9007199254740995n);
  assert.deepEqual(contracts.encodeJson(schema,fromBinary(schema,toBinary(schema,decoded))),value);
  assert.equal(contracts.decodeStrict(schema,"{}").runtime,undefined);
});
