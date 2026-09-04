import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { fromJson } from "@bufbuild/protobuf";
import { StructSchema } from "@bufbuild/protobuf/wkt";
import { decodeStrict, encodeJson, requireCapabilities, approvalMode } from "../../packages/apex-contracts-ts/src/json.js";
import { ProxyStageTimingSchema } from "../../packages/apex-contracts-ts/src/gen/apex/v1/proxy_trace_pb.js";
import { RuntimeConfigurationSchema } from "../../packages/apex-contracts-ts/src/gen/apex/v1/proxy_runtime_pb.js";
import { McpProxyRevisionSchema, CreateProxyRequestSchema } from "../../packages/apex-contracts-ts/src/gen/apex/v1/mcp_proxy_pb.js";
import { ControlCommandRequestSchema } from "../../packages/apex-contracts-ts/src/gen/apex/v1/control_pb.js";
import { ProxyActivitySummarySchema, ProxyOperationSchema } from "../../packages/apex-contracts-ts/src/gen/apex/v1/proxy_management_pb.js";

const fixture = name => JSON.parse(readFileSync(new URL("../fixtures/mcp-proxy/" + name + ".json", import.meta.url)));
test("timing preserves microseconds and integers beyond JavaScript's safe range", () => {
  const input = fixture("trace");
  assert.equal(input.durationUs, "7");
  assert.equal(BigInt(input.startedAtUnixUs) + 1n, 1788480000123457n);
  assert.deepEqual(encodeJson(ProxyStageTimingSchema, decodeStrict(ProxyStageTimingSchema, input)), input);
  const huge = { ...input, startedAtUnixUs: "9007199254740993" };
  assert.equal(encodeJson(ProxyStageTimingSchema, decodeStrict(ProxyStageTimingSchema, huge)).startedAtUnixUs, huge.startedAtUnixUs);
  for (const bad of [9007199254740992, 7, "1e3", "-1", "18446744073709551616"]) {
    assert.throws(() => decodeStrict(ProxyStageTimingSchema, { ...input, durationUs: bad }));
  }
});
test("control and runtime fixtures retain distinct endpoints and resource audience", () => {
  const control = decodeStrict(McpProxyRevisionSchema, fixture("control-revision"));
  const runtime = decodeStrict(RuntimeConfigurationSchema, fixture("runtime-revision"));
  assert.equal(runtime.spec.ingress.host, control.spec.ingress.host);
  assert.notEqual(runtime.resourceUrl, runtime.spec.upstreams[0].endpointOrCommandRef);
  assert.equal(runtime.auth.audience, runtime.resourceUrl);
  assert.deepEqual(encodeJson(RuntimeConfigurationSchema, runtime), fixture("runtime-revision"));
});
test("unknown fields are rejected at every nested typed boundary", () => {
  assert.throws(() => decodeStrict(ProxyStageTimingSchema, { ...fixture("trace"), surprise: true }), /unknown/i);
  const runtime = fixture("runtime-revision");
  runtime.spec.ingress.surprise = true;
  assert.throws(() => decodeStrict(RuntimeConfigurationSchema, runtime), /unknown/i);
});
test("request identifiers reject UUIDv4 and missing identifiers", () => {
  const request = { requestId: "0191b7f1-7f2c-7c13-9a61-2f29f2be1001" };
  assert.equal(decodeStrict(CreateProxyRequestSchema, request).requestId, request.requestId);
  for (const requestId of ["", "0191b7f1-7f2c-4c13-9a61-2f29f2be1001", request.requestId.toUpperCase()]) {
    assert.throws(() => decodeStrict(CreateProxyRequestSchema, { requestId }), /UUIDv7/);
  }
  assert.throws(() => decodeStrict(CreateProxyRequestSchema, {}), /UUIDv7/);
});
for (const [name, schema, wrap] of [
  ["direct operation", ProxyOperationSchema, operation => operation],
  ["oneof lifecycle operation", ProxyActivitySummarySchema, operation => ({ lifecycle: { operation } })],
]) {
  test(`${name} accepts UUIDv7 on decode and encode`, () => {
    const input = wrap({ requestId: "0191b7f1-7f2c-7c13-9a61-2f29f2be1001" });
    assert.deepEqual(encodeJson(schema, decodeStrict(schema, input)), input);
    assert.deepEqual(encodeJson(schema, fromJson(schema, input)), input);
  });
  const invalidOperations = [
    {},
    { requestId: "" },
    { requestId: "0191b7f1-7f2c-4c13-9a61-2f29f2be1001" },
    { requestId: "0191B7F1-7F2C-7C13-9A61-2F29F2BE1001" },
  ];
  test(`${name} rejects missing and invalid UUIDv7 on decode`, () => {
    for (const operation of invalidOperations) {
      const input = wrap(operation);
      assert.throws(() => decodeStrict(schema, input), /UUIDv7/, JSON.stringify(input));
      assert.throws(() => decodeStrict(schema, JSON.stringify(input)), /UUIDv7/);
    }
  });
  test(`${name} rejects missing and invalid UUIDv7 on encode`, () => {
    for (const operation of invalidOperations) {
      const input = wrap(operation);
      assert.throws(() => encodeJson(schema, fromJson(schema, input)), /UUIDv7/, JSON.stringify(input));
    }
  });
}
test("unselected lifecycle oneof does not require an operation request identifier", () => {
  for (const input of [{}, { call: { callId: "call-1" } }, { trace: {} }]) {
    assert.deepEqual(encodeJson(ProxyActivitySummarySchema, decodeStrict(ProxyActivitySummarySchema, input)), input);
  }
});
test("approval modes and capability checks fail closed", () => {
  for (const name of ["none", "operator", "dual-operator"]) assert.equal(approvalMode(name), name);
  for (const name of ["", "dual_operator", "auto", null]) assert.throws(() => approvalMode(name));
  assert.throws(() => requireCapabilities(undefined, ["streamable-http"]), /capabilit/i);
  assert.throws(() => requireCapabilities({ supported: [] }, ["streamable-http"]), /capabilit/i);
  assert.doesNotThrow(() => requireCapabilities({ supported: ["streamable-http"] }, ["streamable-http"]));
});
test("JSON conversion enforces request bounds", () => {
  const oversized = { name: "x".repeat(262145) };
  let nested = {};
  for (let i = 0; i < 70; i++) nested = { nested };
  const wide = Object.fromEntries(Array.from({ length: 8193 }, (_, index) => ["key" + index, true]));
  for (const [input, error] of [[oversized, /size/i], [nested, /depth/i], [wide, /field count/i]]) {
    assert.throws(() => decodeStrict(ProxyStageTimingSchema, input), error);
    assert.throws(() => decodeStrict(ProxyStageTimingSchema, JSON.stringify(input)), error);
  }
});

test("event-compatible Struct data retains decimal strings and fine-grained durations", () => {
  for (const duration of ["1", "7", "999"]) {
    const input = { parameters: { trace: { startedAtUnixUs: "9007199254740993", durationUs: duration } } };
    assert.deepEqual(encodeJson(ControlCommandRequestSchema, decodeStrict(ControlCommandRequestSchema, input)), input);
  }
});

test("conflicting protobuf aliases and unknown enum numbers are refused", () => {
  for (const input of [
    { durationUs: "1", duration_us: "2" },
    '{"durationUs":"1","duration_us":"2"}',
    String.raw`{"durationUs":"1","duration\u005fus":"2"}`,
  ]) assert.throws(() => decodeStrict(ProxyStageTimingSchema, input), /duplicate/);
  const runtime = fixture("runtime-revision");
  runtime.approvalMode = 999;
  assert.throws(() => decodeStrict(RuntimeConfigurationSchema, runtime), /enum/);
});

for (const [name, schema, input] of [
  ["top-level identical values", ProxyStageTimingSchema, '{"durationUs":"7","durationUs":"7"}'],
  ["top-level differing values", ProxyStageTimingSchema, '{"durationUs":"7","durationUs":"8"}'],
  ["invalid numeric value overwritten", ProxyStageTimingSchema, '{"durationUs":9007199254740993,"durationUs":"8"}'],
  ["escaped alias", ProxyStageTimingSchema, String.raw`{"durationUs":"7","duration\u0055s":"8"}`],
  ["escaped alias first", ProxyStageTimingSchema, String.raw`{"\u0064urationUs":"7","durationUs":"8"}`],
  ["oneof operation", ProxyActivitySummarySchema,
    '{"lifecycle":{"operation":{"requestId":"0191b7f1-7f2c-4c13-9a61-2f29f2be1001","requestId":"0191b7f1-7f2c-7c13-9a61-2f29f2be1001"}}}'],
  ["repeated typed message", ProxyActivitySummarySchema,
    '{"trace":{"stages":[{"durationUs":7,"durationUs":"8"}]}}'],
  ["WKT Struct", ControlCommandRequestSchema, '{"parameters":{"key":1,"key":2}}'],
  ["nested WKT Struct", ControlCommandRequestSchema, '{"parameters":{"nested":{"key":1,"key":2}}}'],
  ["WKT list object", ControlCommandRequestSchema, '{"parameters":{"list":[{"key":1,"key":2}]}}'],
  ["direct WKT", StructSchema, '{"key":1,"key":2}'],
  ["WKT empty key", StructSchema, '{"":1,"":2}'],
  ["WKT escaped slash", StructSchema, String.raw`{"a/b":1,"a\/b":2}`],
  ["WKT escaped quote", StructSchema, String.raw`{"a\"b":1,"a\u0022b":2}`],
  ["WKT escaped backslash", StructSchema, String.raw`{"a\\b":1,"a\u005cb":2}`],
  ["WKT escaped control character", StructSchema, String.raw`{"\n":1,"\u000a":2}`],
  ["WKT escaped Unicode", StructSchema, String.raw`{"😀":1,"\ud83d\ude00":2}`],
]) {
  test(`JSON text refuses duplicate keys: ${name}`, () => {
    assert.throws(() => decodeStrict(schema, input), /duplicate/i);
  });
}

test("JSON text accepts sibling keys and delimiters inside escaped strings", () => {
  const input = String.raw`{
    "parameters": {
      "text": "braces { }, commas, colon: and \"key\":1,\"key\":2",
      "slash": "\\",
      "list": [{"key": "first"}, {"key": "second"}, [true, false, null, -1.5e+2]],
      "empty": {}, "emptyList": [], "": "empty key",
      "a\/b": "slash key", "a\"b": "quote key", "\u006bey": "escaped key",
      "é": "composed", "e\u0301": "combining"
    }
  }`;
  assert.deepEqual(encodeJson(ControlCommandRequestSchema, decodeStrict(ControlCommandRequestSchema, input)), JSON.parse(input));
});

test("JSON text retains syntax validation after token scanning", () => {
  for (const input of [
    '', ' ', '{}{}', '{"parameters":{}} trailing', '{"parameters":',
    '{"parameters":{"key":1,}}', '{"parameters":{"list":[1,]}}',
    '{"parameters":{"list":[,1]}}', '{"parameters" {}}', '{parameters:{}}',
    '{"parameters":{"key" 1}}', '{"parameters":{"key":1 "next":2}}',
    '{"parameters":{"key":01}}', '{"parameters":{"key":+1}}',
    '{"parameters":{"key":1e}}', '{"parameters":{"key":NaN}}',
    '{"parameters":{"key":tru}}', '{"parameters":{"key":/*comment*/1}}',
    String.raw`{"parameters":{"key":"bad\x20"}}`,
    String.raw`{"parameters":{"\u00xz":1}}`,
    '{"parameters":{"key":"unterminated}}', '{"parameters":{"key":"line\nbreak"}}',
    '\u00a0{}',
  ]) assert.throws(() => decodeStrict(ControlCommandRequestSchema, input), SyntaxError, input);
});

test("JSON text keeps inclusive depth and aggregate field limits", () => {
  let nested = "leaf";
  for (let i = 0; i < 63; i++) nested = { child: nested };
  assert.doesNotThrow(() => decodeStrict(ControlCommandRequestSchema, JSON.stringify({ parameters: nested })));
  assert.throws(() => decodeStrict(ControlCommandRequestSchema, JSON.stringify({ parameters: { child: nested } })), /depth/i);
  const wide = { list: Array.from({ length: 8190 }, () => null) };
  assert.doesNotThrow(() => decodeStrict(ControlCommandRequestSchema, JSON.stringify({ parameters: wide })));
  wide.list.push(null);
  assert.throws(() => decodeStrict(ControlCommandRequestSchema, JSON.stringify({ parameters: wide })), /field count/i);
  const deepText = '{"parameters":' + '['.repeat(10000) + '0' + ']'.repeat(10000) + '}';
  assert.throws(() => decodeStrict(ControlCommandRequestSchema, deepText), /depth/i);
});

test("audience is not silently defaulted or substituted with an upstream URL", () => {
  for (const audience of ["apex-mcp-proxy", "https://portfolio-api.apex.test/mcp", ""]) {
    const runtime = fixture("runtime-revision");
    runtime.auth.audience = audience;
    assert.throws(() => decodeStrict(RuntimeConfigurationSchema, runtime), /audience/);
  }
});
