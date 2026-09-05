import assert from "node:assert/strict";
import test from "node:test";
import { clone } from "@bufbuild/protobuf";
import { ReadinessReportSchema } from "@apex/contracts";
import { completed, fixture, rejects, rejectsBoth, text } from "./test-support.js";

test("decode requires original primitive JSON text and cannot accept already collapsed objects", async () => {
  const f = fixture();
  for (const input of [JSON.parse(text(f.report)), f.report, new String(text(f.report)), undefined, null, 1, true]) {
    rejects(() => f.codec.decode(input as never));
  }
  await f.monitor.close();
});

test("original input accepts 8192 bytes including whitespace and rejects byte 8193", async () => {
  const f = fixture(), original = text(f.report), exact = original + " ".repeat(8192 - Buffer.byteLength(original));
  assert.equal(Buffer.byteLength(exact), 8192);
  assert.deepEqual(f.codec.decode(exact), f.report);
  rejects(() => f.codec.decode(exact + " "));
  await f.monitor.close();
});

test("raw byte ceiling precedes every JSON parse including reconstructed scanner keys", async context => {
  const f = fixture();
  for (const input of [" ".repeat(8193), '"' + "雪".repeat(2731) + '"']) {
    assert.ok(Buffer.byteLength(input) > 8192);
    let calls = 0, caught: unknown;
    const probe = context.mock.method(JSON, "parse", () => { calls++; throw new Error("REPORT_CANARY"); });
    try { f.codec.decode(input); } catch (error) { caught = error; } finally { probe.mock.restore(); }
    rejects(() => { if (caught !== undefined) throw caught; });
    assert.equal(calls, 0, "oversized original text never reaches any JSON parser");
  }
  await f.monitor.close();
});

test("original duplicate escaped duplicate alias unknown malformed enum and uint64 fields stay rejected", async () => {
  const f = await completed(), original = text(f.report);
  for (const input of [
    original.replace('"live":true', '"live":true,"live":true'),
    original.replace('"live":true', String.raw`"li\u0076e":true,"live":true`),
    original.replace('"observedAtUnixUs":', '"observed_at_unix_us":"1","observedAtUnixUs":'),
    original.replace('"generation":"1"', '"generation":"1","generation":"1"'),
    original.replace('"durationNs":"0"', '"duration_ns":"0","durationNs":"0"'),
    original.replace('"target":{', '"target":{"rawSecret":"REPORT_CANARY",'),
    original.replace('"checks":[{', '"checks":[{"rawSecret":"REPORT_CANARY",'),
    original.replace('"stages":[{', '"stages":[{"rawSecret":"REPORT_CANARY",'),
    original.replace('{', '{"rawSecret":"REPORT_CANARY",'),
    original.replace('"READINESS_CHECK_STATUS_PASS"', '"READINESS_CHECK_STATUS_FUTURE"'),
    original.replace('"READINESS_REASON_OK"', '999'),
    "", "null", "[]", "{", "true", original + "REPORT_CANARY",
  ]) { assert.notEqual(input, original); rejects(() => f.codec.decode(input)); }
  for (const field of ["observedAtUnixUs", "durationNs", "clockUncertaintyUs", "fencingToken"]) {
    for (const value of [0, 9007199254740992, "01", "-1", "+1", "1e3", "1.0", " 1", "1\n", "18446744073709551616"]) {
      const json = JSON.parse(original);
      if (field === "fencingToken") json.target[field] = value;
      else if (field === "observedAtUnixUs") json[field] = value;
      else json.stages[0][field] = value;
      rejects(() => f.codec.decode(JSON.stringify(json)));
    }
  }
  for (const value of ["\ud800", "\udfff", "\ud800x", "x\udfff"]) {
    const report = clone(ReadinessReportSchema, f.report); report.stages[0].clockSource = value;
    rejectsBoth(f.codec, report);
    rejects(() => f.codec.decode(original.replace('"component-clock"', `"${value}"`)));
  }
  assert.deepEqual(f.codec.decode(original.replace('"live":true', String.raw`"li\u0076e":true`)), f.report);
  await f.monitor.close();
});

test("generated oversized escaped values fail while a maximally sized valid stage profile stays representable", async () => {
  const f = await completed(), maximum = (1n << 64n) - 1n;
  const report = clone(ReadinessReportSchema, f.report); report.observedAtUnixUs = maximum;
  for (const stage of report.stages) Object.assign(stage, { startedAtUnixUs: maximum, durationNs: maximum,
    durationUs: maximum / 1000n, clockResolutionNs: maximum, clockUncertaintyUs: maximum, clockSource: "\\".repeat(128) });
  assert.ok(Buffer.byteLength(text(report)) < 8192); // No fictitious 8192-byte valid generated positive.
  assert.deepEqual(f.codec.decode(f.codec.encode(report)), report);
  report.stages[0].clockSource = "\\".repeat(4096);
  assert.ok(Buffer.byteLength(text(report)) > 8192);
  rejectsBoth(f.codec, report); // Both semantic string bound and byte ceiling apply.
  await f.monitor.close();
});
