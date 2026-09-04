import { performance } from "node:perf_hooks";

import { jsonToStruct } from "../src/live/events.ts";

const payload = {
  caller: { principal: "spiffe://apex/agent/research", agent_id: "research-agent" },
  scope: { workspace_id: "northstar", namespace_id: "research" },
  tool: "portfolio.read",
  sizes: { input_bytes: 31, source_bytes: 208, filtered_bytes: 150, output_bytes: 150 },
  filtering: { removed_fields: ["client.account_number", "client.tax_id"] },
};

function oldJsonToStruct(value) {
  return {
    fields: Object.fromEntries(
      Object.entries(value).map(([key, item]) => [key, oldJsonToValue(item)]),
    ),
  };
}

function oldJsonToValue(value) {
  if (value === null) return { nullValue: 0 };
  if (typeof value === "boolean") return { boolValue: value };
  if (typeof value === "string") return { stringValue: value };
  if (typeof value === "number") {
    if (!Number.isFinite(value) || !Number.isSafeInteger(value)) {
      throw new TypeError("Struct numbers must be finite safe integers");
    }
    return { numberValue: value };
  }
  if (Array.isArray(value)) return { listValue: { values: value.map(oldJsonToValue) } };
  return { structValue: oldJsonToStruct(value) };
}

if (JSON.stringify(oldJsonToStruct(payload)) !== JSON.stringify(jsonToStruct(payload))) {
  throw new Error("benchmark encoders produced different wire values");
}

function measure(fn, iterations) {
  for (let index = 0; index < 10_000; index += 1) fn(payload);
  const started = performance.now();
  for (let index = 0; index < iterations; index += 1) fn(payload);
  return performance.now() - started;
}

const iterations = 100_000;
const samples = Array.from({ length: 5 }, () => ({
  oldMs: measure(oldJsonToStruct, iterations),
  newMs: measure(jsonToStruct, iterations),
}));
console.log(JSON.stringify({ iterations, samples }, null, 2));
