import assert from "node:assert/strict";
import test, { type TestContext } from "node:test";

import { parseRuntimeConfiguration } from "../runtime-config.js";
import { assertDataTree } from "./boundary.js";
import { artifactText, source, rejectsSafely, rustManifestHash } from "./test-support.js";

/** Stop only the real codec's root-object stringify, so a RED run cannot expand
 * the shared graph. This spy checks allocation order, not the final rejection
 * (which the unfixed downstream codec already performs after serialization).
 */
function rejectedBeforeSerialization(context: TestContext, input: unknown): void {
  const stringify = JSON.stringify;
  let serialized = 0;
  const probe = context.mock.method(JSON, "stringify", (value: unknown) => {
    if (value === input) {
      serialized++;
      throw new Error("serialization boundary reached");
    }
    return stringify(value);
  });
  try {
    rejectsSafely(() => parseRuntimeConfiguration(input));
    assert.equal(serialized, 0, "over-budget object must be rejected before generated codec serialization");
  } finally {
    probe.mock.restore();
  }
}

test("object preflight counts shared legal-size strings before generated serialization", context => {
  const input = source();
  // Only one 16 KiB string and 17 references; expanded content alone is 272 KiB.
  input.secretRefs = Array<string>(17).fill("x".repeat(16384));
  rejectedBeforeSerialization(context, input);
});

test("object preflight counts shared object keys on every occurrence", context => {
  const input = source();
  const shared = { ["k".repeat(16384)]: "" };
  // Keys alone would occupy 272 KiB; no expanded JSON is ever allocated.
  input.secretRefs = Array(17).fill(shared);
  rejectedBeforeSerialization(context, input);
});

test("object preflight counts JSON escaping of repeated keys and values", context => {
  for (const shared of [
    "\u0000".repeat(4096), // Each control byte requires six JSON bytes.
    { ['"'.repeat(12288)]: "" }, // Each quote in a key requires two JSON bytes.
  ]) {
    const input = source();
    input.secretRefs = Array(11).fill(shared);
    rejectedBeforeSerialization(context, input);
  }
});

test("preflight enforces the escaped UTF-8 budget including quotes and punctuation", () => {
  // {"value":""} is 12 bytes; literal widths below are independent of production.
  for (const [character, width] of [
    ["a", 1], ['"', 2], ["\\", 2], ["\b", 2], ["\t", 2], ["\n", 2],
    ["\f", 2], ["\r", 2], ["\u0000", 6], ["\u001f", 6], ["é", 2], ["雪", 3], ["😀", 4],
  ] as const) {
    const available = 262144 - 12;
    const value = character.repeat(Math.floor(available / width)) + "a".repeat(available % width);
    assert.doesNotThrow(() => assertDataTree({ value }, false), `exact limit: ${width}-byte token`);
    rejectsSafely(() => assertDataTree({ value: value + "a" }, false), `one byte over: ${width}-byte token`);
  }
});

test("preflight includes repeated-container syntax and scalar JSON widths", () => {
  // [{"k":""},{"k":""}] is 19 bytes; both occurrences must contribute.
  const shared = { k: "" };
  const remaining = 262144 - 19;
  const half = Math.floor(remaining / 2);
  shared.k = "a".repeat(half);
  assert.doesNotThrow(() => assertDataTree([shared, shared], false));
  shared.k += "a";
  rejectsSafely(() => assertDataTree([shared, shared], false));
  // {"pad":"","scalar":false} is 25 bytes, with five contributed by false.
  for (const [scalar, width] of [[null, 4], [true, 4], [false, 5], [0, 1], [-1.7976931348623157e308, 24]] as const) {
    const pad = "a".repeat(262144 - 20 - width);
    assert.doesNotThrow(() => assertDataTree({ pad, scalar }, false));
    rejectsSafely(() => assertDataTree({ pad: pad + "a", scalar }, false));
  }
});

test("aggregate traversal preserves no-execution guards and does not memoize shared nodes", () => {
  let invoked = 0;
  const shared = { value: "small" };
  assert.doesNotThrow(() => assertDataTree([shared, shared], false));
  const accessor = Object.defineProperty({}, "value", {
    enumerable: true, get() { invoked++; throw new Error("SENSITIVE"); },
  });
  const proxy = new Proxy({}, { ownKeys() { invoked++; throw new Error("SENSITIVE"); } });
  const coercion = Object.defineProperty({}, "toJSON", { value() { invoked++; return "SENSITIVE"; } });
  for (const unsafe of [accessor, proxy, coercion]) rejectsSafely(() => assertDataTree([shared, unsafe], false));
  const cycle: unknown[] = [];
  cycle.push(cycle);
  rejectsSafely(() => assertDataTree(cycle, false));
  rejectsSafely(() => assertDataTree({ value: "\ud800" }, false));
  assert.equal(invoked, 0);
});

test("actual Rust artifact still crosses both preflights and retains its manifest", () => {
  const config = parseRuntimeConfiguration(artifactText);
  assert.doesNotThrow(() => assertDataTree(config, true));
  assert.equal(parseRuntimeConfiguration(source()).runtimeManifestHash, rustManifestHash);
});
