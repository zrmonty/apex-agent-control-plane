import { expect, test, vi } from "vitest";
import { newRequestId } from "./request-id";

const uuid7 = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

test("encodes the exact 48-bit millisecond epoch and RFC version/variant", () => {
  vi.spyOn(Date, "now").mockReturnValue(0x123456789abc);
  const id = newRequestId();
  expect(id).toMatch(uuid7);
  expect(id.replaceAll("-", "").slice(0, 12)).toBe("123456789abc");
});

test("uses independent cryptographic randomness for same-millisecond mutations", () => {
  vi.spyOn(Date, "now").mockReturnValue(1788480000123);
  const values = new Set(Array.from({ length: 256 }, () => newRequestId()));
  expect(values.size).toBe(256);
  for (const value of values) expect(value).toMatch(uuid7);
});

test.each([-1, 2 ** 48, NaN, Infinity, 1.5])("rejects an unrepresentable UUID epoch: %s", (value) => {
  vi.spyOn(Date, "now").mockReturnValue(value);
  expect(() => newRequestId()).toThrow();
});

test("entropy failure does not fall back to Math.random", () => {
  vi.spyOn(crypto, "getRandomValues").mockImplementation(() => { throw new Error("entropy unavailable"); });
  expect(() => newRequestId()).toThrow();
});
