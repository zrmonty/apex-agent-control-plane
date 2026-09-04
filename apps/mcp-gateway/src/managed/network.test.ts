import assert from "node:assert/strict";
import test from "node:test";

import { GatewayError } from "../contracts.js";
import {
  validateHttpsDestination,
  validateRedirect,
  validateResolvedAddresses,
} from "./network.js";

function assertRejected(action: () => unknown): void {
  assert.throws(
    action,
    (error: unknown) => error instanceof GatewayError && error.code === "INVALID_INPUT",
  );
}

test("accepts only declared HTTPS destinations on safe ports", () => {
  const endpoint = validateHttpsDestination(
    "https://portfolio.example.test/mcp",
    ["portfolio.example.test"],
  );

  assert.equal(endpoint.hostname, "portfolio.example.test");
  assert.equal(endpoint.port, "");
});

test("rejects unsafe schemes, ports, host forms, and undeclared hosts", () => {
  for (const endpoint of [
    "http://portfolio.example.test/mcp",
    "https://portfolio.example.test:22/mcp",
    "https://127.0.0.1/mcp",
    "https://user:pass@portfolio.example.test/mcp",
    "https://portfolio.example.test/mcp#fragment",
  ]) {
    assertRejected(() => validateHttpsDestination(endpoint, ["portfolio.example.test"]));
  }

  assertRejected(() =>
    validateHttpsDestination("https://other.example.test/mcp", ["portfolio.example.test"]),
  );
});

test("rejects private, metadata, link-local, and multicast DNS answers", () => {
  for (const address of [
    "10.0.0.5",
    "192.168.1.12",
    "169.254.169.254",
    "127.0.0.1",
    "224.0.0.1",
    "::1",
    "fc00::1",
    "fe80::1",
    "ff02::1",
  ]) {
    assertRejected(() => validateResolvedAddresses("portfolio.example.test", [address]));
  }
  assertRejected(() => validateResolvedAddresses("portfolio.example.test", ["93.184.216.999"]));
});

test("revalidates redirects against the declared destination policy", () => {
  const original = validateHttpsDestination(
    "https://portfolio.example.test/mcp",
    ["portfolio.example.test"],
  );
  const redirected = validateRedirect(original, "https://portfolio.example.test/v2/mcp", [
    "portfolio.example.test",
  ]);

  assert.equal(redirected.pathname, "/v2/mcp");
  assertRejected(() =>
    validateRedirect(original, "https://other.example.test/mcp", ["portfolio.example.test"]),
  );
});
