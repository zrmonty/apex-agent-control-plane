import assert from "node:assert/strict";
import test from "node:test";

import { GatewayError } from "../contracts.js";
import { parseProxyRevisionConfig } from "./config.js";

const validConfig = {
  proxyId: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e84",
  revisionId: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e85",
  configHash: "a".repeat(64),
  ingress: {
    transport: "streamable-http",
    endpoint: "https://proxy.example.test/mcp",
    allowedOrigins: ["https://console.example.test"],
  },
  upstreams: [
    {
      upstreamId: "portfolio",
      transport: "streamable-http",
      endpointOrCommandRef: "https://portfolio.example.test/mcp",
      credentialRef: "secret://portfolio/read",
    },
  ],
  exposedTools: [
    {
      upstreamId: "portfolio",
      toolName: "portfolio.read",
      alias: "portfolio.read",
      classification: "read",
    },
  ],
  cliProfiles: [],
  authBindings: [
    {
      bindingId: "inbound",
      direction: "inbound",
      audience: "apex-mcp-proxy",
    },
  ],
  governance: {
    policyId: "policy-portfolio-read",
    approvalMode: "none",
    classification: "confidential",
  },
  runtime: {
    imageDigest: "sha256:" + "b".repeat(64),
    cpuMillis: 500,
    memoryBytes: 268_435_456,
    pidLimit: 128,
    readOnlyRootfs: true,
    networkMode: "declared-egress",
    noNewPrivileges: true,
    droppedCapabilities: ["ALL"],
  },
} as const;

function assertInvalid(value: unknown): void {
  assert.throws(
    () => parseProxyRevisionConfig(value),
    (error: unknown) => error instanceof GatewayError && error.code === "INVALID_INPUT",
  );
}

test("accepts a bounded immutable read-only portfolio revision", () => {
  const parsed = parseProxyRevisionConfig(validConfig);

  assert.equal(parsed.proxyId, validConfig.proxyId);
  assert.equal(parsed.governance.classification, "confidential");
  assert.equal(Object.isFrozen(parsed), true);
  assert.equal(Object.isFrozen(parsed.runtime), true);
});

test("rejects missing proxy or revision identity", () => {
  const missingProxy = { ...validConfig, proxyId: undefined };
  const missingRevision = { ...validConfig, revisionId: undefined };

  assertInvalid(missingProxy);
  assertInvalid(missingRevision);
});

test("rejects unknown root and nested fields", () => {
  assertInvalid({ ...validConfig, unexpected: true });
  assertInvalid({
    ...validConfig,
    runtime: { ...validConfig.runtime, hostNetwork: true },
  });
});

test("rejects unbounded runtime and CLI limits", () => {
  assertInvalid({
    ...validConfig,
    runtime: { ...validConfig.runtime, memoryBytes: 2 ** 40 },
  });
  assertInvalid({
    ...validConfig,
    cliProfiles: [
      {
        profileId: "read-cli",
        executableRef: "tool.read",
        executableDigest: "sha256:" + "c".repeat(64),
        fixedArgv: ["read"],
        argvSchema: { fields: [] },
        environmentAllowlist: [],
        secretRefs: [],
        workingDirectory: "/tmp/apex",
        filesystemPolicy: "read-only",
        networkPolicy: "declared-egress",
        shell: false,
        timeoutMs: 300_001,
        maxOutputBytes: 1024,
        allowedExitCodes: [0],
      },
    ],
  });
});

test("requires governance and rejects raw secret values", () => {
  const { governance: _governance, ...missingGovernance } = validConfig;
  assertInvalid(missingGovernance);
  assertInvalid({
    ...validConfig,
    upstreams: [
      {
        ...validConfig.upstreams[0],
        credentialRef: "Bearer raw-token-value",
      },
    ],
  });
});

test("rejects writable rootfs and host networking", () => {
  assertInvalid({
    ...validConfig,
    runtime: { ...validConfig.runtime, readOnlyRootfs: false },
  });
  assertInvalid({
    ...validConfig,
    runtime: { ...validConfig.runtime, networkMode: "host" },
  });
});
