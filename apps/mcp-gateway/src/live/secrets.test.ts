import assert from "node:assert/strict";
import { mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import type { LiveGrpcConfig } from "./config.js";
import { loadClientMaterial } from "./secrets.js";

const config: LiveGrpcConfig = {
  endpoint: "https://gateway:8443",
  caFile: "ca.pem",
  clientCertFile: "client.pem",
  clientKeyFile: "client.key",
  tokenFile: "token",
};

async function writeMaterial(root: string): Promise<void> {
  await Promise.all([
    writeFile(path.join(root, "ca.pem"), "ca"),
    writeFile(path.join(root, "client.pem"), "certificate"),
    writeFile(path.join(root, "client.key"), "private-key", { mode: 0o600 }),
    writeFile(path.join(root, "token"), "token-0123456789abcd", { mode: 0o600 }),
  ]);
}

test("loads relative material only from the trusted directory", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "apex-gateway-secrets-"));
  try {
    await writeMaterial(root);
    const material = await loadClientMaterial(config, root);
    assert.equal(material.token, "token-0123456789abcd");
    assert.equal(material.ca.toString(), "ca");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("rejects a non-directory base and paths outside the trusted directory", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "apex-gateway-secrets-"));
  try {
    await writeMaterial(root);
    const fileBase = path.join(root, "ca.pem");
    await assert.rejects(loadClientMaterial(config, fileBase), /GOVERNANCE_UNAVAILABLE/);
    await assert.rejects(
      loadClientMaterial({ ...config, tokenFile: "../outside-token" }, root),
      /GOVERNANCE_UNAVAILABLE/,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("refuses a symlinked private material file", async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "apex-gateway-secrets-"));
  const outside = await mkdtemp(path.join(os.tmpdir(), "apex-gateway-outside-"));
  try {
    await writeMaterial(root);
    await writeFile(path.join(outside, "token"), "token-0123456789abcd");
    try {
      await rm(path.join(root, "token"), { force: true });
      await symlink(path.join(outside, "token"), path.join(root, "token"));
    } catch {
      t.skip("symlink creation is unavailable on this host");
      return;
    }
    await assert.rejects(loadClientMaterial(config, root), /GOVERNANCE_UNAVAILABLE/);
  } finally {
    await rm(root, { recursive: true, force: true });
    await rm(outside, { recursive: true, force: true });
  }
});
