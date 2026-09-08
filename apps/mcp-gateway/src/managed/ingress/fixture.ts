import { X509Certificate } from "node:crypto";
import { request } from "node:https";
import type { TestContext } from "node:test";
import assert from "node:assert/strict";
import { setTimeout as delay } from "node:timers/promises";
import { materialFixture, now } from "../bootstrap/runtime-materials/fixture.js";
import { fixture as pki } from "../bootstrap/tls-role-fixture.js";
import { createManagedRuntimeMaterials, disposeRuntimeMaterials } from "../bootstrap/runtime-materials.js";
import { disposeStageOwner } from "../bootstrap/stage-owner.js";
import { executionFixture } from "./execution-fixture.js";
import { startIngress } from "./owner.js";
import type { IngressLimits } from "./limits.js";
export { pki };
export async function until(check: () => boolean) {
  for (let i = 0; i < 100; i++) { if (check()) return; await delay(10); }
  assert.ok(check(), "expected observable work within one second");
}

export async function ingressFixture(t: TestContext, limits?: Partial<IngressLimits>, initiallyAdmitting = true) {
  const f = await materialFixture(value => {
    value.value.profile.managed.ingress.edge_certificate_sha256 = [
      new X509Certificate(pki.governance.cert).fingerprint256.replaceAll(":", "").toLowerCase(),
    ];
    value.stage.files["authority-profile.json"] = value.bytes();
  });
  const materials = createManagedRuntimeMaterials(f.stageOwner, now), execution = executionFixture(f.stageOwner);
  let admitting = initiallyAdmitting, fatals = 0;
  const options = { stage: f.stageOwner, materials, executor: execution.executor,
    clock: execution.clock, isAdmitting: () => admitting, onFatal: () => { fatals++; },
    verifier: { async verify(token: string) {
      if (token !== "alice" && token !== "bob") throw Error("synthetic rejected token");
      return { issuer: f.stageOwner.documents.config.auth!.issuer,
        audience: f.stageOwner.documents.config.auth!.audience, subject: token,
        proxyId: f.stageOwner.documents.config.proxyId, expiresAt: 4_000_000_000, scope: "mcp:tools" };
    } },
  };
  const ingress = startIngress(options, { address: () => ({ host: "127.0.0.1", port: 0 }), limits });
  t.after(async () => {
    ingress.cancel(); await execution.cleanup(); await ingress.closed;
    disposeRuntimeMaterials(materials); disposeStageOwner(f.stageOwner); await f.bootstrap.closed;
  });
  const address = await ingress.result;
  return { ...f, options, ingress, address, execution, revoke() { admitting = false; },
    admit() { admitting = true; }, get fatals() { return fatals; } };
}

export const initialize = { jsonrpc: "2.0", id: 1, method: "initialize", params: {
  protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "synthetic-ingress-test", version: "1" },
} };
export function send(port: number, options: { method?: string; path?: string; body?: unknown;
  signal?: AbortSignal;
  headers?: Record<string, string | string[]>; token?: string | null; servername?: string;
  cert?: { cert: string; key: string } | null } = {}) {
  return new Promise<{ status: number; headers: import("node:http").IncomingHttpHeaders; body: string }>((resolve, reject) => {
    const body = options.body === undefined ? undefined : JSON.stringify(options.body);
    const req = request({ host: "127.0.0.1", port, signal: options.signal, servername: options.servername ?? "gateway.test", ca: pki.ca,
      ...(options.cert === null ? {} : options.cert ?? pki.governance), agent: false,
      method: options.method ?? "POST", path: options.path ?? "/mcp",
      headers: { host: "proxy.apex.test", origin: "https://console.apex.test",
        ...(options.token === null ? {} : { authorization: `Bearer ${options.token ?? "alice"}` }),
        accept: "application/json, text/event-stream", ...(body ? { "content-type": "application/json",
          "content-length": String(Buffer.byteLength(body)) } : {}), ...options.headers },
    }, res => {
      let data = ""; res.on("data", chunk => { data += String(chunk); });
      res.on("end", () => resolve({ status: res.statusCode!, headers: res.headers, body: data }));
      res.on("error", reject);
    });
    req.on("error", reject); req.setTimeout(3000, () => req.destroy(Error("test request timeout"))); req.end(body);
  });
}
