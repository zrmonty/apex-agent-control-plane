import { expect, test, vi } from "vitest";
import { requestId, createProxyApi } from "./api";
import { createManagementClient } from "../../api/client";
import { McpProxyService } from "@apex/contracts";

const session = { subject: "operator:keycloak:alice", csrfToken: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8" };
const api = () => createProxyApi(createManagementClient(() => session, () => {}));

test("management mutation IDs are lowercase UUIDv7, not browser UUIDv4", () => {
  expect(requestId()).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
});

test("inventory outage cannot return preview data as server state", async () => {
  const fetch = vi.fn().mockRejectedValue(new TypeError("offline"));
  vi.stubGlobal("fetch", fetch);
  await expect(api().listProxies({ workspaceId: "acme", namespaceId: "prod" }))
    .rejects.toThrow();
  expect(fetch).toHaveBeenCalledOnce();
});

test("proxy API exposes exactly the generated 22 management methods", () => {
  expect(Object.keys(api()).sort()).toEqual(Object.keys(McpProxyService.method).sort());
});

test("list returns generated server fields and the exact opaque pagination token", async () => {
  const fetch = vi.fn().mockResolvedValue(new Response('{"proxies":[],"nextPageToken":"opaque-cursor"}', { headers: { "content-type": "application/json" } }));
  vi.stubGlobal("fetch", fetch);
  const result = await api().listProxies({ workspaceId: "acme", namespaceId: "prod", pageSize: 25, pageToken: "previous" });
  expect(result.proxies).toEqual([]);
  expect(result.nextPageToken).toBe("opaque-cursor");
  expect(fetch.mock.calls[0][0]).toBe("/api/apex/v1/McpProxyService/ListProxies");
  expect(JSON.parse(fetch.mock.calls[0][1].body)).toEqual({ workspaceId: "acme", namespaceId: "prod", pageSize: 25, pageToken: "previous" });
});
