import { McpProxyService } from "@apex/contracts";
import type { DescMethod, MessageInitShape } from "@bufbuild/protobuf";
import { useMemo } from "react";
import type { createManagementClient } from "../../api/client";
import { useOperatorSession } from "../../api/session-context";

// Generated inputs/outputs, never a parallel handwritten transport model.
export function createProxyApi(client: ReturnType<typeof createManagementClient>) {
  const bind = <M extends DescMethod>(method: M) =>
    (input: MessageInitShape<M["input"]>, signal?: AbortSignal) => client.call(method, input, signal);
  const methods = McpProxyService.method;
  return {
    createProxy: bind(methods.createProxy), getProxy: bind(methods.getProxy),
    listProxies: bind(methods.listProxies), updateProxyDraft: bind(methods.updateProxyDraft),
    validateProxy: bind(methods.validateProxy), discoverUpstream: bind(methods.discoverUpstream),
    testProxyConnection: bind(methods.testProxyConnection), publishProxyRevision: bind(methods.publishProxyRevision),
    deployProxy: bind(methods.deployProxy), pauseProxy: bind(methods.pauseProxy),
    resumeProxy: bind(methods.resumeProxy), rotateProxyCredentials: bind(methods.rotateProxyCredentials),
    rollbackProxy: bind(methods.rollbackProxy), retireProxy: bind(methods.retireProxy),
    listProxyActivity: bind(methods.listProxyActivity), getProxyCapabilities: bind(methods.getProxyCapabilities),
    listProxyRevisions: bind(methods.listProxyRevisions), getProxyOperation: bind(methods.getProxyOperation),
    listProxyBindings: bind(methods.listProxyBindings), listProxyApprovals: bind(methods.listProxyApprovals),
    decideProxyApproval: bind(methods.decideProxyApproval), getProxyTrace: bind(methods.getProxyTrace),
  };
}

export function useProxyApi() {
  const { client } = useOperatorSession();
  return useMemo(() => createProxyApi(client), [client]);
}

export const proxyQueryKeys = {
  list: (prefix: readonly unknown[], pageToken: string) => [...prefix, "list", pageToken] as const,
  detail: (prefix: readonly unknown[], proxyId: string) => [...prefix, "detail", proxyId] as const,
  activity: (prefix: readonly unknown[], proxyId: string, revisionId: string, pageToken: string) =>
    [...prefix, "activity", proxyId, revisionId, pageToken] as const,
};
export { newRequestId as requestId } from "../../api/request-id";
