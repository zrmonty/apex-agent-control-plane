import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
import { ManagedDeploymentGrantSchema, ManagedDeploymentRenewalSchema, ManagedGrantMode,
  type ManagedDeploymentBinding } from "@apex/contracts";
import { immutableBinding, nonce, uint64, validReply } from "./binding.js";
import type { DeploymentBinding, GrantExchange, GrantReply, GrantRequest, GrantTransport } from "./types.js";
import type { OwnedAuthorityChannel } from "./unary.js";

const refused = () => new Error("managed grant refused safely");
export class AuthenticatedGrantTransport implements GrantTransport {
  constructor(private readonly channel: Pick<OwnedAuthorityChannel, "start">) {}
  start(request: GrantRequest): GrantExchange {
    const binding = immutableBinding(request.binding);
    const expectedNonce = request.nonce;
    const sequence = request.renewalSequence;
    if (!nonce(expectedNonce) || !uint64(sequence) || (request.applied && (
      !/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(request.applied.decisionId) ||
      !uint64(request.applied.epoch) || typeof request.applied.admitting !== "boolean" ||
      !Number.isSafeInteger(request.applied.activeCalls) || request.applied.activeCalls < 0 || request.applied.activeCalls > 128))) throw refused();
    const payload = toBinary(ManagedDeploymentRenewalSchema, create(ManagedDeploymentRenewalSchema, {
      binding: wireBinding(binding), nonce: Buffer.from(expectedNonce, "hex"), applied: request.applied,
      renewalSequence: sequence,
    }));
    const exchange = this.channel.start("/apex.v1.ManagedRuntimeAuthority/RenewDeployment", payload);
    const result = exchange.result.then(bytes => {
      try {
        const decoded = fromBinary(ManagedDeploymentGrantSchema, bytes);
        const mode = decoded.mode === ManagedGrantMode.PREPARE ? "prepare" :
          decoded.mode === ManagedGrantMode.SERVE ? "serve" : decoded.mode === ManagedGrantMode.CLOSED ? "closed" : undefined;
        if (!mode) throw refused();
        const reply: GrantReply = Object.freeze({ binding: readBinding(decoded.binding),
          nonce: Buffer.from(decoded.nonce).toString("hex"), decisionId: decoded.decisionId,
          renewalSequence: decoded.renewalSequence,
          epoch: decoded.epoch, mode, validForUs: decoded.validForUs });
        if (!validReply(reply, binding, expectedNonce, sequence)) throw refused();
        return reply;
      } catch { exchange.cancel(); throw refused(); }
    }, () => { throw refused(); });
    return Object.freeze({ result, closed: exchange.closed, cancel: () => exchange.cancel() });
  }
}

export function wireBinding(binding: DeploymentBinding) {
  return { installationId: binding.installationId, target: {
    workspaceId: binding.workspaceId, namespaceId: binding.namespaceId, proxyId: binding.proxyId,
    revisionId: binding.revisionId, generation: binding.generation, fencingToken: binding.fencingToken,
  }, processInstanceId: binding.processInstanceId, configHash: binding.configHash, launchContextHash: binding.launchContextHash };
}
export function readBinding(binding: ManagedDeploymentBinding | undefined): DeploymentBinding {
  if (!binding?.target) throw refused();
  return immutableBinding({ installationId: binding.installationId, workspaceId: binding.target.workspaceId,
    namespaceId: binding.target.namespaceId, proxyId: binding.target.proxyId, revisionId: binding.target.revisionId,
    generation: binding.target.generation, fencingToken: binding.target.fencingToken,
    processInstanceId: binding.processInstanceId, configHash: binding.configHash, launchContextHash: binding.launchContextHash });
}
