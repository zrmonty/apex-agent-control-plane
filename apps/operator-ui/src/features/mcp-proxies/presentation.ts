import { McpProxyLifecycleState as State } from "@apex/contracts";

export const lifecycleCopy: Record<State, string> = {
  [State.UNSPECIFIED]: "Unknown", [State.DRAFT]: "Draft", [State.VALIDATING]: "Validating",
  [State.AWAITING_APPROVAL]: "Awaiting approval", [State.PROVISIONING]: "Provisioning",
  [State.READY]: "Ready", [State.DEGRADED]: "Degraded", [State.PAUSED]: "Paused",
  [State.RETIRING]: "Retiring", [State.RETIRED]: "Retired", [State.FAILED]: "Failed",
};
