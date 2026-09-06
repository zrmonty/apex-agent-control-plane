/** Exact immutable deployment identity; never an admission permit by itself. */
export type DeploymentBinding = Readonly<{
  installationId: string;
  workspaceId: string;
  namespaceId: string;
  proxyId: string;
  revisionId: string;
  generation: bigint;
  fencingToken: bigint;
  processInstanceId: string;
  configHash: string;
  launchContextHash: string;
}>;

export type GrantMode = "prepare" | "serve" | "closed";
export type AppliedGrant = Readonly<{
  decisionId: string;
  epoch: bigint;
  admitting: boolean;
  activeCalls: number;
}>;
export type GrantRequest = Readonly<{
  binding: DeploymentBinding;
  nonce: string;
  renewalSequence: bigint;
  applied?: AppliedGrant;
}>;
export type GrantReply = Readonly<{
  binding: DeploymentBinding;
  nonce: string;
  renewalSequence: bigint;
  decisionId: string;
  epoch: bigint;
  mode: GrantMode;
  validForUs: bigint;
}>;

/** `closed` means physical RPC cleanup, not merely a reporting timeout. */
export interface GrantExchange {
  result: Promise<GrantReply>;
  closed: Promise<void>;
  cancel(): void;
}
export interface GrantTransport {
  start(request: GrantRequest): GrantExchange;
}
export interface GrantScheduler {
  after(milliseconds: number, callback: () => void): () => void;
}
export type GrantOwnerOptions = Readonly<{
  binding: DeploymentBinding;
  transport: GrantTransport;
  monotonicNowNs(): bigint;
  nonce?(): string;
  scheduler?: GrantScheduler;
}>;

export type GrantSnapshot = Readonly<{
  mode: GrantMode;
  admitting: boolean;
  activeCalls: number;
  epoch?: bigint;
  decisionId?: string;
}>;
