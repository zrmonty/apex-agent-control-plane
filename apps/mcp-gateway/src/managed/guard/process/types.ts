import type { LoadedManagedStage, ManagedStageLoad, GuardStageLoadOptions } from "../stage-reader.js";
import type { GuardConfiguration } from "../configuration.js";
import type { EgressRelayOptions, IngressRelayOptions, RelayAddress } from "../relay-types.js";
import type { Timers } from "../../stage-reader/types.js";
export type GuardProcessOptions = Readonly<{ env: NodeJS.ProcessEnv; onFatal(): void }>;
export type GuardProcess = Readonly<{
  result: Promise<Readonly<{ addresses: GuardConfiguration["addresses"] }>>;
  revoked: Promise<void>; closed: Promise<void>; cancel(): void;
}>;
export type Relay = { readonly revoked: Promise<void>; listen(): Promise<RelayAddress>; close(): Promise<void> };
export type Dependencies = Readonly<{
  load(options: GuardStageLoadOptions): ManagedStageLoad;
  ingress(options: IngressRelayOptions): Relay;
  egress(options: EgressRelayOptions): Relay;
  timers: Timers;
  unixMs(): number;
}>;
export type Gate = { held?: object };
export type Material = LoadedManagedStage;
