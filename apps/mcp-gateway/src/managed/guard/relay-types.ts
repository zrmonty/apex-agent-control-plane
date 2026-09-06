import type { LookupAddress } from "node:dns";
import type { GuardEgressPolicy } from "./egress-policy.js";

/** The callback, not logical cancellation, releases ownership of native DNS. */
export type RelayLookup = (host: string,
  callback: (error: NodeJS.ErrnoException | null, answers: readonly LookupAddress[]) => void) => void;
export type RelayAddress = Readonly<{ address: string; port: number; family: 4 | 6 }>;
export type RelayBindOptions = Readonly<{
  bindAddress: string; port: number; monotonicNowNs?(): bigint;
}>;
export type EgressRelayOptions = RelayBindOptions & Readonly<{
  gatewayAddress: string; outboundAddress: string; policy: GuardEgressPolicy; lookup?: RelayLookup;
}>;
export type IngressRelayOptions = RelayBindOptions & Readonly<{
  edgeAddress: string; gatewayAddress: string; outboundAddress: string;
}>;
