import type { InboundTokenVerifier } from "../auth.js";
import type { ReadonlyRuntimeConfiguration } from "../runtime-config.js";
import { createVerifier } from "./inbound-verifier/owner.js";
import { jwtVerify } from "jose";
export interface ManagedInboundVerifier extends InboundTokenVerifier { close(): Promise<void>; }
/** Staged bytes only: no paths, remote JWK fetch or caller-selected crypto. */
export function createManagedInboundVerifier(bytes: Uint8Array, config: ReadonlyRuntimeConfiguration): ManagedInboundVerifier {
  return createVerifier(bytes, config, { verify: jwtVerify, wallMs: Date.now, monoNs: process.hrtime.bigint });
}
