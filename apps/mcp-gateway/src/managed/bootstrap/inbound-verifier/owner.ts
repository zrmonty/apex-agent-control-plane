import { RuntimeConfigurationSchema } from "@apex/contracts";
import { jwtVerify } from "jose";
import type { ManagedInboundVerifier } from "../inbound-verifier.js";
import { runtimeManifestHash, type ReadonlyRuntimeConfiguration } from "../../runtime-config.js";
import { assertDataTree, assertMessage } from "../../runtime-config/boundary.js";
import { validateMetadata } from "../../runtime-config/validation.js";
import type { RuntimeConfiguration } from "@apex/contracts";
import { publicKeys, refused } from "./keys.js";
import { claims, compact, type Binding } from "./token.js";

/** Internal fixture seam. Production entry supplies real JOSE and clocks. */
export function createVerifier(bytes: Uint8Array, config: ReadonlyRuntimeConfiguration,
  dependencies: Readonly<{ verify: typeof jwtVerify; wallMs(): number; monoNs(): bigint }>): ManagedInboundVerifier {
  try {
    assertDataTree(config, true); assertMessage(RuntimeConfigurationSchema, config);
    validateMetadata(config as RuntimeConfiguration);
    if (runtimeManifestHash(config) !== config.runtimeManifestHash) throw refused();
    const binding: Binding = Object.freeze({ issuer: config.auth!.issuer, audience: config.auth!.audience,
      proxyId: config.proxyId, scopes: Object.freeze([...config.auth!.requiredScopes]) });
    const keys = publicKeys(bytes);
    let stopped = false, pending = 0, last: bigint | undefined, drain!: () => void;
    const closed = new Promise<void>(done => { drain = done; });
    const finish = () => { if (stopped && !pending) { keys.clear(); drain(); } };
    const close = () => { stopped = true; finish(); return closed; };
    const sample = () => {
      try {
        const mono = dependencies.monoNs(), wall = dependencies.wallMs();
        if (stopped || typeof mono !== "bigint" || mono < 0n || last !== undefined && mono < last ||
          !Number.isSafeInteger(wall) || wall < 0 || wall >= 253402300800000) throw refused();
        last = mono; return { mono, wall };
      } catch { void close(); throw refused(); }
    };
    return Object.freeze({ close, async verify(token: string) {
      if (stopped || pending >= 128) throw refused();
      pending++;
      try {
        const start = sample(), input = compact(token), selected = keys.get(input.header.kid);
        if (!selected || selected.alg !== input.header.alg) throw refused();
        claims(input.payload, binding, start.wall);
        if (stopped || sample().mono - start.mono >= 5000000000n) throw refused();
        await dependencies.verify(token, selected.key, { issuer: binding.issuer, audience: binding.audience,
          algorithms: [selected.alg], requiredClaims: ["iss", "aud", "sub", "exp"], currentDate: new Date(start.wall), clockTolerance: 0 });
        const end = sample(); if (stopped || end.mono - start.mono >= 5000000000n) throw refused();
        return claims(input.payload, binding, end.wall);
      } catch { throw refused(); }
      finally { pending--; finish(); }
    } });
  } catch { throw refused(); }
}
