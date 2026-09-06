import { lookup as nativeLookup } from "node:dns";
import { OwnedRelayListener } from "./relay-owner.js";
import { numericAddress, parseConnect, relayRefused } from "./relay-protocol.js";
import type { EgressRelayOptions, IngressRelayOptions, RelayLookup } from "./relay-types.js";

const lookup: RelayLookup = (host, done) => { nativeLookup(host, { all: true }, done); };

/** Trusted composition supplies policy and inspected numeric addresses. These
 * constructor values do not establish protected-stage or kernel provenance. */
export class GuardEgressRelay extends OwnedRelayListener {
  constructor(options: EgressRelayOptions) {
    try {
      const localAddress = numericAddress(options.outboundAddress), policy = options.policy, resolve = options.lookup ?? lookup;
      if (typeof policy?.select !== "function" || typeof resolve !== "function") throw relayRefused();
      super(options, options.gatewayAddress, job => {
        let header = Buffer.alloc(0), selected = false;
        const onData = (bytes: Buffer) => {
          try {
            job.checkHandshake();
            if (selected || header.length + bytes.length > 2048) throw relayRefused();
            header = Buffer.concat([header, bytes]);
            const selector = parseConnect(header); if (!selector) return;
            selected = true;
            const route = policy.select(selector.host, selector.port);
            if (route.host !== selector.host || route.port !== selector.port) throw relayRefused();
            job.checkHandshake();
            job.resolve(route, resolve, localAddress, () => { job.source.off("data", onData); header = Buffer.alloc(0); });
          } catch { job.cancel(); }
        };
        job.source.on("data", onData); job.source.resume();
      });
    } catch { throw relayRefused(); }
  }
}

/** Opaque edge bytes have no routing semantics. No TLS or credential material API. */
export class GuardIngressRelay extends OwnedRelayListener {
  constructor(options: IngressRelayOptions) {
    try {
      const gateway = numericAddress(options.gatewayAddress), localAddress = numericAddress(options.outboundAddress);
      super(options, options.edgeAddress, job => { job.connect(gateway, 8080, localAddress); });
    } catch { throw relayRefused(); }
  }
}
