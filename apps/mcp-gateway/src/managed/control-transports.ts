import { startGuardedH2Connection } from "./guard/h2-connection.js";
import { OwnedAuthorityChannel } from "./authority/unary.js";
import { OwnedEvidenceChannel } from "./evidence-channel.js";
import { localTimers } from "./stage-reader/fs.js";
import { startPair } from "./control-transports/job.js";
import type { Gate, Options, Handle } from "./control-transports/types.js";
export type { Options as ManagedControlTransportOptions, Handle as ManagedControlTransports } from "./control-transports/types.js";
const processGate: Gate = {};
/** Stage-bound actual guarded control channels. No admission or readiness claim. */
export function startManagedControlTransports(options: Options): Handle {
    return startPair(options, { timers: localTimers, unixMs: Date.now, connect: startGuardedH2Connection,
        authority: (session, credential, now) => new OwnedAuthorityChannel(session, credential, now),
        evidence: (session, token, now) => new OwnedEvidenceChannel(session, token, now) }, processGate);
}
