import type { ClientHttp2Session } from "node:http2";
import type { StageOwner } from "../bootstrap/stage-owner.js";
import type { RuntimeMaterials } from "../bootstrap/runtime-materials.js";
import type { OwnedAuthorityChannel, WorkloadCredential } from "../authority/unary.js";
import type { OwnedEvidenceChannel } from "../evidence-channel.js";
import type { GuardedH2Connection, GuardedH2Options } from "../guard/h2-connection.js";
import type { Timers } from "../stage-reader/types.js";
export type Options = Readonly<{
    stage: StageOwner;
    materials: RuntimeMaterials;
    onFatal(): void;
}>;
export type Pair = Readonly<{
    authority: OwnedAuthorityChannel;
    evidence: OwnedEvidenceChannel;
}>;
export type Handle = Readonly<{
    result: Promise<Pair>;
    revoked: Promise<void>;
    closed: Promise<void>;
    cancel(): void;
}>;
export type Gate = {
    held?: object;
};
export type Dependencies = Readonly<{
    timers: Timers;
    unixMs(): number;
    connect(options: GuardedH2Options): GuardedH2Connection;
    authority(session: ClientHttp2Session, credential: WorkloadCredential, now: () => bigint): OwnedAuthorityChannel;
    evidence(session: ClientHttp2Session, token: string, now: () => bigint): OwnedEvidenceChannel;
}>;
