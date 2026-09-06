import { EventEmitter } from "node:events";
import type { ClientHttp2Session } from "node:http2";
import { materialFixture, now } from "../bootstrap/runtime-materials/fixture.js";
import { createManagedRuntimeMaterials, disposeRuntimeMaterials } from "../bootstrap/runtime-materials.js";
import { disposeStageOwner } from "../bootstrap/stage-owner.js";
import { FakeTime, deferred } from "../stage-reader/fixture.js";
import type { Dependencies, Gate } from "./types.js";
import type { GuardedH2Options } from "../guard/h2-connection.js";
import type { OwnedAuthorityChannel, WorkloadCredential } from "../authority/unary.js";
import type { OwnedEvidenceChannel } from "../evidence-channel.js";
export async function setup() {
    const f = await materialFixture(f => Object.assign(f.env, { APEX_MCP_MANAGED_BOOTSTRAP: "sealed-stage-v2",
        APEX_MCP_NETWORK_PROFILE: "isolated-bridge-v1", APEX_MCP_GUARD_ADDRESS: "10.96.0.3", APEX_MCP_NETWORK_BINDING_SHA256: "b".repeat(64) }));
    const materials = createManagedRuntimeMaterials(f.stageOwner, now), time = new FakeTime(), gate: Gate = {};
    const connections: Connection[] = [], channels: Channel[] = [], credentials: WorkloadCredential[] = [], tokens: string[] = [];
    let fatals = 0;
    const deps: Dependencies = { timers: time, unixMs: () => Number(now / 1000n),
        connect(options) { const c = new Connection(options); connections.push(c); return c; },
        authority(_session, credential) {
            credentials.push({ token: credential.token, instanceProof: Buffer.from(credential.instanceProof) });
            const c = new Channel();
            channels.push(c);
            return c as unknown as OwnedAuthorityChannel;
        },
        evidence(_session, token) { tokens.push(token); const c = new Channel(); channels.push(c); return c as unknown as OwnedEvidenceChannel; } };
    return { f, materials, time, gate, deps, connections, channels, credentials, tokens,
        options: { stage: f.stageOwner, materials, onFatal() { fatals++; } }, fatals: () => fatals,
        async dispose() { disposeRuntimeMaterials(materials); disposeStageOwner(f.stageOwner); await f.bootstrap.closed; } };
}
export class Connection {
    readonly session = new EventEmitter() as ClientHttp2Session;
    readonly response = deferred<ClientHttp2Session>();
    readonly receipt = deferred<void>();
    readonly result = this.response.promise;
    readonly closed = this.receipt.promise;
    cancels = 0;
    hold = false;
    constructor(readonly options: GuardedH2Options) { void this.result.catch(() => { }); }
    ready() { this.response.resolve(this.session); }
    cancel() { this.cancels++; this.response.reject(Error("fixture cancelled")); if (!this.hold)
        this.receipt.resolve(); }
}
export class Channel {
    readonly receipt = deferred<void>();
    closes = 0;
    hold = false;
    close() { this.closes++; if (!this.hold)
        this.receipt.resolve(); return this.receipt.promise; }
}
export async function turn() { for (let i = 0; i < 12; i++)
    await Promise.resolve(); }
