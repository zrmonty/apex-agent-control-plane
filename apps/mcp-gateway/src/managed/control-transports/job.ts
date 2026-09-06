import type { Options, Dependencies, Gate, Handle, Pair } from "./types.js";
import { capture, refused, type Captured } from "./capture.js";
import { exact, MAX_TIME } from "../guard/configuration/boundary.js";
type Resource = {
    close(): Promise<void>;
    closing: boolean;
    closed: boolean;
};
const min = (a: bigint, b: bigint) => a < b ? a : b;
export function startPair(options: Options, deps: Dependencies, gate: Gate): Handle {
    if (gate.held) {
        const result = Promise.reject<Pair>(refused());
        void result.catch(() => { });
        return Object.freeze({ result, revoked: Promise.resolve(), closed: Promise.resolve(), cancel() { } });
    }
    const job = new Job(deps, () => {
        if (gate.held === job) delete gate.held;
    });
    gate.held = job;
    job.start(options);
    return job.handle;
}
class Job {
    readonly handle: Handle;
    private resolve!: (pair: Pair) => void;
    private reject!: (error: Error) => void;
    private revoke!: () => void;
    private drain!: () => void;
    private captured?: Captured;
    private fatal = () => { };
    private fatalInvoked = false;
    private started = 0n;
    private last = 0n;
    private lastWall = 0n;
    private workDeadline = 0n;
    private expiry = 0n;
    private notAfterUnixUs = 0n;
    private pending = false;
    private stopped = false;
    private finished = false;
    private settled = false;
    private published = false;
    private resources: Resource[] = [];
    private stopTimer?: () => void;
    private stopCleanup?: () => void;
    private cleanupAt?: bigint;
    private cleanupLast = 0n;
    constructor(private readonly deps: Dependencies, private readonly release: () => void) {
        const result = new Promise<Pair>((yes, no) => { this.resolve = yes; this.reject = no; });
        void result.catch(() => { });
        this.handle = Object.freeze({ result, revoked: new Promise<void>(yes => { this.revoke = yes; }),
            closed: new Promise<void>(yes => { this.drain = yes; }), cancel: () => this.stop() });
    }
    start(options: Options) {
        try {
            const input = exact(options, ["stage", "materials", "onFatal"]);
            if (typeof input.onFatal !== "function")
                throw refused();
            const fatal = input.onFatal;
            this.fatal = () => { fatal(); };
            this.captured = capture(input.stage as Options["stage"], input.materials as Options["materials"]);
            this.started = this.deps.timers.now();
            this.last = this.started;
            if (typeof this.started !== "bigint" || this.started < 0n)
                throw refused();
            this.lastWall = this.wall();
            this.workDeadline = this.started + 10000000000n;
            this.notAfterUnixUs = this.captured.notAfterUnixUs;
            this.expiry = this.started + (this.captured.notAfterUnixUs - this.lastWall - 1000n) * 1000n;
            this.check();
            this.pending = true;
            queueMicrotask(() => { void this.run(); });
        }
        catch {
            this.dispose();
            this.stop();
        }
    }
    private wall() {
        const ms = this.deps.unixMs();
        if (!Number.isSafeInteger(ms) || ms <= 0 || BigInt(ms) * 1000n > MAX_TIME - 1000n)
            throw refused();
        return BigInt(ms) * 1000n;
    }
    private check() {
        if (this.stopped)
            throw refused();
        const now = this.deps.timers.now(), wall = this.wall();
        if (typeof now !== "bigint" || now < this.last || wall < this.lastWall)
            throw refused();
        this.last = now;
        this.lastWall = wall;
        if (this.stopped || (!this.published && now >= this.workDeadline) || now >= this.expiry ||
            wall + 1000n >= this.notAfterUnixUs)
            throw refused();
    }
    private liveClock = () => {
        try {
            this.check();
            return this.last;
        } catch {
            this.stop();
            throw refused();
        }
    };
    private arm() {
        this.check();
        this.stopTimer?.();
        const remaining = (this.published ? this.expiry : min(this.expiry, this.workDeadline)) - this.last;
        if (remaining <= 0n)
            throw refused();
        this.stopTimer = this.deps.timers.after(Number(min(1000n, (remaining + 999999n) / 1000000n)), () => {
            this.stopTimer = undefined;
            try {
                this.arm();
            }
            catch {
                this.stop();
            }
        });
    }
    private adopt(close: () => Promise<void>): Resource {
        const r = { close, closing: false, closed: false };
        this.resources.push(r);
        if (this.stopped)
            this.close(r);
        return r;
    }
    private async run() {
        try {
            this.arm();
            const c = this.captured!;
            const connections = c.destinations.map(destination => {
                this.check();
                const connection = this.deps.connect({ guard: c.guard, destination, startedAtMonotonicNs: this.started,
                    monotonicNowNs: this.liveClock, onFatal: () => { this.stop(); this.notifyFatal(); } });
                this.adopt(() => { connection.cancel(); return connection.closed; });
                void connection.closed.then(() => this.stop(), () => this.stop());
                return connection;
            });
            const channels = await Promise.all(connections.map(async (connection, index) => {
                const session = await connection.result;
                this.check();
                for (const event of ["error", "goaway", "close", "frameError"])
                    session.once(event, () => this.stop());
                const channel = index === 0 ? this.deps.authority(session, { token: c.governanceToken.toString("ascii"), instanceProof: c.proof }, this.liveClock) :
                    this.deps.evidence(session, c.evidenceToken.toString("ascii"), this.liveClock);
                this.adopt(() => channel.close());
                this.check();
                return channel;
            }));
            this.check();
            this.published = true;
            this.arm();
            this.check();
            this.settled = true;
            this.resolve(Object.freeze({ authority: channels[0] as Pair["authority"], evidence: channels[1] as Pair["evidence"] }));
        }
        catch {
            this.stop();
        }
        finally {
            this.pending = false;
            this.dispose();
            this.finish();
        }
    }
    private dispose() { this.captured?.dispose(); this.captured = undefined; }
    private close(r: Resource) {
        if (r.closing)
            return;
        r.closing = true;
        try {
            void r.close().then(() => { r.closed = true; this.finish(); }, () => this.stop());
        }
        catch {
            this.stop();
        }
    }
    private stop() {
        if (this.finished)
            return;
        if (!this.stopped) {
            this.stopped = true;
            this.revoke();
            this.stopTimer?.();
            this.stopTimer = undefined;
            if (!this.settled) {
                this.settled = true;
                this.reject(refused());
            }
            let observed = this.last;
            try {
                const value = this.deps.timers.now();
                if (typeof value === "bigint" && value >= observed)
                    observed = value;
            }
            catch { /* Preserve last accepted floor. */ }
            this.cleanupLast = observed;
            this.cleanupAt = min(observed, this.published ? this.expiry : min(this.expiry, this.workDeadline)) + 5000000000n;
        }
        for (const r of this.resources)
            this.close(r);
        this.finish();
        this.cleanup();
    }
    private cleanup() {
        if (this.finished || this.fatalInvoked || this.stopCleanup || this.cleanupAt === undefined)
            return;
        let remaining = 0n;
        try {
            const sample = this.deps.timers.now();
            if (typeof sample !== "bigint" || sample < this.cleanupLast)
                throw refused();
            this.cleanupLast = sample;
            remaining = this.cleanupAt - sample;
        }
        catch { /* Never renew grace after uncertain clocks. */ }
        if (remaining <= 0n) {
            this.notifyFatal();
            return;
        }
        this.stopCleanup = this.deps.timers.after(Number((remaining + 999999n) / 1000000n), () => { this.stopCleanup = undefined; this.cleanup(); });
    }
    private notifyFatal() {
        if (this.finished || this.fatalInvoked) return;
        this.fatalInvoked = true;
        try { this.fatal(); }
        catch { /* Unknown work remains owned. */ }
    }
    private finish() {
        if (this.finished || !this.stopped || this.pending || this.captured || this.resources.some(r => !r.closed))
            return;
        this.finished = true;
        this.stopTimer?.();
        this.stopCleanup?.();
        this.release();
        this.drain();
    }
}
