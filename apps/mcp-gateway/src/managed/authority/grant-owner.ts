import { randomBytes } from "node:crypto";
import { GatewayError } from "../../contracts.js";
import { immutableBinding, MAX_GRANT_US, nonce, uint64, validReply } from "./binding.js";
import type { DeploymentBinding, GrantExchange, GrantOwnerOptions, GrantReply,
  GrantScheduler, GrantSnapshot } from "./types.js";

type Pending = {
  result: Promise<boolean>; settle(value: boolean): void;
  drained: Promise<void>; drain(): void;
  started: bigint; nonce: string; sequence: bigint; finished: boolean; physicallyClosed: boolean;
  exchange?: GrantExchange; stopTimer?: () => void;
};
type Accepted = { reply: GrantReply; expires: bigint };
export type OwnedManagedCall = Readonly<{ isCurrent(): boolean; release(): void }>;
const MAX_LOCAL_CALLS = 128;
const timers: GrantScheduler = { after(ms, callback) {
  const timer = setTimeout(callback, ms); return () => clearTimeout(timer);
} };

/** Component boundary; production composition requires the authenticated client. */
export class DeploymentGrantOwner {
  private readonly binding: DeploymentBinding;
  private readonly scheduler: GrantScheduler;
  private pending?: Pending;
  private accepted?: Accepted;
  private lastTime?: bigint;
  private lastNonce?: string;
  private sequence = 0n;
  private stopped = false;
  private clockFailed = false;
  private activeCalls = 0;
  private callsDrained?: Promise<void>;
  private drainCalls?: () => void;

  constructor(private readonly options: GrantOwnerOptions) {
    this.binding = immutableBinding(options.binding);
    this.scheduler = options.scheduler ?? timers;
    if (typeof options.monotonicNowNs !== "function" || typeof options.transport?.start !== "function" ||
      typeof this.scheduler.after !== "function") {
      throw new GatewayError("INVALID_INPUT", "deployment grant owner rejected safely");
    }
  }

  renew(): Promise<boolean> {
    if (this.pending) return this.pending.result;
    if (this.stopped || this.clockFailed) return Promise.resolve(false);
    let settle!: Pending["settle"], drain!: Pending["drain"];
    const job: Pending = { result: new Promise(done => { settle = done; }), settle: value => settle(value),
      drained: new Promise(done => { drain = done; }), drain: () => drain(), started: 0n, nonce: "",
      sequence: 0n, finished: false, physicallyClosed: false };
    // Reserve before trusted callbacks: even synchronous reentry shares one owner.
    this.pending = job;
    try {
      const started = this.sample();
      const requestNonce = this.options.nonce?.() ?? randomBytes(32).toString("hex");
      if (started === undefined || this.stopped || !nonce(requestNonce) || requestNonce === this.lastNonce) throw new Error();
      job.started = started; job.nonce = requestNonce; this.lastNonce = requestNonce;
      if (!uint64(this.sequence + 1n)) { this.stopped = true; throw new Error(); }
      job.sequence = ++this.sequence;
      const snapshot = this.snapshot();
      const applied = this.accepted ? Object.freeze({ decisionId: this.accepted.reply.decisionId,
        epoch: this.accepted.reply.epoch, admitting: snapshot.admitting, activeCalls: this.activeCalls }) : undefined;
      if (this.stopped || this.clockFailed) throw new Error();
      job.exchange = this.options.transport.start(Object.freeze({ binding: this.binding, nonce: requestNonce,
        renewalSequence: job.sequence, applied }));
      // Observe both immediately; neither a rejected result nor timeout detaches cleanup.
      void job.exchange.result.then(reply => this.receive(job, reply), () => this.fail(job));
      void job.exchange.closed.then(() => {
        job.physicallyClosed = true;
        this.release(job);
      }, () => {
        // Failed cleanup is not termination proof. Keep the slot until process teardown.
        this.fail(job);
      });
      if (this.stopped) this.fail(job);
      else this.arm(job);
    } catch {
      if (!job.exchange) job.physicallyClosed = true;
      this.fail(job);
    }
    return job.result;
  }

  snapshot(): GrantSnapshot {
    const now = this.sample();
    const reply = this.accepted?.reply;
    const mode = !this.stopped && now !== undefined && this.accepted && now < this.accepted.expires ? reply!.mode : "closed";
    return Object.freeze({ mode, admitting: mode === "serve", activeCalls: this.activeCalls,
      epoch: reply?.epoch, decisionId: reply?.decisionId });
  }

  /** Local physical ceiling only; a separate durable policy reservation is mandatory. */
  tryBeginCall(): OwnedManagedCall | undefined {
    const grant = this.snapshot();
    if (!grant.admitting || this.activeCalls >= MAX_LOCAL_CALLS) return undefined;
    this.activeCalls += 1;
    let released = false;
    return Object.freeze({
      isCurrent: () => !released && this.snapshot().admitting && this.accepted?.reply.epoch === grant.epoch,
      release: () => {
        if (released) return;
        released = true; this.activeCalls -= 1;
        if (this.activeCalls === 0) this.drainCalls?.();
      },
    });
  }

  close(): Promise<void> {
    this.stopped = true;
    const job = this.pending;
    if (job) this.fail(job);
    if (this.activeCalls > 0 && !this.callsDrained) {
      this.callsDrained = new Promise(done => { this.drainCalls = done; });
    }
    return Promise.all([job?.drained, this.callsDrained]).then(() => undefined);
  }

  private sample(): bigint | undefined {
    if (this.clockFailed) return undefined;
    try {
      const now = this.options.monotonicNowNs();
      if (typeof now !== "bigint" || now < 0n || (this.lastTime !== undefined && now < this.lastTime)) throw new Error();
      this.lastTime = now; return now;
    } catch { this.clockFailed = true; return undefined; }
  }

  private receive(job: Pending, reply: GrantReply): void {
    if (job.finished || this.pending !== job) return;
    const now = this.sample();
    const previous = this.accepted?.reply;
    if (this.stopped || now === undefined || !validReply(reply, this.binding, job.nonce, job.sequence) ||
      now >= job.started + reply.validForUs * 1_000n ||
      (previous && (reply.epoch < previous.epoch || reply.decisionId === previous.decisionId ||
        (reply.epoch === previous.epoch && reply.mode !== previous.mode)))) {
      this.fail(job); return;
    }
    this.accepted = { reply: Object.freeze({ ...reply, binding: this.binding }), expires: job.started + reply.validForUs * 1_000n };
    this.finish(job, true);
  }

  private arm(job: Pending): void {
    if (job.finished) return;
    const now = this.sample();
    const remaining = now === undefined ? 0n : job.started + MAX_GRANT_US * 1_000n - now;
    if (this.stopped || remaining <= 0n) { this.fail(job); return; }
    job.stopTimer = this.scheduler.after(Number((remaining + 999_999n) / 1_000_000n), () => {
      if (job.finished) return;
      try { this.arm(job); } catch { this.fail(job); }
    });
  }

  private fail(job: Pending): void {
    if (this.pending !== job) return;
    if (this.accepted) this.accepted.expires = 0n;
    this.finish(job, false);
    try { job.exchange?.cancel(); } catch { /* Failure remains physically owned. */ }
  }

  private finish(job: Pending, success: boolean): void {
    if (!job.finished) {
      job.finished = true;
      try { job.stopTimer?.(); } catch { /* No future callback can apply this result. */ }
      job.settle(success);
    }
    this.release(job);
  }

  private release(job: Pending): void {
    if (!job.finished || !job.physicallyClosed) return;
    if (this.pending === job) this.pending = undefined;
    job.drain();
  }
}
