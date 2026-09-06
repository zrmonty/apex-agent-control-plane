import { parseManagedStageDocuments } from "../stage-documents.js";
import { parseSealedStageEnvironment, type ManagedBootstrapSelection } from "../environment.js";
import { data } from "../../stage-reader/validation.js";
import type { LoadedManagedStage, ManagedStageLoad, ManagedStageLoadOptions, Timers } from "../../stage-reader/types.js";
import { publishMaterial, refused, type StageOwner } from "./material.js";
export type { StageOwner } from "./material.js";
export interface BootstrapOptions { readonly env: NodeJS.ProcessEnv; readonly onFatal: () => void }
export interface StageBootstrap { readonly result: Promise<StageOwner>; readonly closed: Promise<void>; cancel(): void }
export type Loader = (options: ManagedStageLoadOptions) => ManagedStageLoad;
export type Gate = { held?: object };
const WORK = 5000000000n;
export function startOwnedStage(input: BootstrapOptions, load: Loader, time: Timers, gate: Gate): StageBootstrap {
  if (gate.held) {
    const result = Promise.reject<StageOwner>(refused()); void result.catch(() => {});
    return Object.freeze({ result, closed: Promise.resolve(), cancel() {} });
  }
  const job = new Job(load, time, () => { if (gate.held === job) delete gate.held; });
  gate.held = job; // Strong retention, including uncertain physical closure.
  job.start(input);
  return job.handle;
}

class Job {
  readonly handle: StageBootstrap;
  private entry = 0n;
  private last = 0n;
  private selection?: ManagedBootstrapSelection;
  private fatalCallback?: () => void;
  private fatal = false;
  private failed = false;
  private published = false;
  private pendingStart = true;
  private settled = true;
  private physical = true;
  private cleaned = true;
  private done = false;
  private cancelledLoader = false;
  private loader?: ManagedStageLoad;
  private material?: LoadedManagedStage;
  private publishedMaterial?: ReturnType<typeof publishMaterial>;
  private stopTimer?: () => void;
  private resolve!: (owner: StageOwner) => void;
  private reject!: (error: Error) => void;
  private resolveClosed!: () => void;

  constructor(private readonly load: Loader, private readonly time: Timers, private readonly release: () => void) {
    const result = new Promise<StageOwner>((yes, no) => { this.resolve = yes; this.reject = no; });
    // Contain early cancellation/refusal even when the caller observes later.
    void result.catch(() => {});
    this.handle = Object.freeze({ result, closed: new Promise<void>(yes => { this.resolveClosed = yes; }),
      cancel: () => this.fail() });
  }
  start(input: BootstrapOptions): void {
    try {
      this.entry = this.last = this.sample();
      const fatal = data(input, "onFatal"), env = data(input, "env");
      if (typeof fatal !== "function") throw refused();
      this.fatalCallback = () => { fatal(); };
      this.selection = parseSealedStageEnvironment(env as NodeJS.ProcessEnv);
      this.guard(); this.arm();
      queueMicrotask(() => this.run());
    } catch { this.pendingStart = false; this.fail(); }
  }
  private sample(): bigint {
    const now = this.time.now();
    if (typeof now !== "bigint" || now < 0n || now < this.last) throw refused();
    this.last = now; return now;
  }
  private guard(): bigint {
    if (this.failed) throw refused();
    const now = this.sample();
    if (this.failed || now - this.entry >= WORK) throw refused();
    return now;
  }
  private arm(): void {
    const remaining = this.entry + WORK - this.guard();
    this.stopTimer = this.time.after(Number((remaining + 999999n) / 1000000n), () => {
      this.stopTimer = undefined;
      if (this.published || this.failed) return;
      try { this.guard(); this.arm(); } catch { this.fail(); }
    });
  }
  private run(): void {
    try {
      this.guard(); this.settled = false; this.physical = false;
      try {
        this.loader = this.load(Object.freeze({ expectedManifestSha256: this.selection!.expectedManifestSha256,
          toolSecretReferences: this.selection!.toolSecretReferences, onFatal: () => this.notifyFatal(),
          monotonicNowNs: () => this.guard() }));
      } catch { this.settled = true; this.physical = true; throw refused(); }
      // Attach both rejection handlers BEFORE a post-callback clock/fence can
      // throw, cancel or reenter. No result/close race relinquishes ownership.
      void this.loader.result.then(stage => this.loaded(stage), () => { this.settled = true; this.fail(); this.finish(); });
      void this.loader.closed.then(() => { this.physical = true; this.finish(); }, () => this.notifyFatal());
      this.guard();
    } catch { this.fail(); }
    finally { this.pendingStart = false; this.cancelLoader(); this.finish(); }
  }
  private loaded(stage: LoadedManagedStage): void {
    this.settled = true; this.material = stage; this.cleaned = false;
    try {
      this.guard();
      // Network handoff is captured separately; the document join keeps its
      // exact three-field contract and cannot acquire ambient routing inputs.
      const selection = this.selection!;
      const documents = parseManagedStageDocuments(stage, { installationId: selection.installationId,
        expectedManifestSha256: selection.expectedManifestSha256, toolSecretReferences: selection.toolSecretReferences });
      this.guard();
      this.publishedMaterial = publishMaterial(stage, documents, () => this.dispose(), selection.network);
      this.guard(); // Original entry deadline, after interpretation/capture.
      this.published = true; this.stopTimer?.(); this.stopTimer = undefined;
      this.resolve(this.publishedMaterial.owner);
    } catch { this.fail(); }
    this.finish();
  }
  private dispose(): void {
    if (this.cleaned || !this.material) return;
    const stage = this.material;
    this.material = undefined; // Reentry cannot wipe twice or copy while wiping.
    this.publishedMaterial?.revoke();
    try { stage.dispose(); this.cleaned = true; }
    catch { this.notifyFatal(); } // Uncertain wipe retains the process slot.
    this.finish();
  }
  private fail(): void {
    if (!this.failed) {
      this.failed = true; this.reject(refused()); this.stopTimer?.(); this.stopTimer = undefined;
    }
    this.cancelLoader(); this.dispose(); this.finish();
  }
  private cancelLoader(): void {
    if (!this.failed || !this.loader || this.cancelledLoader) return;
    this.cancelledLoader = true;
    try { this.loader.cancel(); } catch { this.notifyFatal(); }
  }
  private notifyFatal(): void {
    if (this.fatal) return;
    this.fatal = true;
    try { this.fatalCallback?.(); } catch { /* Trusted supervisor must terminate. */ }
  }
  private finish(): void {
    if (this.done || this.pendingStart || !this.settled || !this.physical || !this.cleaned ||
      !this.failed && !this.published) return;
    this.done = true; this.release(); this.resolveClosed();
  }
}
