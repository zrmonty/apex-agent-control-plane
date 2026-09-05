import type { Clock } from "../../telemetry/clock.js";
import type { ReadinessBinding } from "../readiness/types.js";

/** Trusted integration precondition, NOT an authenticated TypeScript brand.
 * The owner independently binds complete metadata and HEALTH_TOKEN role/ref/
 * version/content to the immutable local /run/apex/runtime mount AND ancestors,
 * container-relative UID/GID, and read lifetime. No production owner exists here. */
export type HealthMaterialOwner = Readonly<{
  expected: ReadinessBinding;
  isCurrent(binding: ReadinessBinding): boolean;
}>;
export type HealthMaterialLoadOptions = Readonly<{
  owner: HealthMaterialOwner;
  clock: Clock;
  /** Required synchronous nonblocking process-failure request, called once. */
  onFatal(): void;
}>;
export type LoadedHealthMaterial = Readonly<{
  binding: ReadinessBinding;
  /** Loader-owned exact32 bytes. Consumers must copy before disposing. */
  tokenBytes: Buffer;
  dispose(): void;
}>;
export type HealthMaterialLoad = Readonly<{
  /** Settles only after actual outstanding work/descriptor cleanup. A timeout
   * or fatal callback is not termination. Unresolved work remains retained. */
  completion: Promise<LoadedHealthMaterial>;
  /** Latches failure before cleanup; after success disposes the owned token. */
  cancel(): void;
}>;

// Private, purpose-specific OS test seam; never an option of the public loader.
export type Metadata = Readonly<{
  dev: bigint; ino: bigint; mode: bigint; uid: bigint; gid: bigint;
  nlink: bigint; size: bigint; mtimeNs: bigint; ctimeNs: bigint;
}>;
export type HealthFile = Readonly<{
  stat(): Promise<Metadata>;
  read(buffer: Buffer, offset: number, length: number): Promise<number>;
  close(): Promise<void>;
}>;
export type HealthFileSystem = Readonly<{
  platform: string;
  flags: Readonly<{ readOnly: number; noFollow: number; nonblock: number }>;
  lstat(path: string): Promise<Metadata>;
  open(path: string, flags: number): Promise<HealthFile>;
}>;
export type TimerBoundary = Readonly<{
  /** Private OS monotonic anchor covers synchronous defensive copying before
   * any supplied callback. Not a public clock/policy override. */
  monotonicNs(): bigint;
  after(ms: number, callback: () => void): () => void;
}>;
