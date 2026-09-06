export interface ManagedStageLoadOptions {
  readonly expectedManifestSha256: string;
  readonly toolSecretReferences: readonly string[];
  /** Trusted supervisor: terminate the owning process on uncertain cleanup. */
  readonly onFatal: () => void;
  readonly monotonicNowNs?: () => bigint;
}
export interface LoadedManagedStage {
  /** Byte ownership transfers on success. No parsed meaning or provenance claim. */
  readonly files: Readonly<Record<string, Buffer>>;
  readonly manifestSha256: string;
  dispose(): void;
}
export interface ManagedStageLoad {
  readonly result: Promise<LoadedManagedStage>;
  /** Resolves only after actual I/O/close, not merely reporting failure. */
  readonly closed: Promise<void>;
  cancel(): void;
}

// Internal OS boundary. Not reexported by stage-reader.ts.
export type Metadata = Record<"dev" | "ino" | "mode" | "uid" | "gid" | "nlink" |
  "size" | "mtimeNs" | "ctimeNs", bigint>;
export interface FileHandle {
  readonly fd: number;
  stat(): Promise<Metadata>;
  read(buffer: Buffer, offset: number, length: number): Promise<number>;
  close(): Promise<void>;
}
export interface DirectoryHandle {
  read(): Promise<string | null>;
  close(): Promise<void>;
}
export interface FileSystem {
  readonly platform: string;
  readonly flags: { readOnly: number; directory: number; noFollow: number; nonblock: number };
  lstat(path: string): Promise<Metadata>;
  open(path: string, flags: number): Promise<FileHandle>;
  opendir(path: string): Promise<DirectoryHandle>;
}
export interface Timers {
  now(): bigint;
  after(ms: number, callback: () => void): () => void;
}
export function rejected(): Error { return new Error("managed stage load rejected"); }
