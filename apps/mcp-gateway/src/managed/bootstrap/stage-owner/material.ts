import { types } from "node:util";
import type { ManagedStageDocuments } from "../stage-documents.js";
import type { LoadedManagedStage } from "../../stage-reader.js";
import { ROLES, data } from "../../stage-reader/validation.js";
import type { SealedStageNetwork } from "../environment.js";

export interface StageOwner { readonly documents: ManagedStageDocuments; readonly network?: SealedStageNetwork }
export const refused = () => new Error("managed stage bootstrap rejected");
const typed = Object.getPrototypeOf(Uint8Array.prototype);
const lengthOf = Object.getOwnPropertyDescriptor(typed, "byteLength")!.get!;
const backing = Object.getOwnPropertyDescriptor(typed, "buffer")!.get!;
const nativeSet = Uint8Array.prototype.set;
type Material = { active: boolean; roles: Map<string, Uint8Array>; tools: Map<string, Uint8Array>; dispose: () => void };
const genuine = new WeakMap<object, Material>();

function view(value: unknown, cap: number): Uint8Array {
  if (types.isProxy(value) || !types.isUint8Array(value)) throw refused();
  const size: number = lengthOf.call(value);
  if (size < 1 || size > cap || types.isSharedArrayBuffer(backing.call(value))) throw refused();
  return value as Uint8Array;
}
/** Internal: only the owning job can publish reader material. Capture passive
 * native views once; no caller/source property access in the copy helpers. */
export function publishMaterial(stage: LoadedManagedStage, documents: ManagedStageDocuments, dispose: () => void,
  network?: SealedStageNetwork) {
  const files = data(stage, "files"), roles = new Map<string, Uint8Array>(), tools = new Map<string, Uint8Array>();
  for (const name of [...ROLES, "instance-proof"]) {
    roles.set(name, view(data(files, name), name === "instance-proof" ? 32 : name === "health-token" ? 43 : 65536));
  }
  for (const entry of documents.tools.entries) tools.set(entry.reference, view(data(files, entry.filename), 65536));
  const owner: StageOwner = Object.freeze({ documents, ...(network ? { network } : {}) });
  const state: Material = { active: true, roles, tools, dispose };
  genuine.set(owner, state);
  return { owner, revoke() { state.active = false; roles.clear(); tools.clear(); } };
}
function stateOf(owner: unknown): Material {
  // WeakMap lookup does not inspect a forged object or invoke proxy traps.
  const state = owner !== null && typeof owner === "object" ? genuine.get(owner) : undefined;
  if (!state) throw refused();
  return state;
}
function copy(owner: unknown, key: unknown, role: boolean): Buffer {
  try {
    const state = stateOf(owner);
    if (!state.active || typeof key !== "string") throw refused();
    const source = (role ? state.roles : state.tools).get(key);
    if (!source) throw refused();
    const bytes = Buffer.alloc(lengthOf.call(source)); nativeSet.call(bytes, source); return bytes;
  } catch { throw refused(); }
}
/** Consumer owns and must eventually wipe this independent copy. */
export function copyStageRole(owner: StageOwner, role: string): Buffer { return copy(owner, role, true); }
/** Only a published, joined tool reference is selectable, never a filename. */
export function copyStageTool(owner: StageOwner, publishedReference: string): Buffer { return copy(owner, publishedReference, false); }
export function disposeStageOwner(owner: StageOwner): void { stateOf(owner).dispose(); }
