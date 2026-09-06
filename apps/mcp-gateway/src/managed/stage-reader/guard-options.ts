import { types } from "node:util";
import { data } from "./validation.js";
import { rejected } from "./types.js";

export interface GuardStageLoadOptions {
  readonly expectedManifestSha256: string;
  /** Trusted supervisor: terminate this process if physical cleanup is uncertain. */
  readonly onFatal: () => void;
  readonly monotonicNowNs?: () => bigint;
}

/** Internal fixed guard inventory. Never accept caller-supplied paths or names. */
export function guardOptions(value: GuardStageLoadOptions) {
  if (!value || typeof value !== "object" || types.isProxy(value) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(value))) throw rejected();
  const keys = Reflect.ownKeys(value);
  if (keys.length < 2 || keys.length > 3 || keys.some(key => typeof key !== "string" ||
    !["expectedManifestSha256", "onFatal", "monotonicNowNs"].includes(key))) throw rejected();
  const hash = data(value, "expectedManifestSha256"), fatal = data(value, "onFatal");
  const clock = data(value, "monotonicNowNs", true);
  if (typeof hash !== "string" || !/^[a-f0-9]{64}$/.test(hash) || typeof fatal !== "function" ||
    clock !== undefined && typeof clock !== "function") throw rejected();
  return { hash, names: new Map([["guard-config.json", 262144]]),
    fatal: () => { fatal.call(value); },
    clock: clock === undefined ? undefined : () => clock.call(value) as bigint };
}
