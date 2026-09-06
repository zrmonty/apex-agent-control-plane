import { createHash } from "node:crypto";
import { copyStageRole, copyStageTool, type StageOwner } from "./stage-owner.js";
import type { DeploymentBinding } from "../authority/types.js";
import { preflightTlsRole, assertDistinctTlsRoles, tlsRoleMaterial, disposeTlsRole, type TlsRole } from "./tls-role.js";
import { parseManagedUpstreamCredential, upstreamCredentialMaterial, disposeUpstreamCredential, type UpstreamMaterial } from "./upstream-material.js";
import { health } from "../stage-reader/validation.js";
export type RuntimeTlsPurpose = "governance" | "evidence" | "ingress";
export type RuntimeMaterials = Readonly<{ binding: DeploymentBinding; notAfterUnixUs: bigint; upstreamReferences: readonly string[];
  tls: Readonly<Record<RuntimeTlsPurpose, Readonly<{ certificateSha256: string; publicKeySha256: string }>>> }>;
type State = { stage: StageOwner; tls: Map<string, TlsRole>; tokens: Map<string, Buffer>; jwks?: Buffer; upstreams: Map<string, UpstreamMaterial> };
const owned = new WeakMap<RuntimeMaterials, State>();
const refused = () => new Error("managed runtime materials refused safely");
const digest = (bytes: Buffer) => createHash("sha256").update(bytes).digest("hex");

/** Stage remains caller-owned on success AND failure. The root separately
 * disposes it and waits bootstrap.closed; this is not physical I/O closure. */
export function createManagedRuntimeMaterials(stage: StageOwner, nowUnixUs: bigint): RuntimeMaterials {
  const temporary: Buffer[] = [];
  const state: State = { stage, tls: new Map(), tokens: new Map(), upstreams: new Map() };
  try {
    const roleBytes = (name: string) => { const bytes = copyStageRole(stage, name); temporary.push(bytes); return bytes; };
    // Genuine-handle lookup occurs BEFORE any metadata read on a supplied object.
    const proof = roleBytes("instance-proof");
    if (proof.length !== 32 || proof.every(byte => byte === 0)) throw refused();
    const documents = stage.documents, profile = documents.authority.profile;
    if (profile.managed.upstream_credentials !== "managed_upstream_v1") throw refused();
    const healthToken = roleBytes("health-token"); health(healthToken);
    const protectedBytes = [proof, healthToken];
    state.tokens.set("instance-proof", Buffer.from(proof)); state.tokens.set("health", Buffer.from(healthToken));
    for (const name of ["governance", "evidence"]) {
      const bytes = roleBytes(`${name}-token`), token = bytes.toString("utf8");
      if (bytes.length > 4098 || !/^[A-Za-z0-9._~+/-]{16,4096}={0,2}$/.test(token) || /[^A-Za-z0-9._~+/=-]/.test(token)) throw refused();
      protectedBytes.push(bytes); state.tokens.set(name, Buffer.from(bytes));
    }
    const decodedHealth = Buffer.from(healthToken.toString("ascii"), "base64url"); temporary.push(decodedHealth);
    const protectedDigests = new Set(protectedBytes.map(digest));
    if (protectedDigests.size !== 4 || protectedDigests.has(digest(decodedHealth))) throw refused();
    protectedDigests.add(digest(decodedHealth));
    state.jwks = Buffer.from(roleBytes("inbound-jwks")); // Semantics verified by the separate staged JWT factory.
    for (const [name, prefix] of [["governance", "governance"], ["evidence", "evidence"], ["ingress", "workload"]] as const) {
      const value = preflightTlsRole({ ca: roleBytes(`${prefix}-ca`), cert: roleBytes(`${prefix}-cert`), key: roleBytes(`${prefix}-key`),
        purpose: name === "ingress" ? "server" : "client",
        ...(name === "ingress" ? { serverName: profile.managed.ingress.tls_server_name } : {}) }, nowUnixUs);
      state.tls.set(name, value);
    }
    const roles = [...state.tls.values()]; assertDistinctTlsRoles(roles);
    const criticalKeys = new Set(roles.map(role => role.publicKeySha256));
    let notAfterUnixUs = roles.reduce((until, role) => role.notAfterUnixUs < until ? role.notAfterUnixUs : until, roles[0].notAfterUnixUs);
    const references = [...new Set(documents.config.spec!.upstreams.map(upstream => upstream.credentialRef))].sort();
    for (const reference of references) {
      const source = copyStageTool(stage, reference); temporary.push(source);
      const credential = parseManagedUpstreamCredential(source, nowUnixUs); state.upstreams.set(reference, credential);
      if (credential.clientPublicKeySha256 && criticalKeys.has(credential.clientPublicKeySha256)) throw refused();
      const material = upstreamCredentialMaterial(credential);
      try { if (material.token && protectedDigests.has(digest(material.token))) throw refused(); }
      finally { for (const bytes of Object.values(material)) bytes.fill(0); }
      if (credential.notAfterUnixUs < notAfterUnixUs) notAfterUnixUs = credential.notAfterUnixUs;
    }
    const tls = Object.freeze(Object.fromEntries([...state.tls].map(([name, value]) => [name,
      Object.freeze({ certificateSha256: value.certificateSha256, publicKeySha256: value.publicKeySha256 })]))) as RuntimeMaterials["tls"];
    const result = Object.freeze({ binding: documents.binding, notAfterUnixUs, upstreamReferences: Object.freeze(references), tls });
    owned.set(result, state); return result;
  } catch { dispose(state); throw refused(); }
  finally { for (const bytes of temporary) bytes.fill(0); }
}
function stateOf(owner: RuntimeMaterials): State { const state = owned.get(owner); if (!state) throw refused(); return state; }
/** Composition consistency only; never authority to perform an effect. */
export function assertRuntimeMaterialsStage(owner: RuntimeMaterials, stage: StageOwner): void {
  if (stateOf(owner).stage !== stage) throw refused();
  const proof = copyStageRole(stage, "instance-proof"); proof.fill(0);
}
export function runtimeTokenMaterial(owner: RuntimeMaterials, role: string): Buffer {
  const value = stateOf(owner).tokens.get(role); if (!value || typeof role !== "string") throw refused(); return Buffer.from(value);
}
export function runtimeJwksMaterial(owner: RuntimeMaterials): Buffer { return Buffer.from(stateOf(owner).jwks!); }
export function runtimeTlsMaterial(owner: RuntimeMaterials, role: RuntimeTlsPurpose) {
  const value = stateOf(owner).tls.get(role); if (!value || typeof role !== "string") throw refused(); return tlsRoleMaterial(value);
}
export function runtimeUpstreamMaterial(owner: RuntimeMaterials, reference: string) {
  const value = stateOf(owner).upstreams.get(reference); if (!value || typeof reference !== "string") throw refused();
  return upstreamCredentialMaterial(value);
}
export function disposeRuntimeMaterials(owner: RuntimeMaterials): void {
  const state = owned.get(owner); if (!state) return; owned.delete(owner); dispose(state);
}
function dispose(state: State): void {
  for (const role of state.tls.values()) disposeTlsRole(role); state.tls.clear();
  for (const value of state.upstreams.values()) disposeUpstreamCredential(value); state.upstreams.clear();
  for (const token of state.tokens.values()) token.fill(0); state.tokens.clear(); state.jwks?.fill(0); state.jwks = undefined;
}
