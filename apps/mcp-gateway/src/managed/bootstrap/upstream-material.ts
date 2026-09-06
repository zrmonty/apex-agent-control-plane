import { parseWireJson } from "../upstream-wire/json.js";
import { record } from "../call-preparation/boundary.js";
import { preflightTlsRole, tlsRoleMaterial, disposeTlsRole } from "./tls-role.js";
import { copyBytes, serverTrust, refused } from "./upstream-material/validation.js";

export type UpstreamAuthentication = "server_tls" | "bearer" | "mtls" | "mtls_bearer";
export type UpstreamMaterial = Readonly<{ authentication: UpstreamAuthentication; notAfterUnixUs: bigint;
  clientCertificateSha256?: string; clientPublicKeySha256?: string }>;
type Material = Readonly<{ serverCa: Buffer; token?: Buffer; clientCert?: Buffer; clientKey?: Buffer }>;
const owned = new WeakMap<UpstreamMaterial, Material>();

/** Pure interpretation, never provenance or permission. Only the production
 * sealed-stage owner may supply protected bytes to runtime factories. */
export function parseManagedUpstreamCredential(bytes: Uint8Array, nowUnixUs: bigint): UpstreamMaterial {
  let input: Buffer | undefined;
  const allocated: Buffer[] = [];
  try {
    input = copyBytes(bytes);
    const value = record(parseWireJson(input), ["schema_version", "authentication", "server_ca", "token", "client"]);
    if (value.schema_version !== 1 || !["server_tls", "bearer", "mtls", "mtls_bearer"].includes(value.authentication as string)) throw refused();
    const authentication = value.authentication as UpstreamAuthentication;
    const bearer = authentication === "bearer" || authentication === "mtls_bearer";
    const mutual = authentication === "mtls" || authentication === "mtls_bearer";
    if (Object.keys(value).length !== 3 + Number(bearer) + Number(mutual) ||
      Object.hasOwn(value, "token") !== bearer || Object.hasOwn(value, "client") !== mutual) throw refused();
    const utf8 = (text: unknown): Buffer => {
      if (typeof text !== "string" || text.length < 1 || Buffer.byteLength(text) > 65536) throw refused();
      const result = Buffer.from(text); allocated.push(result); return result;
    };
    const serverCa = utf8(value.server_ca);
    let notAfterUnixUs = serverTrust(serverCa, nowUnixUs);
    let token: Buffer | undefined, clientCert: Buffer | undefined, clientKey: Buffer | undefined;
    let clientCertificateSha256: string | undefined, clientPublicKeySha256: string | undefined;
    if (bearer) {
      if (typeof value.token !== "string" || value.token.length > 4098 ||
        !/^[A-Za-z0-9._~+/-]{16,4096}={0,2}$/.test(value.token) || /[^A-Za-z0-9._~+/=-]/.test(value.token)) throw refused();
      token = utf8(value.token);
    }
    if (mutual) {
      const client = record(value.client, ["ca", "cert", "key"]);
      if (Object.keys(client).length !== 3) throw refused();
      const ca = utf8(client.ca), cert = utf8(client.cert), key = utf8(client.key);
      const role = preflightTlsRole({ ca, cert, key, purpose: "client" }, nowUnixUs);
      try {
        const material = tlsRoleMaterial(role);
        material.ca.fill(0); clientCert = material.cert; clientKey = material.key;
        allocated.push(clientCert, clientKey);
        clientCertificateSha256 = role.certificateSha256; clientPublicKeySha256 = role.publicKeySha256;
        if (role.notAfterUnixUs < notAfterUnixUs) notAfterUnixUs = role.notAfterUnixUs;
      } finally { disposeTlsRole(role); ca.fill(0); cert.fill(0); key.fill(0); }
    }
    const result = Object.freeze({ authentication, notAfterUnixUs,
      ...(mutual ? { clientCertificateSha256, clientPublicKeySha256 } : {}) });
    owned.set(result, Object.freeze({ serverCa, ...(token ? { token } : {}),
      ...(mutual ? { clientCert, clientKey } : {}) }));
    return result;
  } catch { for (const buffer of allocated) buffer.fill(0); throw refused(); }
  finally { input?.fill(0); }
}

/** Copies transfer to the consumer, who must wipe them after physical closure. */
export function upstreamCredentialMaterial(value: UpstreamMaterial): Material {
  const material = owned.get(value); if (!material) throw refused();
  return Object.freeze({ serverCa: copyBytes(material.serverCa),
    ...(material.token ? { token: copyBytes(material.token) } : {}),
    ...(material.clientCert ? { clientCert: copyBytes(material.clientCert), clientKey: copyBytes(material.clientKey!) } : {}) });
}
export function disposeUpstreamCredential(value: UpstreamMaterial): void {
  const material = owned.get(value); if (!material) return;
  owned.delete(value); for (const buffer of Object.values(material)) buffer.fill(0);
}
