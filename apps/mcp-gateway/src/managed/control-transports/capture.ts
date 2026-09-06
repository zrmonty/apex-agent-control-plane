import type { StageOwner } from "../bootstrap/stage-owner.js";
import { assertRuntimeMaterialsStage, runtimeTlsMaterial, runtimeTokenMaterial, type RuntimeMaterials } from "../bootstrap/runtime-materials.js";
import type { GuardedTlsDestination } from "../guard/tls-connector.js";
export const refused = () => new Error("managed control transports refused safely");
/** Internal immutable derivation. Copies are caller-owned; no I/O or authority. */
export function capture(stage: StageOwner, materials: RuntimeMaterials) {
    const bytes: Buffer[] = [];
    try {
        assertRuntimeMaterialsStage(materials, stage);
        const network = stage.network, profile = stage.documents.authority.profile;
        if (!network || network.profile !== "isolated-bridge-v1" || network.guardPort !== 18080 ||
            materials.binding !== stage.documents.binding)
            throw refused();
        const purposes = ["governance", "evidence"] as const;
        const destinations = purposes.map(purpose => {
            const endpoint = profile[purpose], url = new URL(endpoint.endpoint);
            if (url.protocol !== "https:" || url.hostname !== endpoint.tls_server_name || url.username || url.password ||
                url.search || url.hash || url.pathname !== "/")
                throw refused();
            const tls = runtimeTlsMaterial(materials, purpose);
            bytes.push(tls.ca, tls.cert, tls.key);
            return Object.freeze({ id: purpose, host: url.hostname, port: url.port ? Number(url.port) : 443,
                authentication: "mutual_tls", alpn: "h2", ...tls }) satisfies GuardedTlsDestination;
        });
        const token = (role: string) => { const value = runtimeTokenMaterial(materials, role); bytes.push(value); return value; };
        return Object.freeze({ guard: Object.freeze({ address: network.guardAddress, port: network.guardPort }),
            destinations: Object.freeze(destinations), governanceToken: token("governance"), evidenceToken: token("evidence"),
            proof: token("instance-proof"), notAfterUnixUs: materials.notAfterUnixUs,
            dispose() { for (const value of bytes)
                value.fill(0); } });
    }
    catch {
        for (const value of bytes)
            value.fill(0);
        throw refused();
    }
}
export type Captured = ReturnType<typeof capture>;
