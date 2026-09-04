//! Builds the mTLS server identity and the three operator/agent/revocation
//! credential resolvers, each from its own trusted-secret material.

use std::io;
use std::path::Path;

use apex_control_plane_api::{
    AgentRevocationList, BoxedAgentWorkloadResolver, BoxedOperatorCredentialResolver,
    GatewayTokenAuthenticator, GovernanceConfig, GovernanceGatewayService, KeycloakConfig,
    KeycloakOperatorCredentialResolver, MAX_AGENT_REVOCATION_FILE_BYTES,
    RevocationAwareAgentResolver, StaticAgentWorkloadResolver, parse_agent_token_table,
    parse_operator_token_table,
};
use tonic::transport::{Certificate, Identity, ServerTlsConfig};

use super::super::env::{
    AgentTokenSource, OperatorTokenSource, agent_revocation_env, agent_token_source, keycloak_env,
    operator_token_source, optional, path,
};
use super::super::secrets::{read_bounded, read_credential_table, trusted_secret_path};

/// PEM material ceiling, matching `event-ingest`'s own 1 MiB bound on the
/// same three files.
const MAX_TLS_MATERIAL_BYTES: usize = 1024 * 1024;
/// The credential table is `token|scopes;...` with up to 256 entries of up to
/// 4096 token bytes (`auth::MAX_OPERATOR_TOKEN_ENTRIES` /
/// `MAX_OPERATOR_TOKEN_BYTES`), so 64 KiB is generous headroom while still
/// bounding what a mounted file can make this process allocate.
const MAX_OPERATOR_TABLE_BYTES: usize = 64 * 1024;

/// Builds the live MCP governance service when its dedicated service token is
/// configured. The operator and agent tables are intentionally not accepted
/// as a fallback: a credential-space crossover would turn a protocol adapter
/// into an operator or workload authority.
pub(super) fn build_governance_service(
    trusted_base: &Path,
) -> Result<GovernanceGatewayService, Box<dyn std::error::Error>> {
    let token_path = trusted_secret_path(
        &path("APEX_CONTROL_MCP_GATEWAY_TOKEN_FILE")?,
        trusted_base,
        4096,
        true,
        "APEX_CONTROL_MCP_GATEWAY_TOKEN_FILE",
    )?;
    let token = read_credential_table(&token_path, 4096, "APEX_CONTROL_MCP_GATEWAY_TOKEN_FILE")?;
    let auth = GatewayTokenAuthenticator::new(token.trim())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid MCP gateway token"))?;
    let portfolios = csv_values(
        optional("APEX_CONTROL_MCP_ALLOWED_PORTFOLIOS").as_deref(),
        "northstar-401k",
    );
    let scopes = csv_values(
        optional("APEX_CONTROL_MCP_ALLOWED_SCOPES").as_deref(),
        "acme/prod",
    );
    let config = GovernanceConfig::new(
        portfolios,
        scopes,
        "apex-mcp-read-v1",
        1,
        [
            "client.account_number",
            "client.tax_id",
            "positions.cost_basis",
        ],
    )?;
    Ok(GovernanceGatewayService::new(config, auth))
}

fn csv_values(raw: Option<&str>, default: &str) -> Vec<String> {
    raw.unwrap_or(default)
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

/// Loads the mTLS server identity and the CA that operator client
/// certificates must chain to.
///
/// **TLS is mandatory.** All three paths are `required()`, so a missing one
/// aborts startup instead of silently degrading to plaintext. This matches
/// `event-ingest` exactly: that binary has no "lab mode" TLS bypass either --
/// `APEX_GATEWAY_SERVER_CERT_FILE`/`_KEY_FILE`/`_CLIENT_CA_FILE` are all
/// `path()` (i.e. required) and its `client_auth_optional(false)` is
/// explicit. Local and CI use is served by the real PKI in
/// `deploy/compose/live-mtls/`, not by an unencrypted fallback, so adding one
/// here would invent a weaker mode that does not exist anywhere else in this
/// repository.
pub(super) fn load_server_tls(trusted_base: &Path) -> Result<ServerTlsConfig, io::Error> {
    let server_cert_path = trusted_secret_path(
        &path("APEX_CONTROL_SERVER_CERT_FILE")?,
        trusted_base,
        MAX_TLS_MATERIAL_BYTES as u64,
        false,
        "APEX_CONTROL_SERVER_CERT_FILE",
    )?;
    let server_key_path = trusted_secret_path(
        &path("APEX_CONTROL_SERVER_KEY_FILE")?,
        trusted_base,
        MAX_TLS_MATERIAL_BYTES as u64,
        true,
        "APEX_CONTROL_SERVER_KEY_FILE",
    )?;
    let client_ca_path = trusted_secret_path(
        &path("APEX_CONTROL_CLIENT_CA_FILE")?,
        trusted_base,
        MAX_TLS_MATERIAL_BYTES as u64,
        false,
        "APEX_CONTROL_CLIENT_CA_FILE",
    )?;
    let server_cert = read_bounded(
        &server_cert_path,
        MAX_TLS_MATERIAL_BYTES,
        "APEX_CONTROL_SERVER_CERT_FILE",
    )?;
    let server_key = read_bounded(
        &server_key_path,
        MAX_TLS_MATERIAL_BYTES,
        "APEX_CONTROL_SERVER_KEY_FILE",
    )?;
    let client_ca = read_bounded(
        &client_ca_path,
        MAX_TLS_MATERIAL_BYTES,
        "APEX_CONTROL_CLIENT_CA_FILE",
    )?;
    Ok(ServerTlsConfig::new()
        .identity(Identity::from_pem(server_cert, server_key))
        .client_ca_root(Certificate::from_pem(client_ca))
        // Explicit, for the same reason `event-ingest` states it explicitly:
        // a tonic upgrade must not be able to make operator client
        // certificates optional at the gRPC boundary by changing a default.
        .client_auth_optional(false))
}

/// PEM ceiling for the Keycloak JWKS CA, matching the mTLS material bound.
const MAX_KEYCLOAK_CA_BYTES: usize = 1024 * 1024;

/// Selects the operator credential verifier.
///
/// Three paths, chosen by explicit configuration and never inferred from one
/// another (see `startup::env::operator_token_source_value`):
///
/// - **Keycloak** (`APEX_CONTROL_KEYCLOAK_ISSUER`) -- the production path.
///   Verifies short-lived, scope-bound credentials Keycloak issued through
///   RFC 8693 token exchange. This process is a resource server: it holds no
///   client secret, performs no exchange, and only checks signatures and
///   claims.
/// - **File** (`APEX_CONTROL_OPERATOR_TOKENS_FILE`) and **inline**
///   (`APEX_CONTROL_OPERATOR_TOKENS`) -- the static table, unchanged, still
///   the local/lab and CI seam.
///
/// The return type is erased because the three implementations are different
/// types; `ControlGatewayService` stays generic so in-process tests keep
/// monomorphising over the resolver they actually construct.
pub(super) fn build_operator_resolver(
    trusted_base: &Path,
) -> Result<BoxedOperatorCredentialResolver, Box<dyn std::error::Error>> {
    let raw = match operator_token_source()? {
        OperatorTokenSource::Keycloak(issuer) => {
            let settings = keycloak_env(issuer)?;
            let ca_path = trusted_secret_path(
                &settings.ca_file,
                trusted_base,
                MAX_KEYCLOAK_CA_BYTES as u64,
                // A CA certificate is public material, so it is not held to
                // the private-key permission policy -- the same call the
                // NATS/mTLS client CAs get.
                false,
                "APEX_CONTROL_KEYCLOAK_CA_FILE",
            )?;
            let jwks_ca_pem = read_bounded(
                &ca_path,
                MAX_KEYCLOAK_CA_BYTES,
                "APEX_CONTROL_KEYCLOAK_CA_FILE",
            )?;
            let config = KeycloakConfig {
                issuer: settings.issuer,
                audience: settings.audience,
                jwks_url: settings.jwks_url,
                jwks_ca_pem,
                jwks_refresh: settings.jwks_refresh,
                jwks_max_age: settings.jwks_max_age,
                scope_claim: settings.scope_claim,
                role_claim: settings.role_claim,
                global_role: settings.global_role,
                global_subjects: settings.global_subjects,
                max_token_lifetime: settings.max_token_lifetime,
                expected_typ: settings.expected_typ,
            };
            let break_glass = if config.global_role.is_some() {
                config.global_subjects.len()
            } else {
                0
            };
            // Constructed here, before the serving runtime exists: the JWKS
            // client is `reqwest::blocking` and owns an internal runtime, so
            // building it on a runtime thread panics -- the same hazard that
            // made `run()` synchronous for `PostgresOutbox`.
            let resolver = KeycloakOperatorCredentialResolver::start(config)?;
            println!(
                "apex-control-plane-api operator credentials: keycloak (break-glass subjects allow-listed: {break_glass})"
            );
            return Ok(Box::new(resolver));
        }
        OperatorTokenSource::File(configured) => {
            let table_path = trusted_secret_path(
                &configured,
                trusted_base,
                MAX_OPERATOR_TABLE_BYTES as u64,
                // Bearer credentials, not just a config file: held to the
                // same owner-only permission policy as a private key.
                true,
                "APEX_CONTROL_OPERATOR_TOKENS_FILE",
            )?;
            read_credential_table(
                &table_path,
                MAX_OPERATOR_TABLE_BYTES,
                "APEX_CONTROL_OPERATOR_TOKENS_FILE",
            )?
        }
        OperatorTokenSource::Inline(raw) => raw,
        OperatorTokenSource::Unset => {
            // Fail-closed, not fail-open: an empty resolver authenticates
            // nobody. Loud on stderr because a control gateway that accepts
            // no operator at all is almost never what was intended.
            eprintln!(
                "control-plane-api: none of APEX_CONTROL_KEYCLOAK_ISSUER, APEX_CONTROL_OPERATOR_TOKENS_FILE or APEX_CONTROL_OPERATOR_TOKENS is set; no operator credential will authenticate"
            );
            return Ok(Box::new(
                apex_control_plane_api::StaticOperatorTokenResolver::new(),
            ));
        }
    };
    // A malformed credential table is a configuration failure, not something
    // to log past. Skipping a bad entry would leave the gateway running with
    // an operator silently unable to act -- or, worse, acting under a
    // mis-parsed scope.
    let resolver = parse_operator_token_table(&raw)?;
    println!("apex-control-plane-api operator credentials: static table");
    Ok(Box::new(resolver))
}

/// The agent workload credential table is the same shape and the same size
/// class as the operator one: `token|cert_sha256|agent_id|scopes`, up to 1024
/// entries.
const MAX_AGENT_TABLE_BYTES: usize = 256 * 1024;

/// Selects the **agent workload** credential verifier for `PollCommands`.
///
/// Deliberately its own function, its own variables, and its own fail-closed
/// default, rather than a branch inside `build_operator_resolver`. Sharing that
/// function would be the first step toward sharing the credential space, which
/// is the boundary ADR-0006 draws between issuing a command and receiving one.
///
/// Unset is a *supported* configuration: a deployment that has not yet issued
/// agent workload credentials still runs a perfectly good command gateway, it
/// simply has no agent that can retrieve them. It is announced loudly on
/// stderr, because a control channel where nothing can receive a `stop` is the
/// exact situation this work item exists to make visible rather than silent.
///
/// Wraps the resolved table in [`RevocationAwareAgentResolver`] whenever
/// `APEX_CONTROL_AGENT_REVOCATION_FILE` is configured (see
/// [`build_agent_revocation_list`]); when it is unset, the returned resolver
/// is exactly the unwrapped table, so every deployment that predates this
/// feature is unaffected.
pub(super) fn build_agent_resolver(
    trusted_base: &Path,
) -> Result<BoxedAgentWorkloadResolver, Box<dyn std::error::Error>> {
    let raw = match agent_token_source()? {
        AgentTokenSource::File(configured) => {
            let table_path = trusted_secret_path(
                &configured,
                trusted_base,
                MAX_AGENT_TABLE_BYTES as u64,
                // Bearer credentials, held to the same owner-only permission
                // policy as a private key and as the operator table.
                true,
                "APEX_CONTROL_AGENT_TOKENS_FILE",
            )?;
            Some(read_credential_table(
                &table_path,
                MAX_AGENT_TABLE_BYTES,
                "APEX_CONTROL_AGENT_TOKENS_FILE",
            )?)
        }
        AgentTokenSource::Inline(raw) => Some(raw),
        AgentTokenSource::Unset => {
            eprintln!(
                "control-plane-api: neither APEX_CONTROL_AGENT_TOKENS_FILE nor APEX_CONTROL_AGENT_TOKENS is set; no agent will be able to retrieve commands through PollCommands"
            );
            println!("apex-control-plane-api agent credentials: none configured");
            None
        }
    };
    let resolver = match raw {
        Some(raw) => {
            let resolver = parse_agent_token_table(&raw)?;
            println!("apex-control-plane-api agent credentials: static table");
            resolver
        }
        None => StaticAgentWorkloadResolver::new(),
    };
    match build_agent_revocation_list(trusted_base)? {
        Some(revocations) => Ok(BoxedAgentWorkloadResolver::new(
            RevocationAwareAgentResolver::new(resolver, revocations),
        )),
        None => Ok(BoxedAgentWorkloadResolver::new(resolver)),
    }
}

/// Selects and starts the agent-credential **revocation list**
/// (`APEX_CONTROL_AGENT_REVOCATION_FILE`), or `None` when it is unset.
///
/// The path goes through the same `trusted_secret_path` confinement every
/// other configured secret path in this crate does, so a tampered env var
/// cannot point this process at an arbitrary host file, with one difference
/// from the credential tables: `private` is `false`, because a certificate
/// fingerprint is public material derived from a certificate, not a secret --
/// the same call already made for the Keycloak JWKS CA file.
///
/// `trusted_secret_path` also refuses a zero-byte file. That is deliberate
/// here too, not just inherited: a zero-byte file at a configured path is
/// indistinguishable from a secret mount that was never actually populated,
/// and this feature must not silently no-op in that case. An operator who
/// wants "armed, nothing currently revoked" writes a file containing a single
/// blank line -- see `agent_auth::revocation::parse_revocation_list`'s doc.
///
/// `AgentRevocationList::start` performs the actual first read and is what
/// enforces "a configured-but-unreadable path fails startup loudly": unlike
/// the Keycloak JWKS fetch, there is no acceptable "warn and keep going" here,
/// because the file is local operator configuration, not an external network
/// dependency ADR-0006 requires this gateway to tolerate being briefly
/// unreachable.
fn build_agent_revocation_list(
    trusted_base: &Path,
) -> Result<Option<AgentRevocationList>, Box<dyn std::error::Error>> {
    let Some(settings) = agent_revocation_env()? else {
        println!("apex-control-plane-api agent revocation: none configured");
        return Ok(None);
    };
    let revocation_path = trusted_secret_path(
        &settings.file,
        trusted_base,
        MAX_AGENT_REVOCATION_FILE_BYTES as u64,
        false,
        "APEX_CONTROL_AGENT_REVOCATION_FILE",
    )?;
    let list = AgentRevocationList::start(revocation_path, settings.refresh, settings.max_age)?;
    println!(
        "apex-control-plane-api agent revocation: file (refresh {}s, max age {}s)",
        settings.refresh.as_secs(),
        settings.max_age.as_secs()
    );
    Ok(Some(list))
}
