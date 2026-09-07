# Protected paired gateway staging

The managed network branch stages the gateway after verifying and sealing its paired guard. Both complete and recovered stages remain **NotServing**, with `RUNTIME_NETWORK_ENFORCEMENT_UNAVAILABLE`. This slice does not pull images, create or start containers, register an instance, activate readiness, routes, admission or tracing, or clean up a paired deployment. Apex remains the only policy and durable evidence authority.

## Required contract

Use an explicit schema3 `managed_ingress` authority profile and the original published runtime revision, launch, authority and tool-binding documents. Schema1/2 profiles are not implicitly upgraded. The stage contains exactly:

- `runtime-revision.json`, `launch-context.json`, `authority-profile.json`, `tool-bindings.json`;
- one 32-byte `instance-proof`;
- the 13 fixed role files: `health-token`, `governance-ca`, `governance-cert`, `governance-key`, `governance-token`, `evidence-ca`, `evidence-cert`, `evidence-key`, `evidence-token`, `inbound-jwks`, `workload-ca`, `workload-cert`, `workload-key`;
- one `tool-<sha256(reference)>` file per exact configured secret reference.

The health token is exactly 43 canonical base64url characters. Each credential/tool file is at most 65536 bytes, with at most 32 tool files and at most 4MiB in the complete stage. Files use UID/GID10001 and mode0400; the sealed directory uses UID/GID10001 and mode0500. Source and stage hierarchies must remain protected for their lifetime. Files must be single-link regular files, opened without following links, on their expected mount. The original protected root, directory and file identities are checked across recovery. Non-Linux hosts refuse staging effects.

The production caller verifies actual guard and gateway image signatures against current protected digest/signer selections on creation and recovery. It rechecks current operation, metadata, policy validity, cancellation, shutdown and job/lease deadlines around slow work and storage effects. A recorded historical signature selection or seal is not an effect permit.

## Durable phases and recovery

`Installed.gateway_stage` is optional. Its absence preserves legacy journal serialization/checksums and the dormant no-network flow. Adding paired staging does not change network owner identity or the original installed revision, launch or publication when current command/fence changes.

| Gateway phase | Durable meaning | Same-instance retry |
| --- | --- | --- |
| `ProofIntent` | One proof generation attempt may have occurred | Quarantine untouched; never generate another proof |
| `StageIntent` | Original file hashes and source identity recorded; directory/file writes may be partial | Quarantine untouched; no mkdir, repair or regeneration |
| `SealIntent` | Original directory and every file identity recorded before permission sealing | Adopt only a complete already-sealed, exact stage; verify all bytes/identities and fsync before recording `Sealed` |
| `Sealed` | Complete verified stage and sealed filesystem identities recorded | Revalidate current signatures, policy, pairing, source identity, inventory, bytes, mounts and original identities; remain NotServing |

A crash after all writes but before permission sealing cannot authorize finishing the seal on retry. A crash after sealing but before final journal commit can recover only the original complete stage. File or source rotation, byte-identical replacement, unexpected mounts, extra/missing files, changed owner/mode, hardlinks, symlinks and protected-root substitution cause refusal. A final source/file identity check follows potentially slow authority callbacks before the journal seal is committed.

Recovery evidence covers service-process restart with the original mounts and
source hierarchy retained. It does not establish host reboot/remount or agent-container
recreation. Changed mount identity refuses recovery; do not relax that check to adopt
an old stage.

## Quarantine handling

`RUNTIME_GATEWAY_STAGE_QUARANTINED` requires operator investigation. Preserve the paired journal, source and staging hierarchies. Do not delete the journal, clear the gateway phase, edit hashes, copy a proof between instances, replace a missing stage, or relax permissions/signing policy to force a retry. This slice supplies no automatic repair, broad deletion or retirement cleanup. A subsequent recovery/redeployment workflow must explicitly handle the quarantined instance under current Apex authority.

Inspect only nonsecret metadata and hash/identity inventory. Never collect credential or proof bytes into diagnostic JSON, shell arguments, environment variables, logs, tickets or reports. Credential/proof buffers in the agent are owned zeroizing memory, and durable records contain their hashes rather than raw material.

## Evidence boundary

Real Linux storage tests establish protected assembly, durable interruption behavior, identity/mount checks and no-repair refusal. A controlled currentness callback establishes the storage gate, not the real authority transport. Existing authority/worker tests separately exercise mTLS, deadlines, cancellation and capacity ownership. Positive production signature and full native paired-network composition remain separate acceptance requirements; storage success does not establish that an approved signed gateway/guard fixture has verified or that a proxy can serve.
