# Managed guard staging

Task4W seals the guard configuration on the managed network branch. Task4X then
adds [protected paired gateway staging](managed-gateway-staging.md). The branch
remains NotServing and returns `RUNTIME_NETWORK_ENFORCEMENT_UNAVAILABLE` after
successful staging. Neither seal permits image pull, container creation/start,
routing, readiness, or admission.

Before guard intent, the runtime owner reconstructs the actual guard producer
output from the original publication/configuration/tool bindings and the observed
topology. It selects the guard's exact digest-pinned image and signing identity
from current protected metadata and runs the real SignatureVerifier. Recovery
also requires signature verification and current authority. A historical signature
binding, checksum, or Observed/Sealed state grants no permission.

The bounded physical worker retains ownership through authority callbacks,
signature verification, native empty-network reinspection, and synchronous
filesystem/journal IO. Current operation, cancellation, shutdown, metadata
identity, policy intervals, and the monotonic job/lease deadline are checked around
guard storage effects. No detached filesystem work is introduced.

## Durable intent and confinement

The optional `Installed.guard_stage` object freezes the exact UTF-8 configuration,
producer file hashes and manifest, environment, image/signing binding, and original
topology. It is omitted for legacy records so their checksums and dormant behavior
remain compatible. It is excluded from the network owner hash. The enclosing
network Installed record remains Intent, with empty gateway file/image/container
fields. Journal load checks bounds, strict object shapes, hashes, and binding joins;
historical configuration validation is not current authorization.

The staging owner uses only `apex-guard-<canonical UUIDv7>/guard-config.json`
relative to its protected root descriptor. Environment strings never become
filesystem inputs. It reads no workload secrets at this boundary. Linux sealing
requires UID/GID 10001, directory mode 0500, a single-link regular file with mode
0400, exact inventory and content, and the same mount as the staging root.
Creation is exclusive; file, directory, and parent are fsynced. Bounded reads and
before/after descriptor/path identity checks detect substitution. Non-Linux
execution remains unsupported.

Recovery coverage is a service-process restart in the same mount namespace with
the original mounts retained. It is not proof of recovery across host reboot,
agent-container recreation, or remount. The intent deliberately retains the
observed mount ID in addition to device/inode identity; a changed ID refuses
recovery and requires quarantine/a fresh instance under the current lifecycle
design. Mountinfo describes mounts visible in a process's mount namespace;
IDs can be reused after unmount, so
the recorded number alone establishes no historical mount provenance. Protected
root ownership, no-follow traversal, device/inode binding, and current same-mount
checks remain independently required. See [mountinfo](https://man7.org/linux/man-pages/man5/proc_pid_mountinfo.5.html)
and [statx](https://www.man7.org/linux/man-pages/man2/statx.2.html).

The durable intent binds the original staging-root device/inode/mount identity
before mkdir/write. Both phases enforce that identity after restart. After an interruption, an existing
intent may only verify a complete sealed directory, then sync its file, directory,
and parent before recording Sealed. Missing or partial state,
extra files, content/permission/owner/link/mount/identity mismatch, or uncertainty
refuses recovery. It never creates replacement files under that instance. A
completed record additionally binds the sealed file and directory identities.
Quarantine remains untouched on failure and on Drop. Managed network cleanup
continues to refuse; there is no automatic guard quarantine deletion.

## Policy changes and evidence limits

Every write/recovery compares newly produced data with the frozen record. A route,
image, signer, topology, interval, or environment change requires a fresh instance.
In particular, changing a catalog validity interval cannot rewrite or silently
renew the original guard bytes under the same instance. Renewal needs a separate
design; operators must retain the old quarantine pending that lifecycle design.

Protected Linux filesystem/journal tests directly compose the real producer,
Journal, and StagingOwner. They demonstrate storage properties, not positive
production admission. The native refusal regression uses the actual production
binary, mTLS callbacks, Docker network inspection, and real Cosign in a runner
without registry network access. It must refuse before guard intent/files.
Positive native production guard staging requires an actually verified fixture
image and is not established by those storage tests.
