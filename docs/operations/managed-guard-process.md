# Managed guard process

`startGuardProcess({env,onFatal})` composes the actual guard-only sealed reader,
strict configuration parser and two concrete relay listeners. Its image-owned
entry is `node dist/managed/guard/main.js`. No runtime gateway entry, container
start, route publication, production launch or `Serving` transition is enabled
by adding this process. The agent still must stage, inspect and launch the
approved signed artifact with the exact protected topology.

The fixed environment is NODE_ENV=production, HOME=/tmp/apex,
APEX_MCP_PROFILE=guard, APEX_MCP_GUARD_BOOTSTRAP=sealed-stage-v1, and the five
launch metadata values APEX_INSTALLATION_ID, APEX_PROCESS_INSTANCE_ID,
APEX_STAGE_MANIFEST_SHA256, APEX_NETWORK_BINDING_SHA256,
APEX_NETWORK_TOPOLOGY_SHA256. Unknown APEX fields, case aliases, accessors,
symbols and ambient Node/TLS/proxy overrides are rejected. Maximum256 entries,
128-character keys,16384-character values and65536 aggregate key/value characters.
Other ordinary environment values are not used. This check cannot undo Node
startup injection; protected agent argv/environment inspection remains required.

The API exposes no filesystem, clock, resolver, policy or socket override. It
loads only the separate guard stage, joins configuration against the captured
launch metadata, disposes the stage bytes and binds egress on derived guard-inner
port18080 and ingress on guard-outer port8080. Egress accepts only the gateway
source and uses the compiled declared/protected intersection; ingress accepts
only the configured edge source and forwards opaque bytes to gateway8080.
The guard receives no gateway TLS keys, bearer tokens, tool credentials or
control socket. Kernel topology provenance must be established by the launcher.

`result` publishes immutable derived addresses after both actual binds and the
original startup/expiry fences pass. It is an ephemeral process-start observation,
not gateway readiness or admission permission. `revoked` reports stop immediately;
`closed` waits for actual stage-loader closure and both relay close receipts,
including accepted sockets and pending native DNS. Either relay's revocation
stops both. Stage cancellation and material-disposal attempts are each one-shot.
Unknown cleanup never produces a successful physical-close acknowledgement.

The original ten-second startup budget includes capture, reading, parsing and
binding. Wall time starts as a Date.now millisecond interval; expiry conservatively
subtracts its full1000us uncertainty and anchors the remaining budget to the
original monotonic entry. Handshakes and bounded timer wakes check monotonic and
wall expiry/regression. This is not a hard realtime/kernel timer guarantee.
Already established opaque transports close when revocation is observed; gateway
admission independently checks authority for every business call.

One strong process reservation remains held through actual cleanup. A five-second
cleanup watchdog invokes the trusted fatal callback once while retaining unknown
owners. The image-owned main handles SIGINT/SIGTERM by cancelling and draining,
uses static diagnostics, and exits70 on uncertain cleanup. No retries, background
restart, alternate credential source or automatic deployment are performed.

Focused deterministic lifecycle tests and a native relay-revocation test pass on
Windows and Linux. Actual two-network root acceptance is a separate integration
gate; component results alone do not certify its network confinement or activation.
