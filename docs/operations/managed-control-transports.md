# Managed control transport pair

`startManagedControlTransports` composes the actual guarded HTTP/2 connections
and narrow governance/evidence channels from one live sealed-stage-v2 owner and
runtime materials created from that exact stage. Equal metadata is not sufficient
to substitute another stage. The gateway entry point remains gated; this component
is not a serving runtime, readiness check or deployment grant.

The immutable stage chooses the numeric guard address and fixed port18080. Its
joined authority profile chooses each original HTTPS hostname and port. The pair
uses distinct staged client TLS roles and tokens. Governance alone receives the
instance proof; EventIngest does not. No ambient proxy, resolver, reconnect, caller
endpoint, socket/session injection or secret-distribution interface is exposed.

Both native H2 handshakes share one original ten-second monotonic budget. The
pair retains material expiry independently of temporary credential disposal,
using a conservative millisecond wall-clock interval and monotonic duration.
Expiry, regression, peer loss or cancellation revokes both channels. Callers must
observe `revoked`; successful connection establishment never enables admission.

The caller retains its stage and runtime materials. The pair owns independent
copies, two connections and any constructed channels. `cancel` is logical stop;
`closed` requires every exact connection and channel cleanup receipt. A late
constructor return is adopted even after cancellation. Unknown/rejected cleanup
retains the process-level slot and triggers the once-only fatal callback after
the bounded cleanup grace; callbacks are not physical-close evidence. The parent
process must provide its actual fatal-exit policy when integrating this component.

Local stream/socket closure does not prove a remote transaction completed or
release a durable business-call reservation. The typed deployment/business/
evidence clients and call owner maintain those separate protocols. Full runtime
startup, HTTPS sessions, upstream integration, health, routing, lifecycle and
end-to-end trace projection are still independent integration gates.

Native tests use synthetic stage-loader material and actual TLS/H2/guard channels
inside a disposable network namespace. They assert original server names,
distinct peer certificates, token/proof separation, cancellation, restart and peer
loss. They are not protected FD-stage, signed-image, cross-proxy kernel isolation,
production enrollment or durable EventIngest acceptance tests.
