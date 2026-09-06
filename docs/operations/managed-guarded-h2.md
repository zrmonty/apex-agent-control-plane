# Guarded authority and evidence HTTP/2 connections

`startGuardedH2Connection` connects one explicit mTLS/h2 destination through the
actual guarded TLS connector, then creates a native HTTP/2 session on that same
verified socket. The HTTP/2 authority comes from the same captured original
host/port. There is no second DNS connection, ambient proxy, alternate socket
factory, retry, bearer-token input or endpoint selected by a request.

The public handle separates `result`, `closed` and `cancel()`. Result is available
only after TLS authentication, native HTTP/2 connect, first peer settings, and
acknowledgement of the initial local settings disabling push. All of that uses the
original caller monotonic startup timestamp and ten-second budget. It does not
reset the budget after TLS. Destination metadata and connector credential copies
are captured before asynchronous work.

Two process-global slots cover the governance and evidence connections. Slots
are reserved before trusted callbacks and released only after actual HTTP/2 and
TLS connector closure and result processing. Cancellation, GOAWAY, connection
failure or an expired deadline revoke the connection; they do not manufacture
physical closure. Pushed streams are rejected and retained until their close
events. Header tables/lists, native session memory and stream-related limits are
bounded. The five-second cleanup watchdog calls the trusted fatal handler once;
uncertain closure still holds capacity until cleanup is actually observed.

The production root supplies protected, prevalidated material and separately
constructs the typed `OwnedAuthorityChannel` or `OwnedEvidenceChannel`. It must
close those channel/application owners too: transport closure does not prove
remote reservation release or application-result processing. The root must also
supervise credential expiry, grants and readiness. Returning from `onFatal` is
not proof of process termination.

Tests connect real guard/CONNECT/TLS/HTTP2 paths to the real typed unary channels,
using public test-only credentials and loopback routing policy. They cover
original-name/CA/pin refusal, missing client material, deadline boundaries,
captured buffers, cancellation, capacity/reentry, peer shutdown and GOAWAY. A
test-only delayed close acknowledgement checks watchdog/retained capacity after
actual native closure. Neither these tests nor this factory establish protected
stage provenance, real network isolation, EventIngest durability, Serving or
production-root activation.
