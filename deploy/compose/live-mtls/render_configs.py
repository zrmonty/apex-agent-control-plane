#!/usr/bin/env python3
"""Render Valkey/NATS configs against the live-mTLS secrets directory."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parent
SECRETS = ROOT / "secrets"
TEMPLATES = ROOT.parent / "templates"


def main() -> None:
    SECRETS.mkdir(parents=True, exist_ok=True)
    conf = (TEMPLATES / "valkey.conf.template").read_text(encoding="utf-8")
    (SECRETS / "valkey.conf").write_text(conf, encoding="utf-8")

    password = (SECRETS / "valkey-ingest-password").read_text(encoding="utf-8").strip()
    # Valkey ACL parser rejects comment lines; keep only user directives.
    acl = (
        "user default off\n"
        f"user apex-ingest on sanitize-payload >{password} "
        "~apex:ingest:* resetchannels -@all +ping +incr +incrby +get +set +setex +expire +ttl +exists\n"
    )
    (SECRETS / "valkey.acl").write_text(acl, encoding="utf-8")

    # The OOB control gateway's own Valkey ACL, for its own Valkey instance
    # (compose.control-valkey.yaml). A separate user with a separate password
    # and a key pattern narrowed to this service's admission namespace.
    #
    # The pattern is computed, not written by hand, from the same namespace
    # constant the Rust side uses (`service.rs::CONTROL_ADMISSION_NAMESPACE`)
    # and the same encoding `event-ingest`'s `ephemeral::types` applies:
    # `apex:ingest:rl:<hex(namespace)>:<hex(bucket)>`, where the `apex:ingest`
    # prefix is a fixed literal in that crate and the namespace component is
    # what separates the two services. Deriving it here means the ACL cannot
    # silently drift from the key the gateway actually writes -- and a drift
    # would not fail loudly, it would make every check_rate_limit call error
    # and the shared ceiling quietly stop applying.
    control_namespace = "apex.control.admission"
    control_prefix = "apex:ingest:rl:" + control_namespace.encode("ascii").hex()
    control_password = (
        (SECRETS / "valkey-control-password").read_text(encoding="utf-8").strip()
    )
    control_acl = (
        "user default off\n"
        f"user apex-control on sanitize-payload >{control_password} "
        f"~{control_prefix}:* resetchannels -@all "
        "+ping +incr +incrby +get +set +setex +expire +ttl +exists\n"
    )
    (SECRETS / "control-valkey.acl").write_text(control_acl, encoding="utf-8")

    user = (SECRETS / "nats-username").read_text(encoding="utf-8").strip()
    nats_password = (SECRETS / "nats-password").read_text(encoding="utf-8").strip()
    control_user = (SECRETS / "control-nats-username").read_text(encoding="utf-8").strip()
    control_password = (
        (SECRETS / "control-nats-password").read_text(encoding="utf-8").strip()
    )
    # Two broker principals, not one shared credential. Per ADR-0006 the OOB
    # control gateway is a separate trust boundary from the ingest data path,
    # and that has to be true at the broker too -- otherwise "independently
    # authenticated" stops at the gRPC edge and both services hold the same
    # publish rights the moment either is compromised.
    #
    # The control principal is deliberately the narrower of the two: it
    # publishes control events into the same `apex.events.>` stream, but it is
    # granted no `$JS.API.>` because it never creates or manages a stream --
    # `jetstream-init` does that with the ingest credential. Its subscribe
    # grant is only `_INBOX.>`, which is what a JetStream publish ack is
    # delivered on.
    nats = f"""# Generated for live-mTLS only. Do not use in production.
port: 4222
jetstream {{
  store_dir: "/data"
}}
authorization {{
  users: [
    {{
      user: "{user}"
      password: "{nats_password}"
      permissions: {{
        publish: ["apex.events.>", "$JS.API.>"]
        subscribe: ["_INBOX.>", "$JS.ACK.>", "$JS.FC.>"]
      }}
    }},
    {{
      user: "{control_user}"
      password: "{control_password}"
      permissions: {{
        publish: ["apex.events.>"]
        subscribe: ["_INBOX.>"]
      }}
    }}
  ]
}}
tls {{
  cert_file: "/run/secrets/nats_server_cert"
  key_file: "/run/secrets/nats_server_key"
  ca_file: "/run/secrets/nats_client_ca"
  verify: true
  # Must match async-nats ConnectOptions::tls_first() used by the gateway client.
  handshake_first: true
}}
"""
    (SECRETS / "nats.conf").write_text(nats, encoding="utf-8")
    print(f"Rendered Valkey/NATS configs under {SECRETS}")


if __name__ == "__main__":
    main()
