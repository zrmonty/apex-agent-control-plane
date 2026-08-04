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

    user = (SECRETS / "nats-username").read_text(encoding="utf-8").strip()
    nats_password = (SECRETS / "nats-password").read_text(encoding="utf-8").strip()
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
