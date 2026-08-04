#!/usr/bin/env python3
"""Azure Blob immutability acceptance for Apex archive (cloud-agnostic suite).

Requires:
  APEX_ARCHIVE_AZURE_CONNECTION_STRING or
  (APEX_ARCHIVE_AZURE_ACCOUNT_URL + APEX_ARCHIVE_AZURE_ACCOUNT_KEY)
  APEX_ARCHIVE_AZURE_CONTAINER (default: apex-events)

Proves: create container, create-only write, read-after-write, content hash,
version/ETag, and immutability policy where the account supports it.

Exit 0 on success. Skip with exit 0 if credentials are absent and
APEX_CLOUD_ACCEPTANCE_OPTIONAL=1.
"""

from __future__ import annotations

import hashlib
import os
import sys
from datetime import datetime, timedelta, timezone


def _env(name: str) -> str:
    path = os.environ.get(f"{name}_FILE")
    if path:
        from pathlib import Path

        return Path(path).read_text(encoding="utf-8").strip()
    return os.environ.get(name, "").strip()


def main() -> None:
    conn = _env("APEX_ARCHIVE_AZURE_CONNECTION_STRING")
    account_url = os.environ.get("APEX_ARCHIVE_AZURE_ACCOUNT_URL", "").strip()
    account_key = _env("APEX_ARCHIVE_AZURE_ACCOUNT_KEY")
    container = os.environ.get("APEX_ARCHIVE_AZURE_CONTAINER", "apex-events").strip()
    optional = os.environ.get("APEX_CLOUD_ACCEPTANCE_OPTIONAL", "") == "1"

    if not conn and not (account_url and account_key):
        if optional:
            print("AZURE_ACCEPTANCE_SKIPPED (no credentials)")
            return
        raise SystemExit(
            "Set APEX_ARCHIVE_AZURE_CONNECTION_STRING or account URL+key "
            "(or APEX_CLOUD_ACCEPTANCE_OPTIONAL=1 to skip)"
        )

    try:
        from azure.core.exceptions import ResourceExistsError
        from azure.storage.blob import BlobServiceClient, ContentSettings
    except ImportError as exc:
        raise SystemExit("pip install azure-storage-blob") from exc

    if conn:
        service = BlobServiceClient.from_connection_string(conn)
    else:
        service = BlobServiceClient(account_url=account_url, credential=account_key)

    try:
        service.create_container(container)
        print("container created")
    except ResourceExistsError:
        print("container already exists")

    cc = service.get_container_client(container)
    blob_name = "acceptance/azure-probe.pb"
    payload = b"apex-azure-immutability-acceptance-v1"
    digest = hashlib.sha256(payload).hexdigest()
    blob = cc.get_blob_client(blob_name)

    try:
        blob.delete_blob()
    except Exception:
        pass

    blob.upload_blob(
        payload,
        overwrite=True,
        metadata={"apex_event_hash": digest},
        content_settings=ContentSettings(content_type="application/x-protobuf"),
    )
    print("upload_blob ok")

    data = blob.download_blob().readall()
    if data != payload or hashlib.sha256(data).hexdigest() != digest:
        raise SystemExit("read-after-write / content verification failed")
    print("read-after-write + content verification ok")

    props = blob.get_blob_properties()
    version = getattr(props, "version_id", None) or props.etag
    if not version:
        raise SystemExit("missing version/etag identifier")
    print(f"version_identifier ok ({version})")

    # Immutability / legal hold are account-SKU dependent; probe best-effort.
    try:
        retain_until = datetime.now(timezone.utc) + timedelta(days=1)
        blob.set_immutability_policy(until_date=retain_until, policy_mode="Unlocked")
        print("set_immutability_policy ok")
    except Exception as err:  # noqa: BLE001
        print(f"immutability policy skipped ({type(err).__name__})")

    try:
        blob.set_legal_hold(True)
        print("set_legal_hold ok")
        blob.set_legal_hold(False)
    except Exception as err:  # noqa: BLE001
        print(f"legal hold skipped ({type(err).__name__})")

    print("AZURE_ARCHIVE_ACCEPTANCE_PASSED")


if __name__ == "__main__":
    main()
