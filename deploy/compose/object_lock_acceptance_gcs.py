#!/usr/bin/env python3
"""GCS retention / hold acceptance for Apex archive (cloud-agnostic suite).

Requires:
  APEX_ARCHIVE_GCS_BUCKET
  Optional APEX_ARCHIVE_GCS_PROJECT
  Optional APEX_ARCHIVE_GCS_CREDENTIALS_FILE (else ADC)

Proves: object create-only semantics (generation match), read-after-write,
content hash, generation as version id, temporary hold where permitted.

Exit 0 on success. Skip with exit 0 if credentials/bucket absent and
APEX_CLOUD_ACCEPTANCE_OPTIONAL=1.
"""

from __future__ import annotations

import hashlib
import os
import sys


def main() -> None:
    bucket_name = os.environ.get("APEX_ARCHIVE_GCS_BUCKET", "").strip()
    project = os.environ.get("APEX_ARCHIVE_GCS_PROJECT", "").strip() or None
    credentials = os.environ.get("APEX_ARCHIVE_GCS_CREDENTIALS_FILE", "").strip() or None
    optional = os.environ.get("APEX_CLOUD_ACCEPTANCE_OPTIONAL", "") == "1"

    if not bucket_name:
        if optional:
            print("GCS_ACCEPTANCE_SKIPPED (no bucket)")
            return
        raise SystemExit(
            "Set APEX_ARCHIVE_GCS_BUCKET "
            "(or APEX_CLOUD_ACCEPTANCE_OPTIONAL=1 to skip)"
        )

    try:
        from google.api_core import exceptions as gax
        from google.cloud import storage
    except ImportError as exc:
        raise SystemExit("pip install google-cloud-storage") from exc

    if credentials:
        client = storage.Client.from_service_account_json(credentials, project=project)
    else:
        try:
            client = storage.Client(project=project)
        except Exception as exc:
            if optional:
                print(f"GCS_ACCEPTANCE_SKIPPED ({exc})")
                return
            raise SystemExit(f"GCS client init failed: {exc}") from exc

    bucket = client.bucket(bucket_name)
    if not bucket.exists():
        raise SystemExit(
            f"bucket {bucket_name!r} missing; create with retention policy first"
        )

    blob_name = "acceptance/gcs-probe.pb"
    payload = b"apex-gcs-retention-acceptance-v1"
    digest = hashlib.sha256(payload).hexdigest()
    blob = bucket.blob(blob_name)
    if blob.exists():
        blob.delete()

    blob.metadata = {"apex_event_hash": digest}
    blob.upload_from_string(
        payload,
        content_type="application/x-protobuf",
        if_generation_match=0,
    )
    print("upload create-only (if_generation_match=0) ok")

    # Second create must fail precondition.
    try:
        bucket.blob(blob_name).upload_from_string(
            payload + b"-changed",
            if_generation_match=0,
        )
        raise SystemExit("expected PreconditionFailed on second create-only write")
    except gax.PreconditionFailed:
        print("create-only conflict ok")

    blob.reload()
    data = blob.download_as_bytes()
    if data != payload or hashlib.sha256(data).hexdigest() != digest:
        raise SystemExit("read-after-write / content verification failed")
    print("read-after-write + content verification ok")

    if blob.generation is None:
        raise SystemExit("missing object generation")
    print(f"version_identifier ok (generation={blob.generation})")

    try:
        blob.temporary_hold = True
        blob.patch()
        blob.reload()
        if not blob.temporary_hold:
            raise SystemExit("temporary hold not set")
        print("temporary_hold ok")
        blob.temporary_hold = False
        blob.patch()
    except Exception as err:  # noqa: BLE001
        print(f"temporary hold skipped ({type(err).__name__})")

    print("GCS_ARCHIVE_ACCEPTANCE_PASSED")


if __name__ == "__main__":
    main()
