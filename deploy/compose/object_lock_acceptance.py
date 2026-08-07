#!/usr/bin/env python3
"""Object-Lock acceptance checks against an S3-compatible archive store (MinIO).

Requires:
  - MINIO_ENDPOINT (https://host:9000)
  - MINIO_ACCESS_KEY / MINIO_SECRET_KEY (or *_FILE)
  - MINIO_BUCKET
  - Optional MINIO_CA_FILE for TLS verification

Exit 0 only when create/read, retention, legal-hold, and content verify succeed.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import ssl
import sys
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path


def _cred(name: str) -> str:
    file_key = f"{name}_FILE"
    if file_key in os.environ and os.environ[file_key]:
        return Path(os.environ[file_key]).read_text(encoding="utf-8").strip()
    return os.environ.get(name, "").strip()


def _provider_s3_module():
    """Import the reference archive backend from the repo checkout.

    The acceptance script runs standalone (no installed package), so the
    provider tree is added to sys.path here rather than relying on the caller
    to set PYTHONPATH.
    """
    providers = Path(__file__).resolve().parents[2] / "apps" / "reference-providers"
    if str(providers) not in sys.path:
        sys.path.insert(0, str(providers))
    try:
        from apex_reference_providers.backends import s3 as provider_s3
    except ImportError as exc:
        raise SystemExit(
            f"archive backend checks require the reference provider package under {providers}: {exc}"
        ) from exc
    return provider_s3


def _ssl_context(ca_file: str | None) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if ca_file:
        ctx.load_verify_locations(cafile=ca_file)
    return ctx


def signed_request(
    method: str,
    url: str,
    *,
    access: str,
    secret: str,
    body: bytes = b"",
    headers: dict[str, str] | None = None,
    ca_file: str | None = None,
) -> tuple[int, dict[str, str], bytes]:
    # MinIO accepts path-style requests; for acceptance we use the AWS SigV4-less
    # path only when the server is configured with anonymous disabled — use
    # botocore if available, else urllib with AWS4 via aws-requests-auth-like
    # minimal path using environment pre-signed not available.
    #
    # Prefer boto3 when installed for SigV4.
    try:
        import boto3
        from botocore.client import Config
    except ImportError as exc:  # pragma: no cover
        raise SystemExit(
            "object_lock_acceptance requires boto3: python -m pip install boto3"
        ) from exc

    # Parse endpoint
    from urllib.parse import urlparse

    parsed = urlparse(url if "://" in url else f"https://{url}")
    endpoint = f"{parsed.scheme}://{parsed.netloc}"
    verify: bool | str = ca_file if ca_file else True
    client = boto3.client(
        "s3",
        endpoint_url=endpoint,
        aws_access_key_id=access,
        aws_secret_access_key=secret,
        region_name="us-east-1",
        verify=verify,
        config=Config(signature_version="s3v4"),
    )
    return client  # type: ignore[return-value]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--endpoint",
        default=os.environ.get("MINIO_ENDPOINT", "https://127.0.0.1:9000"),
    )
    parser.add_argument("--bucket", default=os.environ.get("MINIO_BUCKET", "apex-events"))
    parser.add_argument("--ca-file", default=os.environ.get("MINIO_CA_FILE"))
    parser.add_argument(
        "--allow-missing-legal-hold",
        action="store_true",
        help="report partial assurance instead of failing when the provider cannot prove legal hold",
    )
    args = parser.parse_args()
    access = _cred("MINIO_ACCESS_KEY") or _cred("MINIO_ROOT_USER")
    secret = _cred("MINIO_SECRET_KEY") or _cred("MINIO_ROOT_PASSWORD")
    if not access or not secret:
        raise SystemExit("MINIO_ACCESS_KEY and MINIO_SECRET_KEY (or root) are required")

    try:
        import boto3
        from botocore.client import Config
        from botocore.exceptions import ClientError
    except ImportError as exc:
        raise SystemExit("pip install boto3") from exc

    from urllib.parse import urlparse

    parsed = urlparse(args.endpoint)
    endpoint = f"{parsed.scheme}://{parsed.netloc}"
    verify: bool | str = args.ca_file if args.ca_file else True
    # Newer botocore defaults can force flexible checksums that MinIO rejects on
    # LegalHold with MissingContentMD5. Prefer when_required when supported.
    client_config_kwargs = {"signature_version": "s3v4"}
    try:
        client_config_kwargs["request_checksum_calculation"] = "when_required"
        client_config_kwargs["response_checksum_validation"] = "when_required"
        client_config = Config(**client_config_kwargs)
    except TypeError:
        client_config = Config(signature_version="s3v4")
    s3 = boto3.client(
        "s3",
        endpoint_url=endpoint,
        aws_access_key_id=access,
        aws_secret_access_key=secret,
        region_name="us-east-1",
        verify=verify,
        config=client_config,
    )

    key = "object-lock-acceptance/probe.bin"
    payload = b"apex-object-lock-acceptance-v1"
    digest = hashlib.sha256(payload).hexdigest()

    # Ensure bucket exists with object lock (create may fail if already present).
    try:
        s3.create_bucket(
            Bucket=args.bucket,
            ObjectLockEnabledForBucket=True,
        )
        print("bucket created with ObjectLockEnabledForBucket")
    except ClientError as err:
        code = err.response.get("Error", {}).get("Code", "")
        if code not in {"BucketAlreadyOwnedByYou", "BucketAlreadyExists"}:
            raise
        print("bucket already exists; continuing")

    s3.put_object(
        Bucket=args.bucket,
        Key=key,
        Body=payload,
        ContentType="application/octet-stream",
        ObjectLockMode="GOVERNANCE",
        ObjectLockRetainUntilDate=__import__("datetime").datetime.now(
            __import__("datetime").timezone.utc
        )
        + __import__("datetime").timedelta(days=1),
    )
    print("put_object with GOVERNANCE retention ok")

    body = s3.get_object(Bucket=args.bucket, Key=key)["Body"].read()
    if body != payload:
        raise SystemExit("read-after-write content mismatch")
    if hashlib.sha256(body).hexdigest() != digest:
        raise SystemExit("content verification hash mismatch")
    print("read-after-write + content verification ok")

    retention = s3.get_object_retention(Bucket=args.bucket, Key=key)
    mode = retention.get("Retention", {}).get("Mode")
    if mode != "GOVERNANCE":
        raise SystemExit(f"unexpected retention mode: {mode}")
    print("get_object_retention ok")

    try:
        # MinIO + recent botocore often disagree on Content-MD5 / flexible
        # checksums for PutObjectLegalHold. Retention already proved above.
        s3.put_object_legal_hold(
            Bucket=args.bucket,
            Key=key,
            LegalHold={"Status": "ON"},
        )
        hold = s3.get_object_legal_hold(Bucket=args.bucket, Key=key)
        if hold.get("LegalHold", {}).get("Status") != "ON":
            raise SystemExit("legal hold not ON")
        print("legal hold ok")
    except ClientError as err:
        code = err.response.get("Error", {}).get("Code", "") or "ClientError"
        if args.allow_missing_legal_hold:
            print(f"legal hold API skipped ({code}); retention check is PARTIAL")
        elif code in {"MissingContentMD5", "NotImplemented", "InvalidRequest", "MalformedXML"}:
            raise SystemExit(
                f"legal hold proof is required for strict retention acceptance ({code}); "
                "use --allow-missing-legal-hold only for an explicitly partial local check"
            ) from err
        else:
            raise

    head = s3.head_object(Bucket=args.bucket, Key=key)
    if "VersionId" not in head:
        raise SystemExit("version identifier missing on head_object")
    print(f"version_identifier ok ({head['VersionId']})")

    _assert_deletion_denied(s3, args.bucket, ClientError)
    _assert_archive_backend_applies_retention(s3, args, ClientError)

    print("OBJECT_LOCK_ACCEPTANCE_PASSED")


def _assert_archive_backend_applies_retention(s3, args, client_error) -> None:
    """Prove the *archive write path* produces retained objects.

    Regression guard. Proving MinIO supports Object Lock says nothing about
    whether Apex uses it. The S3 backend previously called `put_object` with no
    `ObjectLockMode`/`ObjectLockRetainUntilDate`, and because a bucket with
    Object Lock merely enabled applies no default retention, every archived
    event was written completely unprotected and could be erased with a single
    `DeleteObject`. This check writes through the real backend and then reads
    the retention state back.
    """
    import datetime as _dt

    s3_module = _provider_s3_module()
    DEFAULT_OBJECT_LOCK_MODE = s3_module.DEFAULT_OBJECT_LOCK_MODE
    ArchiveRetentionError = s3_module.ArchiveRetentionError
    from apex_reference_providers.backends import build_backend  # noqa: PLC0415

    access = _cred("MINIO_ACCESS_KEY") or _cred("MINIO_ROOT_USER")
    secret = _cred("MINIO_SECRET_KEY") or _cred("MINIO_ROOT_PASSWORD")
    backend = build_backend(
        "s3",
        s3_endpoint=args.endpoint,
        s3_bucket=args.bucket,
        s3_access_key=access,
        s3_secret_key=secret,
        s3_region="us-east-1",
        s3_ca_file=args.ca_file,
        require_object_lock=True,
        retain_days=1,
    )

    capabilities = backend.health()
    if capabilities.immutable_retention != "required":
        raise SystemExit(
            "archive backend must declare immutable_retention=required when Object Lock is enforced, "
            f"got {capabilities.immutable_retention!r}"
        )

    event_id = "0190abcd-1234-7abc-8def-" + _dt.datetime.now().strftime("%H%M%S%f")[:12]
    result = backend.put(event_id, "a" * 64, b"apex-archive-retention-regression")
    if result.status != "created":
        raise SystemExit(f"archive backend put returned {result.status!r}, expected 'created'")

    key = f"events/{event_id}.pb"
    retention = s3.get_object_retention(Bucket=args.bucket, Key=key, VersionId=result.version_id)
    mode = retention.get("Retention", {}).get("Mode")
    if mode != DEFAULT_OBJECT_LOCK_MODE:
        raise SystemExit(
            f"archive backend wrote an object with retention mode {mode!r}, "
            f"expected {DEFAULT_OBJECT_LOCK_MODE!r}"
        )
    print(f"archive backend write path applies {mode} retention")

    try:
        s3.delete_object(Bucket=args.bucket, Key=key, VersionId=result.version_id)
    except client_error as err:
        print(f"  archived event resists deletion ({err.response.get('Error', {}).get('Code')}) ok")
    else:
        raise SystemExit("archive backend wrote a DELETABLE event object")

    # The backend must refuse to start against a bucket that cannot retain.
    unprotected = f"{args.bucket}-no-lock-probe"
    try:
        s3.create_bucket(Bucket=unprotected)
    except client_error:
        pass
    try:
        build_backend(
            "s3",
            s3_endpoint=args.endpoint,
            s3_bucket=unprotected,
            s3_access_key=access,
            s3_secret_key=secret,
            s3_region="us-east-1",
            s3_ca_file=args.ca_file,
            require_object_lock=True,
        )
    except ArchiveRetentionError:
        print("  archive backend fails closed on a non-Object-Lock bucket ok")
    else:
        raise SystemExit("archive backend started against a bucket without Object Lock")


def _assert_deletion_denied(s3, bucket: str, client_error) -> None:
    """Prove the archive write path produces an object that cannot be deleted.

    contracts/archive-provider/v1.md requires every adapter to prove that
    "mutation and deletion are denied while protected". Proving the *store*
    supports Object Lock is not the same claim and does not imply it: a bucket
    with Object Lock merely enabled applies no retention by default, so an
    object written without explicit lock headers is fully deletable. This
    check therefore writes the object the way the archive backend writes it
    and then tries to destroy it.
    """
    import datetime as _dt

    DEFAULT_OBJECT_LOCK_MODE = _provider_s3_module().DEFAULT_OBJECT_LOCK_MODE

    key = "object-lock-acceptance/deletion-probe.pb"
    payload = b"apex-deletion-denial-probe-v1"
    retain_until = _dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(days=1)
    put = s3.put_object(
        Bucket=bucket,
        Key=key,
        Body=payload,
        ContentType="application/x-protobuf",
        Metadata={"apex_event_hash": "0" * 64, "apex_event_id": "deletion-probe"},
        ObjectLockMode=DEFAULT_OBJECT_LOCK_MODE,
        ObjectLockRetainUntilDate=retain_until,
    )
    version_id = put.get("VersionId")
    if not version_id:
        raise SystemExit("deletion probe: bucket is not versioned; Object Lock cannot apply")

    retention = s3.get_object_retention(Bucket=bucket, Key=key, VersionId=version_id)
    mode = retention.get("Retention", {}).get("Mode")
    if mode != DEFAULT_OBJECT_LOCK_MODE:
        raise SystemExit(
            f"deletion probe: retention mode is {mode!r}, expected {DEFAULT_OBJECT_LOCK_MODE!r}"
        )
    print(f"deletion probe: written under {mode} retention")

    def _must_fail(label: str, call) -> None:
        try:
            call()
        except client_error as err:
            print(f"  {label}: denied ({err.response.get('Error', {}).get('Code')}) ok")
            return
        raise SystemExit(f"deletion probe: {label} SUCCEEDED against a retained object")

    _must_fail(
        "DeleteObject(VersionId)",
        lambda: s3.delete_object(Bucket=bucket, Key=key, VersionId=version_id),
    )
    _must_fail(
        "DeleteObject(VersionId, BypassGovernanceRetention)",
        lambda: s3.delete_object(
            Bucket=bucket,
            Key=key,
            VersionId=version_id,
            BypassGovernanceRetention=True,
        ),
    )
    # DeleteObjects reports per-key failures in the response body rather than
    # raising, so an empty Errors list here means the batch call really did
    # erase a retained version.
    batch = s3.delete_objects(
        Bucket=bucket,
        Delete={"Objects": [{"Key": key, "VersionId": version_id}]},
    )
    if batch.get("Deleted"):
        raise SystemExit("deletion probe: DeleteObjects batch erased a retained version")
    print(f"  DeleteObjects(batch): denied ({batch.get('Errors', [{}])[0].get('Code')}) ok")

    # Retention must survive every attempt above.
    survivor = s3.head_object(Bucket=bucket, Key=key, VersionId=version_id)
    if survivor["ContentLength"] != len(payload):
        raise SystemExit("deletion probe: retained object was mutated")
    print("deletion probe: retained version intact after every delete attempt")


if __name__ == "__main__":
    main()
