"""S3-compatible archive backend (AWS S3 or MinIO Object Lock)."""

from __future__ import annotations

import datetime

from .base import HealthCapabilities, PutResult

#: Object Lock retention applied to every archived event. COMPLIANCE is the
#: default because GOVERNANCE is bypassable: any identity holding
#: ``s3:BypassGovernanceRetention`` can permanently erase a "retained" object
#: with a single ``DeleteObject`` call, which defeats the WORM guarantee this
#: backend exists to provide. Operators who genuinely need the escape hatch
#: must opt into GOVERNANCE explicitly.
DEFAULT_OBJECT_LOCK_MODE = "COMPLIANCE"
DEFAULT_RETAIN_DAYS = 365
VALID_OBJECT_LOCK_MODES = {"COMPLIANCE", "GOVERNANCE"}


class ArchiveRetentionError(RuntimeError):
    """The archive could not prove that immutable retention was applied.

    Terminal, not transient: retrying the same write against the same
    misconfigured bucket produces the same unprotected object.
    """


class S3ArchiveBackend:
    def __init__(
        self,
        *,
        endpoint: str | None,
        bucket: str,
        access_key: str | None,
        secret_key: str | None,
        region: str = "us-east-1",
        ca_file: str | None = None,
        object_lock_mode: str | None = None,
        retain_days: int = DEFAULT_RETAIN_DAYS,
        legal_hold: bool = False,
        require_object_lock: bool = True,
    ) -> None:
        try:
            import boto3
            from botocore.client import Config
            from botocore.exceptions import ClientError
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("s3 backend requires: pip install boto3") from exc

        if not access_key or not secret_key:
            raise ValueError("s3 backend requires access_key and secret_key")
        mode = (object_lock_mode or DEFAULT_OBJECT_LOCK_MODE).strip().upper()
        if mode not in VALID_OBJECT_LOCK_MODES:
            raise ValueError(
                f"object_lock_mode must be one of {sorted(VALID_OBJECT_LOCK_MODES)}, got {mode!r}"
            )
        if retain_days < 1:
            raise ValueError("retain_days must be at least 1")
        self._ClientError = ClientError
        self._bucket = bucket
        self._mode = mode
        self._retain_days = retain_days
        self._legal_hold = legal_hold
        self._require_object_lock = require_object_lock
        verify: bool | str = ca_file if ca_file else True
        self._s3 = boto3.client(
            "s3",
            endpoint_url=endpoint,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region,
            verify=verify,
            config=Config(signature_version="s3v4"),
        )
        if require_object_lock:
            self._assert_bucket_object_lock_enabled()

    def _assert_bucket_object_lock_enabled(self) -> None:
        """Refuse to start against a bucket that cannot hold objects immutable.

        Enabling Object Lock is a *create-time, irreversible* bucket property.
        A bucket without it silently accepts ``ObjectLockMode`` headers as
        no-ops on some implementations, so checking once at startup is the only
        way to keep an unprotected archive from looking like a protected one.
        """
        try:
            config = self._s3.get_object_lock_configuration(Bucket=self._bucket)
        except self._ClientError as err:
            code = err.response.get("Error", {}).get("Code", "")
            raise ArchiveRetentionError(
                f"bucket {self._bucket!r} does not have Object Lock enabled ({code}); "
                "recreate it with Object Lock, or set "
                "APEX_ARCHIVE_REQUIRE_OBJECT_LOCK=false for a non-compliance staging archive"
            ) from err
        enabled = config.get("ObjectLockConfiguration", {}).get("ObjectLockEnabled")
        if enabled != "Enabled":
            raise ArchiveRetentionError(
                f"bucket {self._bucket!r} reports ObjectLockEnabled={enabled!r}, expected 'Enabled'"
            )

    def _retain_until(self) -> datetime.datetime:
        return datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
            days=self._retain_days
        )

    def _verify_retention(self, key: str, version_id: str | None) -> None:
        """Prove the write is actually under retention before acknowledging it.

        A backend that accepts the lock headers and stores nothing is
        indistinguishable from a working one on the PUT response alone, so the
        acknowledgement is gated on reading the retention state back.
        """
        if not self._require_object_lock:
            return
        kwargs = {"Bucket": self._bucket, "Key": key}
        if version_id:
            kwargs["VersionId"] = version_id
        try:
            retention = self._s3.get_object_retention(**kwargs)
        except self._ClientError as err:
            code = err.response.get("Error", {}).get("Code", "")
            raise ArchiveRetentionError(
                f"archived object {key!r} has no readable Object Lock retention ({code})"
            ) from err
        applied = retention.get("Retention", {}) or {}
        if applied.get("Mode") != self._mode:
            raise ArchiveRetentionError(
                f"archived object {key!r} has retention mode {applied.get('Mode')!r}, "
                f"expected {self._mode!r}"
            )
        if not applied.get("RetainUntilDate"):
            raise ArchiveRetentionError(
                f"archived object {key!r} has no RetainUntilDate"
            )

    def put(self, event_id: str, event_hash: str, body: bytes) -> PutResult:
        key = f"events/{event_id}.pb"
        try:
            # Head first for conflict detection; Put with IfNoneMatch for create-only.
            try:
                head = self._s3.head_object(Bucket=self._bucket, Key=key)
                meta = head.get("Metadata") or {}
                existing = meta.get("apex_event_hash") or meta.get("apex-event-hash")
                if existing == event_hash:
                    return PutResult(
                        status="replay",
                        version_id=head.get("VersionId"),
                        provider="s3",
                    )
                return PutResult(status="conflict", provider="s3")
            except self._ClientError as err:
                if err.response.get("Error", {}).get("Code") not in {
                    "404",
                    "NoSuchKey",
                    "NotFound",
                }:
                    code = err.response.get("Error", {}).get("Code", "")
                    if code not in {"404", "NoSuchKey", "NotFound"}:
                        # head_object uses 404 HTTP
                        if err.response.get("ResponseMetadata", {}).get("HTTPStatusCode") != 404:
                            raise
            put_kwargs = {
                "Bucket": self._bucket,
                "Key": key,
                "Body": body,
                "ContentType": "application/x-protobuf",
                "Metadata": {
                    "apex_event_hash": event_hash,
                    "apex_event_id": event_id,
                },
                # Create-only when supported by the implementation.
                "IfNoneMatch": "*",
            }
            if self._require_object_lock:
                # Without these two headers the object is written with no
                # retention at all -- a bucket with Object Lock merely
                # *enabled* applies nothing by default, so the object stays
                # deletable by the archive's own credential.
                put_kwargs["ObjectLockMode"] = self._mode
                put_kwargs["ObjectLockRetainUntilDate"] = self._retain_until()
                if self._legal_hold:
                    put_kwargs["ObjectLockLegalHoldStatus"] = "ON"
            result = self._s3.put_object(**put_kwargs)
            version_id = result.get("VersionId")
            self._verify_retention(key, version_id)
            return PutResult(
                status="created",
                version_id=version_id,
                provider="s3",
            )
        except self._ClientError as err:
            code = err.response.get("Error", {}).get("Code", "")
            if code in {"PreconditionFailed", "412"}:
                # Race: object appeared; re-check hash.
                try:
                    head = self._s3.head_object(Bucket=self._bucket, Key=key)
                    meta = head.get("Metadata") or {}
                    existing = meta.get("apex_event_hash") or meta.get("apex-event-hash")
                    if existing == event_hash:
                        return PutResult(
                            status="replay",
                            version_id=head.get("VersionId"),
                            provider="s3",
                        )
                except self._ClientError:
                    pass
                return PutResult(status="conflict", provider="s3")
            raise

    def health(self) -> HealthCapabilities:
        # Declared from the configuration actually in force, not assumed. An
        # archive running with retention disabled must not advertise
        # immutability to a compliance-required deployment.
        retention = "required" if self._require_object_lock else "unavailable"
        return HealthCapabilities(
            immutable_retention=retention,
            legal_hold="supported" if self._require_object_lock else "unavailable",
            version_identifier="supported",
            read_after_write="supported",
            content_verification="supported",
            provider="s3",
        )
