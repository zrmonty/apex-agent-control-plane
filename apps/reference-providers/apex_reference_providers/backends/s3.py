"""S3-compatible archive backend (AWS S3 or MinIO Object Lock)."""

from __future__ import annotations

from .base import HealthCapabilities, PutResult


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
    ) -> None:
        try:
            import boto3
            from botocore.client import Config
            from botocore.exceptions import ClientError
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("s3 backend requires: pip install boto3") from exc

        if not access_key or not secret_key:
            raise ValueError("s3 backend requires access_key and secret_key")
        self._ClientError = ClientError
        self._bucket = bucket
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
            result = self._s3.put_object(
                Bucket=self._bucket,
                Key=key,
                Body=body,
                ContentType="application/x-protobuf",
                Metadata={
                    "apex_event_hash": event_hash,
                    "apex_event_id": event_id,
                },
                # Create-only when supported by the implementation.
                IfNoneMatch="*",
            )
            return PutResult(
                status="created",
                version_id=result.get("VersionId"),
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
        return HealthCapabilities(
            immutable_retention="supported",
            legal_hold="supported",
            version_identifier="supported",
            read_after_write="supported",
            content_verification="supported",
            provider="s3",
        )
