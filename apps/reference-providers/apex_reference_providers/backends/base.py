"""Backend protocol shared by local, Azure, GCS, and S3 adapters."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class PutResult:
    """Outcome of a create-only object write."""

    status: str  # created | replay | conflict
    version_id: str | None = None
    provider: str = "local"


@dataclass(frozen=True)
class HealthCapabilities:
    immutable_retention: str
    legal_hold: str
    version_identifier: str
    read_after_write: str
    content_verification: str
    provider: str


class ArchiveBackend(Protocol):
    def put(self, event_id: str, event_hash: str, body: bytes) -> PutResult: ...

    def health(self) -> HealthCapabilities: ...


def build_backend(
    kind: str,
    *,
    data_dir: str | None = None,
    # Azure
    azure_connection_string: str | None = None,
    azure_container: str | None = None,
    azure_account_url: str | None = None,
    azure_credential: str | None = None,
    # GCS
    gcs_bucket: str | None = None,
    gcs_project: str | None = None,
    gcs_credentials_file: str | None = None,
    # S3 / MinIO
    s3_endpoint: str | None = None,
    s3_bucket: str | None = None,
    s3_access_key: str | None = None,
    s3_secret_key: str | None = None,
    s3_region: str | None = None,
    s3_ca_file: str | None = None,
    # Immutability policy (S3/MinIO Object Lock)
    require_object_lock: bool = True,
    object_lock_mode: str | None = None,
    retain_days: int | None = None,
    legal_hold: bool = False,
) -> ArchiveBackend:
    kind = (kind or "local").strip().lower()
    if kind in {"local", "sqlite", "file"}:
        from .local import LocalArchiveBackend

        if not data_dir:
            raise ValueError("local backend requires data_dir")
        return LocalArchiveBackend(data_dir)
    if kind in {"azure", "azure_blob", "blob"}:
        from .azure_blob import AzureBlobArchiveBackend

        return AzureBlobArchiveBackend(
            connection_string=azure_connection_string,
            container=azure_container or "apex-events",
            account_url=azure_account_url,
            credential=azure_credential,
        )
    if kind in {"gcs", "gcp", "google"}:
        from .gcs import GcsArchiveBackend

        return GcsArchiveBackend(
            bucket=gcs_bucket or "apex-events",
            project=gcs_project,
            credentials_file=gcs_credentials_file,
        )
    if kind in {"s3", "minio"}:
        from .s3 import DEFAULT_RETAIN_DAYS, S3ArchiveBackend

        return S3ArchiveBackend(
            endpoint=s3_endpoint,
            bucket=s3_bucket or "apex-events",
            access_key=s3_access_key,
            secret_key=s3_secret_key,
            region=s3_region or "us-east-1",
            ca_file=s3_ca_file,
            require_object_lock=require_object_lock,
            object_lock_mode=object_lock_mode,
            retain_days=retain_days if retain_days is not None else DEFAULT_RETAIN_DAYS,
            legal_hold=legal_hold,
        )
    raise ValueError(f"unsupported archive backend: {kind}")
