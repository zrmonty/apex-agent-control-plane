"""Google Cloud Storage archive backend (bucket retention / temporary hold).

Uses the GCS SDK only inside this adapter process — never inside event-ingest.
Create-only writes use if_generation_match=0. Hash is stored as custom metadata.
"""

from __future__ import annotations

from ..common import MAX_EVENT_BYTES
from .base import ArchiveVerificationError
from .base import HealthCapabilities, PutResult


class GcsArchiveBackend:
    def __init__(
        self,
        *,
        bucket: str,
        project: str | None = None,
        credentials_file: str | None = None,
    ) -> None:
        try:
            from google.api_core import exceptions as gax
            from google.cloud import storage
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "gcs backend requires: pip install google-cloud-storage"
            ) from exc

        self._gax = gax
        if credentials_file:
            self._client = storage.Client.from_service_account_json(
                credentials_file, project=project
            )
        else:
            # Application Default Credentials (workload identity / gcloud).
            self._client = storage.Client(project=project)
        self._bucket = self._client.bucket(bucket)
        if not self._bucket.exists():
            raise RuntimeError(
                f"GCS bucket {bucket!r} does not exist; provision with retention "
                "policy before starting the archive-provider"
            )
        self._bucket.reload()
        if not getattr(self._bucket, "retention_period", None):
            raise RuntimeError(
                f"GCS bucket {bucket!r} has no readable retention policy; refusing an unprotected archive"
            )

    def _verify_content(self, blob, event_hash: str, body: bytes) -> None:
        try:
            blob.reload()
        except Exception as exc:  # noqa: BLE001
            raise ArchiveVerificationError("provider metadata readback failed") from exc
        if blob.size != len(body) or (blob.size or 0) > MAX_EVENT_BYTES:
            raise ArchiveVerificationError("provider returned an unexpected object size")
        if (blob.metadata or {}).get("apex_event_hash") != event_hash:
            raise ArchiveVerificationError("provider returned an unexpected event hash")
        try:
            actual = blob.download_as_bytes()
        except Exception as exc:  # noqa: BLE001
            raise ArchiveVerificationError("provider readback failed") from exc
        if actual != body:
            raise ArchiveVerificationError("provider readback did not match the request")

    def put(self, event_id: str, event_hash: str, body: bytes) -> PutResult:
        blob = self._bucket.blob(f"events/{event_id}.pb")
        blob.metadata = {"apex_event_hash": event_hash, "apex_event_id": event_id}
        try:
            blob.upload_from_string(
                body,
                content_type="application/x-protobuf",
                if_generation_match=0,
            )
            self._verify_content(blob, event_hash, body)
            return PutResult(
                status="created",
                version_id=str(blob.generation) if blob.generation is not None else None,
                provider="gcs",
            )
        except self._gax.PreconditionFailed:
            try:
                blob.reload()
            except Exception as exc:  # noqa: BLE001
                raise ArchiveVerificationError("provider metadata readback failed") from exc
            existing = (blob.metadata or {}).get("apex_event_hash")
            if existing == event_hash:
                self._verify_content(blob, event_hash, body)
                return PutResult(
                    status="replay",
                    version_id=str(blob.generation)
                    if blob.generation is not None
                    else None,
                    provider="gcs",
                )
            return PutResult(status="conflict", provider="gcs")
        except self._gax.Conflict:
            return PutResult(status="conflict", provider="gcs")

    def health(self) -> HealthCapabilities:
        return HealthCapabilities(
            immutable_retention="required",
            legal_hold="unavailable",
            version_identifier="supported",
            read_after_write="supported",
            content_verification="supported",
            provider="gcs",
        )
