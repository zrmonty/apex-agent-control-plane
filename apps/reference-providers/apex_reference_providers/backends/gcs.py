"""Google Cloud Storage archive backend (bucket retention / temporary hold).

Uses the GCS SDK only inside this adapter process — never inside event-ingest.
Create-only writes use if_generation_match=0. Hash is stored as custom metadata.
"""

from __future__ import annotations

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

    def put(self, event_id: str, event_hash: str, body: bytes) -> PutResult:
        blob = self._bucket.blob(f"events/{event_id}.pb")
        blob.metadata = {"apex_event_hash": event_hash, "apex_event_id": event_id}
        try:
            blob.upload_from_string(
                body,
                content_type="application/x-protobuf",
                if_generation_match=0,
            )
            blob.reload()
            return PutResult(
                status="created",
                version_id=str(blob.generation) if blob.generation is not None else None,
                provider="gcs",
            )
        except self._gax.PreconditionFailed:
            blob.reload()
            existing = (blob.metadata or {}).get("apex_event_hash")
            if existing == event_hash:
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
            immutable_retention="supported",
            legal_hold="supported",
            version_identifier="supported",
            read_after_write="supported",
            content_verification="supported",
            provider="gcs",
        )
