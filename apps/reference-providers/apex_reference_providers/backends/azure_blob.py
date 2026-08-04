"""Azure Blob Storage archive backend (immutable container / legal hold).

Uses the Azure SDK only inside this adapter process — never inside event-ingest.
Create-only writes use If-None-Match: *. Hash is stored as blob metadata.
"""

from __future__ import annotations

from .base import HealthCapabilities, PutResult


class AzureBlobArchiveBackend:
    def __init__(
        self,
        *,
        connection_string: str | None,
        container: str,
        account_url: str | None = None,
        credential: str | None = None,
    ) -> None:
        try:
            from azure.core.exceptions import ResourceExistsError, ResourceModifiedError
            from azure.storage.blob import BlobServiceClient, ContentSettings
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "azure backend requires: pip install azure-storage-blob"
            ) from exc

        self._ResourceExistsError = ResourceExistsError
        self._ResourceModifiedError = ResourceModifiedError
        self._ContentSettings = ContentSettings
        self._container = container

        if connection_string:
            self._service = BlobServiceClient.from_connection_string(connection_string)
        elif account_url and credential:
            # credential may be account key string for SharedKeyCredential
            from azure.storage.blob import BlobServiceClient as BSC

            self._service = BSC(account_url=account_url, credential=credential)
        else:
            raise ValueError(
                "azure backend requires APEX_ARCHIVE_AZURE_CONNECTION_STRING "
                "or account_url + credential"
            )

        # Ensure container exists (immutability policy is an ops/pre-provision step).
        try:
            self._service.create_container(container)
        except ResourceExistsError:
            pass
        self._cc = self._service.get_container_client(container)

    def put(self, event_id: str, event_hash: str, body: bytes) -> PutResult:
        blob = self._cc.get_blob_client(f"events/{event_id}.pb")
        metadata = {"apex_event_hash": event_hash, "apex_event_id": event_id}
        try:
            result = blob.upload_blob(
                body,
                overwrite=False,
                metadata=metadata,
                content_settings=self._ContentSettings(
                    content_type="application/x-protobuf"
                ),
            )
            version = getattr(result, "version_id", None) or getattr(
                result, "etag", None
            )
            return PutResult(
                status="created",
                version_id=str(version) if version else None,
                provider="azure_blob",
            )
        except self._ResourceExistsError:
            props = blob.get_blob_properties()
            existing = (props.metadata or {}).get("apex_event_hash")
            if existing == event_hash:
                version = getattr(props, "version_id", None) or props.etag
                return PutResult(
                    status="replay",
                    version_id=str(version) if version else None,
                    provider="azure_blob",
                )
            return PutResult(status="conflict", provider="azure_blob")
        except self._ResourceModifiedError:
            return PutResult(status="conflict", provider="azure_blob")

    def health(self) -> HealthCapabilities:
        # Capabilities depend on container immutability policy provisioned by ops.
        return HealthCapabilities(
            immutable_retention="supported",
            legal_hold="supported",
            version_identifier="supported",
            read_after_write="supported",
            content_verification="supported",
            provider="azure_blob",
        )
