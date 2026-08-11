"""Shared credential-file reading discipline for the gRPC transports.

Split out of ``control_transport.py``. Both
``control_transport.GrpcControlTransport`` and
``ingest_transport.GrpcEventIngestTransport`` load their mTLS certificate,
key, and bearer-token material through this one function and enforce the
same rules -- symlinks refused, size bounded, private material refused if
readable beyond its owner, the same rules the Rust services apply to the
same files. ``ingest_transport`` has always reused this outright rather than
inventing a second style (see that module's docstring); this module is the
one place both transports import it from, so neither owns the other's
credential-loading code.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

from .errors import ConfigurationError

#: Bound on any credential file this module reads. A workload certificate,
#: key, CA bundle or bearer token that is larger than this is a
#: misconfiguration, and reading it unbounded would let a mounted file decide
#: how much memory the agent process allocates.
MAX_CREDENTIAL_BYTES = 1024 * 1024


def _read_credential_file(path: Path, label: str, *, private: bool) -> bytes:
    """Reads one credential file under the SDK's usual path discipline.

    Symlinks are refused, size is bounded, and private material is refused if
    it is readable beyond its owner -- the same rules the Rust services apply
    to the same files, so a deployment cannot end up with an agent that happily
    reads key material its own gateway would reject.
    """
    try:
        if path.is_symlink():
            raise ConfigurationError(f"{label} must not be a symbolic link")
        resolved = path.resolve(strict=True)
        info = resolved.stat()
    except OSError as exc:
        raise ConfigurationError(f"{label} is not available at the configured path") from exc
    if not stat.S_ISREG(info.st_mode):
        raise ConfigurationError(f"{label} must be a regular file")
    if info.st_size == 0 or info.st_size > MAX_CREDENTIAL_BYTES:
        raise ConfigurationError(f"{label} has an invalid size")
    # Windows ACLs do not map onto POSIX mode bits; enforce where they mean
    # something, exactly as bundle.py already does for trust directories.
    if private and os.name == "posix" and info.st_mode & 0o077:
        raise ConfigurationError(f"{label} permissions are too broad; it must be readable only by its owner")
    try:
        return resolved.read_bytes()
    except OSError as exc:
        raise ConfigurationError(f"{label} could not be read") from exc
