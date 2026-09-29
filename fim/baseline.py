from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from .crypto import hmac_hex, secure_compare


BASELINE_VERSION = 1


class BaselineError(RuntimeError):
    """Base class for baseline failures."""


class BaselineNotFoundError(BaselineError):
    """Raised when monitoring starts before baseline initialization."""


class BaselineIntegrityError(BaselineError):
    """Raised when a stored baseline signature does not verify."""


@dataclass(frozen=True)
class Baseline:
    generation: str
    root: str
    hash_algorithm: str
    created_at: str
    files: dict[str, dict]

    def as_payload(self) -> dict:
        return {
            "version": BASELINE_VERSION,
            "generation": self.generation,
            "root": self.root,
            "hash_algorithm": self.hash_algorithm,
            "created_at": self.created_at,
            "files": self.files,
        }


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def build_baseline(root: Path, files: dict[str, dict]) -> Baseline:
    return Baseline(
        generation=str(uuid4()),
        root=str(root.resolve()),
        hash_algorithm="sha256",
        created_at=_utc_now(),
        files=files,
    )


def _atomic_write(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary_path = Path(temporary_name)

    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())

        try:
            temporary_path.chmod(0o600)
        except OSError:
            pass

        os.replace(temporary_path, path)
    finally:
        temporary_path.unlink(missing_ok=True)


def save_baseline(path: Path, baseline: Baseline, integrity_key: bytes) -> None:
    payload = baseline.as_payload()
    envelope = {
        "payload": payload,
        "signature": hmac_hex(integrity_key, payload),
    }
    _atomic_write(path, envelope)


def load_baseline(path: Path, integrity_key: bytes) -> Baseline:
    if not path.exists():
        raise BaselineNotFoundError(
            "Baseline does not exist. Run 'python -m fim baseline init' first."
        )

    try:
        envelope = json.loads(path.read_text(encoding="utf-8"))
        payload = envelope["payload"]
        signature = envelope["signature"]
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise BaselineIntegrityError(
            "Baseline file is unreadable or malformed"
        ) from exc

    expected = hmac_hex(integrity_key, payload)
    if not secure_compare(signature, expected):
        raise BaselineIntegrityError(
            "Baseline signature verification failed; refusing to trust it"
        )

    if payload.get("version") != BASELINE_VERSION:
        raise BaselineIntegrityError(
            f"Unsupported baseline version: {payload.get('version')}"
        )

    try:
        return Baseline(
            generation=payload["generation"],
            root=payload["root"],
            hash_algorithm=payload["hash_algorithm"],
            created_at=payload["created_at"],
            files=payload["files"],
        )
    except (KeyError, TypeError) as exc:
        raise BaselineIntegrityError(
            "Baseline payload is missing required fields"
        ) from exc
