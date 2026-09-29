from __future__ import annotations

from dataclasses import dataclass

from .baseline import Baseline
from .scanner import ScanError, ScanResult


@dataclass(frozen=True)
class Detection:
    event_type: str
    path: str
    severity: str
    old_state: dict | None
    new_state: dict | None
    details: dict


def _under_error_scope(path: str, errors: tuple[ScanError, ...]) -> bool:
    for error in errors:
        if error.is_scope:
            prefix = error.path.rstrip("/")
            if path == prefix or path.startswith(prefix + "/"):
                return True
        elif path == error.path:
            return True
    return False


def detect_changes(
    baseline: Baseline,
    scan: ScanResult,
) -> list[Detection]:
    detections: list[Detection] = []
    baseline_files = baseline.files
    current_files = scan.files

    for error in scan.errors:
        detections.append(
            Detection(
                event_type="SCAN_ERROR",
                path=error.path,
                severity="HIGH",
                old_state=None,
                new_state=None,
                details={
                    "reason": error.reason,
                    "scope_error": error.is_scope,
                },
            )
        )

    for path, new_state in sorted(current_files.items()):
        old_state = baseline_files.get(path)

        if old_state is None:
            detections.append(
                Detection(
                    event_type="ADDED",
                    path=path,
                    severity="MEDIUM",
                    old_state=None,
                    new_state=new_state,
                    details={},
                )
            )
            continue

        if old_state.get("file_type") != new_state.get("file_type"):
            detections.append(
                Detection(
                    event_type="MODIFIED",
                    path=path,
                    severity="HIGH",
                    old_state=old_state,
                    new_state=new_state,
                    details={"changes": ["file_type"]},
                )
            )
            continue

        if old_state.get("sha256") != new_state.get("sha256"):
            event_type = (
                "SYMLINK_CHANGED"
                if new_state.get("file_type") == "symlink"
                else "MODIFIED"
            )
            detections.append(
                Detection(
                    event_type=event_type,
                    path=path,
                    severity="HIGH",
                    old_state=old_state,
                    new_state=new_state,
                    details={"changes": ["content"]},
                )
            )
            continue

        security_metadata = ("mode", "uid", "gid")
        metadata_changes = [
            field
            for field in security_metadata
            if old_state.get(field) != new_state.get(field)
        ]
        if metadata_changes:
            detections.append(
                Detection(
                    event_type="METADATA_CHANGED",
                    path=path,
                    severity="MEDIUM",
                    old_state=old_state,
                    new_state=new_state,
                    details={"changes": metadata_changes},
                )
            )

    for path, old_state in sorted(baseline_files.items()):
        if path in current_files:
            continue
        if _under_error_scope(path, scan.errors):
            # A read/walk failure must never be silently reclassified as deletion.
            continue
        detections.append(
            Detection(
                event_type="DELETED",
                path=path,
                severity="HIGH",
                old_state=old_state,
                new_state=None,
                details={},
            )
        )

    return detections
