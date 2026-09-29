from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from pathlib import Path

from .baseline import (
    BaselineIntegrityError,
    BaselineNotFoundError,
    build_baseline,
    load_baseline,
    save_baseline,
)
from .config import Settings
from .detection import detect_changes
from .events import EventStore
from .jira import JiraClient, process_pending_deliveries
from .scanner import scan_tree


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ScanSummary:
    detections: int
    new_events: int
    delivered: int
    retrying: int
    dead_letter: int


def _store(settings: Settings) -> EventStore:
    return EventStore(settings.database_path, settings.integrity_key)


def _assert_baseline_root(settings: Settings, baseline_root: str) -> None:
    expected = str(settings.monitor_path.resolve())
    actual = str(Path(baseline_root).resolve())
    if expected != actual:
        raise BaselineIntegrityError(
            "Baseline was created for a different monitored directory"
        )


def initialize_baseline(settings: Settings, force: bool = False) -> int:
    if settings.baseline_path.exists() and not force:
        raise RuntimeError(
            "Baseline already exists. Use --force only when intentionally "
            "re-initializing trust."
        )

    scan = scan_tree(settings.monitor_path, settings.exclude_patterns)
    if scan.errors:
        reasons = "; ".join(
            f"{error.path}: {error.reason}" for error in scan.errors[:5]
        )
        raise RuntimeError(
            "Refusing to initialize an incomplete baseline because scan "
            f"errors occurred: {reasons}"
        )

    baseline = build_baseline(settings.monitor_path, scan.files)
    save_baseline(
        settings.baseline_path,
        baseline,
        settings.integrity_key,
    )

    store = _store(settings)
    store.add_event(
        baseline_generation=baseline.generation,
        event_type="BASELINE_INITIALIZED",
        path=".",
        severity="INFO",
        details={"file_count": len(scan.files), "forced": force},
        queue_jira=False,
    )

    logger.info(
        "Initialized signed baseline with %d files",
        len(scan.files),
    )
    return len(scan.files)


def accept_current_state(settings: Settings, reason: str) -> int:
    if not reason.strip():
        raise ValueError("A reason is required when accepting a new baseline")

    old = load_baseline(
        settings.baseline_path,
        settings.integrity_key,
    )
    _assert_baseline_root(settings, old.root)

    scan = scan_tree(settings.monitor_path, settings.exclude_patterns)
    if scan.errors:
        reasons = "; ".join(
            f"{error.path}: {error.reason}" for error in scan.errors[:5]
        )
        raise RuntimeError(
            "Refusing to accept a baseline while scan errors exist: "
            + reasons
        )

    new = build_baseline(settings.monitor_path, scan.files)
    save_baseline(
        settings.baseline_path,
        new,
        settings.integrity_key,
    )

    store = _store(settings)
    store.add_event(
        baseline_generation=new.generation,
        event_type="BASELINE_ACCEPTED",
        path=".",
        severity="INFO",
        details={
            "reason": reason.strip(),
            "file_count": len(scan.files),
            "previous_generation": old.generation,
        },
        queue_jira=False,
    )

    logger.info(
        "Accepted new baseline generation %s (%d files)",
        new.generation,
        len(scan.files),
    )
    return len(scan.files)


def scan_once(
    settings: Settings,
    *,
    deliver: bool = True,
) -> ScanSummary:
    store = _store(settings)

    try:
        baseline = load_baseline(
            settings.baseline_path,
            settings.integrity_key,
        )
        _assert_baseline_root(settings, baseline.root)
    except (BaselineIntegrityError, BaselineNotFoundError) as exc:
        event = store.add_event(
            baseline_generation="UNTRUSTED",
            event_type="BASELINE_INTEGRITY_FAILURE",
            path=str(settings.baseline_path),
            severity="CRITICAL",
            details={"reason": str(exc)},
            queue_jira=settings.jira.enabled,
        )
        logger.critical("Baseline verification failed: %s", exc)

        if event and deliver and settings.jira.enabled:
            client = JiraClient(settings.jira)
            process_pending_deliveries(
                store,
                client,
                settings.jira.max_attempts,
            )
        raise

    scan = scan_tree(settings.monitor_path, settings.exclude_patterns)
    detections = detect_changes(baseline, scan)

    created = 0
    for detection in detections:
        event = store.add_event(
            baseline_generation=baseline.generation,
            event_type=detection.event_type,
            path=detection.path,
            severity=detection.severity,
            old_state=detection.old_state,
            new_state=detection.new_state,
            details=detection.details,
            queue_jira=settings.jira.enabled,
        )
        if event:
            created += 1
            logger.warning(
                "Detection %s severity=%s path=%s event_id=%s",
                event.event_type,
                event.severity,
                event.path,
                event.id,
            )

    delivery = {
        "delivered": 0,
        "retry": 0,
        "dead_letter": 0,
    }
    if deliver and settings.jira.enabled:
        delivery = process_pending_deliveries(
            store,
            JiraClient(settings.jira),
            settings.jira.max_attempts,
        )

    return ScanSummary(
        detections=len(detections),
        new_events=created,
        delivered=delivery["delivered"],
        retrying=delivery["retry"],
        dead_letter=delivery["dead_letter"],
    )


def retry_pending(settings: Settings) -> dict[str, int]:
    if not settings.jira.enabled:
        raise RuntimeError("Jira delivery is disabled")
    store = _store(settings)
    return process_pending_deliveries(
        store,
        JiraClient(settings.jira),
        settings.jira.max_attempts,
    )


def verify_state(settings: Settings) -> tuple[bool, list[str]]:
    messages: list[str] = []
    ok = True

    try:
        baseline = load_baseline(
            settings.baseline_path,
            settings.integrity_key,
        )
        _assert_baseline_root(settings, baseline.root)
        messages.append(
            "Baseline signature valid "
            f"(generation {baseline.generation}, {len(baseline.files)} files)"
        )
    except (BaselineIntegrityError, BaselineNotFoundError) as exc:
        ok = False
        messages.append(f"Baseline verification failed: {exc}")

    chain_ok, chain_message = _store(settings).verify_chain()
    ok = ok and chain_ok
    messages.append(chain_message)

    return ok, messages


def monitor_forever(settings: Settings) -> None:
    logger.info(
        "Monitoring %s every %d seconds",
        settings.monitor_path,
        settings.interval_seconds,
    )

    while True:
        summary = scan_once(settings)
        logger.info(
            (
                "Scan complete detections=%d new_events=%d delivered=%d "
                "retrying=%d dead_letter=%d"
            ),
            summary.detections,
            summary.new_events,
            summary.delivered,
            summary.retrying,
            summary.dead_letter,
        )
        time.sleep(settings.interval_seconds)
