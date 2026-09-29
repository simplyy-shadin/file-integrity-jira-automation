import json

import pytest

from fim.baseline import BaselineIntegrityError
from fim.events import EventStore
from fim.service import (
    accept_current_state,
    initialize_baseline,
    scan_once,
    verify_state,
)


def event_types(settings):
    store = EventStore(settings.database_path, settings.integrity_key)
    return [event.event_type for event in store.list_events(limit=100)]


def test_initialization_creates_trusted_baseline_without_incidents(settings):
    (settings.monitor_path / "app.conf").write_text("safe=true")

    count = initialize_baseline(settings)

    assert count == 1
    assert settings.baseline_path.exists()
    assert event_types(settings) == ["BASELINE_INITIALIZED"]

    summary = scan_once(settings)
    assert summary.detections == 0
    assert summary.new_events == 0


def test_modification_creates_one_durable_event_until_baseline_changes(settings):
    target = settings.monitor_path / "app.conf"
    target.write_text("safe=true")
    initialize_baseline(settings)

    target.write_text("safe=false")
    first = scan_once(settings)
    second = scan_once(settings)

    assert first.detections == 1
    assert first.new_events == 1
    assert second.detections == 1
    assert second.new_events == 0
    assert event_types(settings)[0] == "MODIFIED"


def test_accepting_change_is_explicit_and_audited(settings):
    target = settings.monitor_path / "app.conf"
    target.write_text("version=1")
    initialize_baseline(settings)

    target.write_text("version=2")
    assert scan_once(settings).new_events == 1

    count = accept_current_state(
        settings,
        reason="Approved configuration rollout SEC-123",
    )
    clean = scan_once(settings)

    assert count == 1
    assert clean.detections == 0
    assert "BASELINE_ACCEPTED" in event_types(settings)


def test_deleted_file_is_not_silently_accepted(settings):
    target = settings.monitor_path / "important.txt"
    target.write_text("critical")
    initialize_baseline(settings)

    target.unlink()
    first = scan_once(settings)
    second = scan_once(settings)

    assert first.new_events == 1
    assert second.new_events == 0
    assert event_types(settings)[0] == "DELETED"


def test_tampered_baseline_aborts_scan_and_records_critical_event(settings):
    target = settings.monitor_path / "important.txt"
    target.write_text("critical")
    initialize_baseline(settings)

    document = json.loads(settings.baseline_path.read_text())
    document["payload"]["files"] = {}
    settings.baseline_path.write_text(json.dumps(document))

    with pytest.raises(BaselineIntegrityError):
        scan_once(settings)

    events = EventStore(
        settings.database_path,
        settings.integrity_key,
    ).list_events()
    assert events[0].event_type == "BASELINE_INTEGRITY_FAILURE"
    assert events[0].severity == "CRITICAL"


def test_verify_checks_both_baseline_and_event_chain(settings):
    (settings.monitor_path / "app.conf").write_text("safe")
    initialize_baseline(settings)

    ok, messages = verify_state(settings)

    assert ok is True
    assert "Baseline signature valid" in messages[0]
    assert "Verified" in messages[1]


def test_force_is_required_to_replace_existing_baseline(settings):
    initialize_baseline(settings)

    with pytest.raises(RuntimeError):
        initialize_baseline(settings)

    initialize_baseline(settings, force=True)
    assert event_types(settings)[0] == "BASELINE_INITIALIZED"
