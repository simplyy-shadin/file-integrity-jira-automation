import sqlite3

from fim.events import EventStore


def add_sample(store, generation="g1", sha="b" * 64):
    return store.add_event(
        baseline_generation=generation,
        event_type="MODIFIED",
        path="app.py",
        severity="HIGH",
        old_state={"sha256": "a" * 64},
        new_state={"sha256": sha},
        details={"changes": ["content"]},
    )


def test_event_store_deduplicates_same_detection(settings):
    store = EventStore(
        settings.database_path,
        settings.integrity_key,
    )

    first = add_sample(store)
    second = add_sample(store)

    assert first is not None
    assert second is None
    assert len(store.list_events()) == 1


def test_new_baseline_generation_allows_future_same_change(settings):
    store = EventStore(
        settings.database_path,
        settings.integrity_key,
    )

    assert add_sample(store, generation="g1")
    assert add_sample(store, generation="g2")
    assert len(store.list_events()) == 2


def test_event_chain_verifies_and_detects_database_tampering(settings):
    store = EventStore(
        settings.database_path,
        settings.integrity_key,
    )
    add_sample(store)
    store.add_event(
        baseline_generation="g1",
        event_type="DELETED",
        path="config.ini",
        severity="HIGH",
    )

    ok, message = store.verify_chain()
    assert ok is True
    assert "Verified 2" in message

    with sqlite3.connect(settings.database_path) as connection:
        connection.execute(
            """
            UPDATE security_events
            SET severity = 'INFO'
            WHERE sequence = 1
            """
        )

    ok, message = store.verify_chain()
    assert ok is False
    assert "signature mismatch" in message.lower()


def test_delivery_state_transitions(settings):
    store = EventStore(
        settings.database_path,
        settings.integrity_key,
    )
    event = add_sample(store)

    pending = store.pending_deliveries()
    assert pending[0][1].status == "pending"

    store.mark_retry(event.id, "temporary failure", 30)
    assert store.delivery_attempts(event.id) == 1

    with sqlite3.connect(settings.database_path) as connection:
        connection.execute(
            """
            UPDATE deliveries
            SET next_attempt_at = NULL
            WHERE event_id = ?
            """,
            (event.id,),
        )

    retry = store.pending_deliveries()
    assert retry[0][1].status == "retry"

    store.mark_delivered(event.id, "SEC-42")
    assert store.delivery_status_counts() == {"delivered": 1}


def test_dead_letter_remains_durable(settings):
    store = EventStore(
        settings.database_path,
        settings.integrity_key,
    )
    event = add_sample(store)
    store.mark_dead_letter(event.id, "invalid credentials")

    assert store.delivery_status_counts() == {"dead_letter": 1}
    assert store.pending_deliveries() == []


def test_local_only_event_does_not_create_delivery(settings):
    store = EventStore(
        settings.database_path,
        settings.integrity_key,
    )
    store.add_event(
        baseline_generation="g1",
        event_type="BASELINE_INITIALIZED",
        path=".",
        severity="INFO",
        queue_jira=False,
    )

    assert store.delivery_status_counts() == {}
