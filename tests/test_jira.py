from dataclasses import dataclass

import requests

from fim.events import EventStore
from fim.jira import (
    JiraClient,
    JiraDeliveryError,
    process_pending_deliveries,
)


@dataclass
class FakeResponse:
    status_code: int
    body: dict | None = None
    text: str = ""
    headers: dict | None = None

    def json(self):
        return self.body or {}

    def __post_init__(self):
        if self.headers is None:
            self.headers = {}


class FakeSession:
    def __init__(self, post_response=None, get_response=None, post_error=None):
        self.post_response = post_response
        self.get_response = get_response
        self.post_error = post_error
        self.last_post = None

    def post(self, url, **kwargs):
        self.last_post = (url, kwargs)
        if self.post_error:
            raise self.post_error
        return self.post_response

    def get(self, url, **kwargs):
        return self.get_response


def sample_event(store):
    return store.add_event(
        baseline_generation="g1",
        event_type="MODIFIED",
        path="etc/app.conf",
        severity="HIGH",
        old_state={"sha256": "a" * 64},
        new_state={"sha256": "b" * 64},
        details={"changes": ["content"]},
    )


def test_jira_create_issue_uses_v3_adf_and_event_marker(jira_settings, settings):
    store = EventStore(settings.database_path, settings.integrity_key)
    event = sample_event(store)
    session = FakeSession(
        post_response=FakeResponse(
            status_code=201,
            body={"key": "SEC-101"},
        )
    )

    key = JiraClient(jira_settings, session=session).create_issue(event)

    assert key == "SEC-101"
    url, kwargs = session.last_post
    assert url.endswith("/rest/api/3/issue")
    description = kwargs["json"]["fields"]["description"]
    assert description["type"] == "doc"
    assert event.id in str(description)


def test_jira_429_is_retryable_and_respects_retry_after(
    jira_settings,
    settings,
):
    store = EventStore(settings.database_path, settings.integrity_key)
    event = sample_event(store)
    session = FakeSession(
        post_response=FakeResponse(
            status_code=429,
            text="rate limited",
            headers={"Retry-After": "17"},
        )
    )

    client = JiraClient(jira_settings, session=session)

    try:
        client.create_issue(event)
    except JiraDeliveryError as exc:
        assert exc.retryable is True
        assert exc.retry_after == 17
    else:
        raise AssertionError("Expected JiraDeliveryError")


def test_jira_400_is_non_retryable(jira_settings, settings):
    store = EventStore(settings.database_path, settings.integrity_key)
    event = sample_event(store)
    session = FakeSession(
        post_response=FakeResponse(
            status_code=400,
            text="bad payload",
        )
    )

    try:
        JiraClient(jira_settings, session=session).create_issue(event)
    except JiraDeliveryError as exc:
        assert exc.retryable is False
    else:
        raise AssertionError("Expected JiraDeliveryError")


def test_jira_timeout_is_retryable(jira_settings, settings):
    store = EventStore(settings.database_path, settings.integrity_key)
    event = sample_event(store)
    session = FakeSession(
        post_error=requests.Timeout("network timeout")
    )

    try:
        JiraClient(jira_settings, session=session).create_issue(event)
    except JiraDeliveryError as exc:
        assert exc.retryable is True
    else:
        raise AssertionError("Expected JiraDeliveryError")


def test_delivery_processor_marks_success(jira_settings, settings):
    store = EventStore(settings.database_path, settings.integrity_key)
    sample_event(store)
    client = JiraClient(
        jira_settings,
        session=FakeSession(
            post_response=FakeResponse(
                status_code=201,
                body={"key": "SEC-1"},
            )
        ),
    )

    summary = process_pending_deliveries(store, client, max_attempts=3)

    assert summary == {
        "delivered": 1,
        "retry": 0,
        "dead_letter": 0,
    }
    assert store.delivery_status_counts() == {"delivered": 1}


def test_delivery_processor_dead_letters_permanent_failure(
    jira_settings,
    settings,
):
    store = EventStore(settings.database_path, settings.integrity_key)
    sample_event(store)
    client = JiraClient(
        jira_settings,
        session=FakeSession(
            post_response=FakeResponse(
                status_code=401,
                text="unauthorized",
            )
        ),
    )

    summary = process_pending_deliveries(store, client, max_attempts=3)

    assert summary["dead_letter"] == 1
    assert store.delivery_status_counts() == {"dead_letter": 1}


def test_jira_connection_check(jira_settings):
    session = FakeSession(
        get_response=FakeResponse(
            status_code=200,
            body={"displayName": "SOC Analyst"},
        )
    )

    profile = JiraClient(
        jira_settings,
        session=session,
    ).validate_connection()

    assert profile["displayName"] == "SOC Analyst"


def test_jira_connection_network_failure_is_retryable(jira_settings):
    class FailingSession:
        def get(self, *args, **kwargs):
            raise requests.ConnectionError("offline")

    try:
        JiraClient(
            jira_settings,
            session=FailingSession(),
        ).validate_connection()
    except JiraDeliveryError as exc:
        assert exc.retryable is True
    else:
        raise AssertionError("Expected JiraDeliveryError")


def test_jira_connection_500_is_retryable(jira_settings):
    session = FakeSession(
        get_response=FakeResponse(
            status_code=503,
            text="unavailable",
        )
    )

    try:
        JiraClient(
            jira_settings,
            session=session,
        ).validate_connection()
    except JiraDeliveryError as exc:
        assert exc.retryable is True
    else:
        raise AssertionError("Expected JiraDeliveryError")


def test_delivery_processor_schedules_retry_for_server_error(
    jira_settings,
    settings,
):
    store = EventStore(settings.database_path, settings.integrity_key)
    sample_event(store)
    client = JiraClient(
        jira_settings,
        session=FakeSession(
            post_response=FakeResponse(
                status_code=503,
                text="unavailable",
            )
        ),
    )

    summary = process_pending_deliveries(store, client, max_attempts=3)

    assert summary["retry"] == 1
    assert store.delivery_status_counts() == {"retry": 1}
