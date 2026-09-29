from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Any

import requests

from .config import JiraSettings
from .events import EventStore, SecurityEvent


@dataclass(frozen=True)
class JiraDeliveryError(RuntimeError):
    message: str
    retryable: bool
    retry_after: int | None = None

    def __str__(self) -> str:
        return self.message


class JiraClient:
    def __init__(
        self,
        settings: JiraSettings,
        session: requests.Session | None = None,
    ):
        self.settings = settings
        self.session = session or requests.Session()

    def _auth(self) -> tuple[str, str]:
        return (
            str(self.settings.email),
            str(self.settings.api_token),
        )

    def validate_connection(self) -> dict[str, Any]:
        try:
            response = self.session.get(
                f"{self.settings.url}/rest/api/3/myself",
                auth=self._auth(),
                headers={"Accept": "application/json"},
                timeout=self.settings.timeout_seconds,
            )
        except requests.RequestException as exc:
            raise JiraDeliveryError(
                f"Jira connection failed: {exc}",
                retryable=True,
            ) from exc

        if response.status_code != 200:
            raise JiraDeliveryError(
                f"Jira authentication check returned HTTP {response.status_code}",
                retryable=response.status_code >= 500
                or response.status_code == 429,
                retry_after=_retry_after(response),
            )

        return response.json()

    def create_issue(self, event: SecurityEvent) -> str:
        marker = f"fim-event-{event.id[:12]}"
        summary_path = event.path if len(event.path) <= 100 else event.path[-100:]
        payload = {
            "fields": {
                "project": {"key": self.settings.project_key},
                "summary": (
                    f"[FIM][{event.severity}] {event.event_type}: "
                    f"{summary_path}"
                )[:255],
                "issuetype": {"name": self.settings.issue_type},
                "labels": ["file-integrity-monitor", marker],
                "description": _adf_description(event),
            }
        }

        try:
            response = self.session.post(
                f"{self.settings.url}/rest/api/3/issue",
                json=payload,
                auth=self._auth(),
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
                timeout=self.settings.timeout_seconds,
            )
        except requests.Timeout as exc:
            raise JiraDeliveryError(
                f"Jira request timed out: {exc}",
                retryable=True,
            ) from exc
        except requests.RequestException as exc:
            raise JiraDeliveryError(
                f"Jira request failed: {exc}",
                retryable=True,
            ) from exc

        if response.status_code == 201:
            body = response.json()
            return str(body.get("key") or body.get("id") or marker)

        retryable = response.status_code == 429 or response.status_code >= 500
        body = response.text[:1000]
        raise JiraDeliveryError(
            (
                f"Jira issue creation returned HTTP "
                f"{response.status_code}: {body}"
            ),
            retryable=retryable,
            retry_after=_retry_after(response),
        )


def _retry_after(response: requests.Response) -> int | None:
    raw = response.headers.get("Retry-After")
    if not raw:
        return None
    try:
        return max(int(float(raw)), 1)
    except ValueError:
        return None


def _text(value: Any) -> str:
    if value is None:
        return "none"
    if isinstance(value, (dict, list)):
        import json

        return json.dumps(value, sort_keys=True)
    return str(value)


def _adf_description(event: SecurityEvent) -> dict:
    lines = [
        ("Event ID", event.id),
        ("Detected", event.detected_at),
        ("Severity", event.severity),
        ("Type", event.event_type),
        ("Path", event.path),
        ("Baseline generation", event.baseline_generation),
        ("Previous state", _text(event.old_state)),
        ("Current state", _text(event.new_state)),
        ("Details", _text(event.details)),
    ]
    content = []
    for label, value in lines:
        content.append(
            {
                "type": "paragraph",
                "content": [
                    {
                        "type": "text",
                        "text": f"{label}: {value}",
                    }
                ],
            }
        )

    return {
        "type": "doc",
        "version": 1,
        "content": content,
    }


def process_pending_deliveries(
    store: EventStore,
    client: JiraClient,
    max_attempts: int,
) -> dict[str, int]:
    summary = {
        "delivered": 0,
        "retry": 0,
        "dead_letter": 0,
    }

    for event, delivery in store.pending_deliveries():
        attempts_before = delivery.attempts

        try:
            issue_key = client.create_issue(event)
        except JiraDeliveryError as exc:
            next_attempt_number = attempts_before + 1
            if not exc.retryable or next_attempt_number >= max_attempts:
                store.mark_dead_letter(event.id, str(exc))
                summary["dead_letter"] += 1
                continue

            exponential = min(300, 5 * (2**attempts_before))
            jitter = random.randint(0, 3)
            delay = exc.retry_after or (exponential + jitter)
            store.mark_retry(event.id, str(exc), delay)
            summary["retry"] += 1
            continue

        store.mark_delivered(event.id, issue_key)
        summary["delivered"] += 1

    return summary
