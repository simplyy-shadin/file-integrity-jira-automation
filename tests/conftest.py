from pathlib import Path

import pytest

from fim.config import JiraSettings, Settings


@pytest.fixture()
def settings(tmp_path: Path) -> Settings:
    monitored = tmp_path / "protected"
    monitored.mkdir()
    state = tmp_path / "state"

    return Settings(
        monitor_path=monitored,
        state_dir=state,
        interval_seconds=1,
        integrity_key=b"k" * 32,
        exclude_patterns=(".git", ".git/**", ".fim-state", ".fim-state/**"),
        jira=JiraSettings(
            enabled=False,
            url=None,
            email=None,
            api_token=None,
            project_key=None,
            issue_type="Task",
            timeout_seconds=1,
            max_attempts=3,
        ),
    )


@pytest.fixture()
def jira_settings() -> JiraSettings:
    return JiraSettings(
        enabled=True,
        url="https://example.atlassian.net",
        email="analyst@example.com",
        api_token="test-token",
        project_key="SEC",
        issue_type="Task",
        timeout_seconds=2,
        max_attempts=3,
    )
