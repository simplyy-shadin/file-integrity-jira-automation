import pytest

from fim.config import ConfigurationError, Settings


def base_environment(monkeypatch, tmp_path):
    monitored = tmp_path / "protected"
    monitored.mkdir()
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FIM_MONITOR_PATH", str(monitored))
    monkeypatch.setenv("FIM_INTEGRITY_KEY", "ab" * 32)
    monkeypatch.setenv("JIRA_ENABLED", "false")
    return monitored


def test_settings_load_secure_local_only_configuration(monkeypatch, tmp_path):
    monitored = base_environment(monkeypatch, tmp_path)

    settings = Settings.from_env()

    assert settings.monitor_path == monitored.resolve()
    assert settings.jira.enabled is False
    assert len(settings.integrity_key) == 32


def test_integrity_key_is_required(monkeypatch, tmp_path):
    base_environment(monkeypatch, tmp_path)
    monkeypatch.delenv("FIM_INTEGRITY_KEY")

    with pytest.raises(ConfigurationError):
        Settings.from_env()


def test_jira_enabled_requires_complete_credentials(monkeypatch, tmp_path):
    base_environment(monkeypatch, tmp_path)
    monkeypatch.setenv("JIRA_ENABLED", "true")

    with pytest.raises(ConfigurationError):
        Settings.from_env()


def test_jira_url_requires_https(monkeypatch, tmp_path):
    base_environment(monkeypatch, tmp_path)
    monkeypatch.setenv("JIRA_ENABLED", "true")
    monkeypatch.setenv("JIRA_URL", "http://example.atlassian.net")
    monkeypatch.setenv("JIRA_EMAIL", "analyst@example.com")
    monkeypatch.setenv("JIRA_API_TOKEN", "token")
    monkeypatch.setenv("JIRA_PROJECT_KEY", "SEC")

    with pytest.raises(ConfigurationError):
        Settings.from_env()


def test_state_directory_inside_monitor_is_auto_excluded(monkeypatch, tmp_path):
    monitored = base_environment(monkeypatch, tmp_path)
    state = monitored / ".security-state"
    monkeypatch.setenv("FIM_STATE_DIR", str(state))

    settings = Settings.from_env()

    assert ".security-state" in settings.exclude_patterns
    assert ".security-state/**" in settings.exclude_patterns
