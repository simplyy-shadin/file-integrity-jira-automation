from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


DEFAULT_EXCLUDES = (
    ".git",
    ".git/**",
    ".fim-state",
    ".fim-state/**",
    "__pycache__",
    "__pycache__/**",
    "*.pyc",
    "*.pyo",
)


class ConfigurationError(ValueError):
    """Raised when required configuration is invalid."""


def _as_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _as_int(name: str, value: str | None, default: int, minimum: int = 1) -> int:
    if value is None or not value.strip():
        return default
    try:
        parsed = int(value)
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be an integer") from exc
    if parsed < minimum:
        raise ConfigurationError(f"{name} must be at least {minimum}")
    return parsed


def _load_integrity_key(value: str | None) -> bytes:
    if not value:
        raise ConfigurationError(
            "FIM_INTEGRITY_KEY is required. Generate one with: "
            "python -c \"import secrets; print(secrets.token_hex(32))\""
        )
    try:
        key = bytes.fromhex(value.strip())
    except ValueError as exc:
        raise ConfigurationError(
            "FIM_INTEGRITY_KEY must be a hexadecimal string"
        ) from exc
    if len(key) < 32:
        raise ConfigurationError(
            "FIM_INTEGRITY_KEY must contain at least 32 random bytes"
        )
    return key


@dataclass(frozen=True)
class JiraSettings:
    enabled: bool
    url: str | None
    email: str | None
    api_token: str | None
    project_key: str | None
    issue_type: str
    timeout_seconds: int
    max_attempts: int

    def validate(self) -> None:
        if not self.enabled:
            return
        required = {
            "JIRA_URL": self.url,
            "JIRA_EMAIL": self.email,
            "JIRA_API_TOKEN": self.api_token,
            "JIRA_PROJECT_KEY": self.project_key,
        }
        missing = [name for name, value in required.items() if not value]
        if missing:
            raise ConfigurationError(
                "Jira delivery is enabled but these values are missing: "
                + ", ".join(missing)
            )
        if not str(self.url).startswith("https://"):
            raise ConfigurationError("JIRA_URL must use https://")


@dataclass(frozen=True)
class Settings:
    monitor_path: Path
    state_dir: Path
    interval_seconds: int
    integrity_key: bytes
    exclude_patterns: tuple[str, ...]
    jira: JiraSettings

    @property
    def baseline_path(self) -> Path:
        return self.state_dir / "baseline.json"

    @property
    def database_path(self) -> Path:
        return self.state_dir / "events.db"

    @classmethod
    def from_env(cls) -> "Settings":
        load_dotenv()

        monitor_value = os.getenv("FIM_MONITOR_PATH")
        if not monitor_value:
            raise ConfigurationError("FIM_MONITOR_PATH is required")

        monitor_path = Path(monitor_value).expanduser().resolve()
        state_dir = Path(
            os.getenv("FIM_STATE_DIR", ".fim-state")
        ).expanduser().resolve()

        excludes = list(DEFAULT_EXCLUDES)
        custom = os.getenv("FIM_EXCLUDE_PATTERNS", "")
        excludes.extend(
            pattern.strip()
            for pattern in custom.split(",")
            if pattern.strip()
        )

        try:
            relative_state = state_dir.relative_to(monitor_path).as_posix()
        except ValueError:
            relative_state = None

        if relative_state and relative_state != ".":
            excludes.extend((relative_state, f"{relative_state}/**"))

        jira = JiraSettings(
            enabled=_as_bool(os.getenv("JIRA_ENABLED"), default=True),
            url=(os.getenv("JIRA_URL") or "").rstrip("/") or None,
            email=os.getenv("JIRA_EMAIL") or None,
            api_token=os.getenv("JIRA_API_TOKEN") or None,
            project_key=os.getenv("JIRA_PROJECT_KEY") or None,
            issue_type=os.getenv("JIRA_ISSUE_TYPE", "Task"),
            timeout_seconds=_as_int(
                "JIRA_TIMEOUT_SECONDS",
                os.getenv("JIRA_TIMEOUT_SECONDS"),
                10,
            ),
            max_attempts=_as_int(
                "JIRA_MAX_ATTEMPTS",
                os.getenv("JIRA_MAX_ATTEMPTS"),
                5,
            ),
        )
        jira.validate()

        settings = cls(
            monitor_path=monitor_path,
            state_dir=state_dir,
            interval_seconds=_as_int(
                "FIM_INTERVAL_SECONDS",
                os.getenv("FIM_INTERVAL_SECONDS"),
                60,
            ),
            integrity_key=_load_integrity_key(
                os.getenv("FIM_INTEGRITY_KEY")
            ),
            exclude_patterns=tuple(dict.fromkeys(excludes)),
            jira=jira,
        )
        settings.validate()
        return settings

    def validate(self) -> None:
        if not self.monitor_path.exists():
            raise ConfigurationError(
                f"Monitored path does not exist: {self.monitor_path}"
            )
        if not self.monitor_path.is_dir():
            raise ConfigurationError(
                f"Monitored path is not a directory: {self.monitor_path}"
            )
