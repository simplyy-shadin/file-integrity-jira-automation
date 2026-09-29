import json
from dataclasses import replace

import fim.cli as cli
from fim.events import EventStore
from fim.service import ScanSummary


def configure_cli(monkeypatch, settings):
    monkeypatch.setattr(
        cli.Settings,
        "from_env",
        staticmethod(lambda: settings),
    )
    monkeypatch.setattr(
        cli,
        "configure_logging",
        lambda *args, **kwargs: None,
    )


def test_cli_baseline_init(monkeypatch, capsys, settings):
    configure_cli(monkeypatch, settings)
    monkeypatch.setattr(cli, "initialize_baseline", lambda settings, force=False: 3)

    code = cli.main(["baseline", "init"])

    assert code == 0
    assert "3 files" in capsys.readouterr().out


def test_cli_baseline_accept(monkeypatch, capsys, settings):
    configure_cli(monkeypatch, settings)
    monkeypatch.setattr(
        cli,
        "accept_current_state",
        lambda settings, reason: 4,
    )

    code = cli.main(
        [
            "baseline",
            "accept",
            "--reason",
            "Approved change",
        ]
    )

    assert code == 0
    assert "4 files" in capsys.readouterr().out


def test_cli_scan_prints_machine_readable_summary(monkeypatch, capsys, settings):
    configure_cli(monkeypatch, settings)
    monkeypatch.setattr(
        cli,
        "scan_once",
        lambda settings, deliver=True: ScanSummary(
            detections=2,
            new_events=1,
            delivered=1,
            retrying=0,
            dead_letter=0,
        ),
    )

    code = cli.main(["scan"])
    output = json.loads(capsys.readouterr().out)

    assert code == 0
    assert output["new_events"] == 1
    assert output["delivered"] == 1


def test_cli_verify_returns_nonzero_when_integrity_fails(
    monkeypatch,
    capsys,
    settings,
):
    configure_cli(monkeypatch, settings)
    monkeypatch.setattr(
        cli,
        "verify_state",
        lambda settings: (False, ["baseline invalid", "chain invalid"]),
    )

    code = cli.main(["verify"])

    assert code == 2
    assert "baseline invalid" in capsys.readouterr().out


def test_cli_events_outputs_json_lines(monkeypatch, capsys, settings):
    configure_cli(monkeypatch, settings)
    store = EventStore(settings.database_path, settings.integrity_key)
    store.add_event(
        baseline_generation="g1",
        event_type="MODIFIED",
        path="app.py",
        severity="HIGH",
        queue_jira=False,
    )

    code = cli.main(["events", "--limit", "5"])
    line = capsys.readouterr().out.strip()

    assert code == 0
    assert json.loads(line)["event_type"] == "MODIFIED"


def test_cli_retry(monkeypatch, capsys, settings):
    configure_cli(monkeypatch, settings)
    monkeypatch.setattr(
        cli,
        "retry_pending",
        lambda settings: {
            "delivered": 1,
            "retry": 0,
            "dead_letter": 0,
        },
    )

    code = cli.main(["retry"])

    assert code == 0
    assert json.loads(capsys.readouterr().out)["delivered"] == 1


def test_cli_monitor_handles_operator_interrupt(monkeypatch, capsys, settings):
    configure_cli(monkeypatch, settings)

    def stop(_settings):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "monitor_forever", stop)

    code = cli.main(["monitor"])

    assert code == 0
    assert "Monitor stopped" in capsys.readouterr().out


def test_cli_jira_check(monkeypatch, capsys, settings):
    enabled = replace(
        settings,
        jira=replace(
            settings.jira,
            enabled=True,
            url="https://example.atlassian.net",
            email="analyst@example.com",
            api_token="token",
            project_key="SEC",
        ),
    )
    configure_cli(monkeypatch, enabled)

    class FakeClient:
        def __init__(self, jira):
            self.jira = jira

        def validate_connection(self):
            return {"displayName": "SOC Analyst"}

    monkeypatch.setattr(cli, "JiraClient", FakeClient)

    code = cli.main(["jira", "check"])

    assert code == 0
    assert "SOC Analyst" in capsys.readouterr().out


def test_cli_status(monkeypatch, capsys, settings):
    configure_cli(monkeypatch, settings)
    monkeypatch.setattr(
        cli,
        "verify_state",
        lambda settings: (True, ["baseline valid", "chain valid"]),
    )

    code = cli.main(["status"])
    output = json.loads(capsys.readouterr().out)

    assert code == 0
    assert output["integrity_ok"] is True


def test_cli_configuration_error_is_controlled(monkeypatch, capsys):
    def fail():
        raise cli.ConfigurationError("bad configuration")

    monkeypatch.setattr(
        cli.Settings,
        "from_env",
        staticmethod(fail),
    )

    code = cli.main(["scan"])

    assert code == 2
    assert "bad configuration" in capsys.readouterr().out
