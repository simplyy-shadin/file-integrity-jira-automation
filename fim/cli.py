from __future__ import annotations

import argparse
import json
import logging
from dataclasses import asdict

from .baseline import BaselineError
from .config import ConfigurationError, Settings
from .events import EventStore
from .jira import JiraClient
from .logging_utils import configure_logging
from .service import (
    accept_current_state,
    initialize_baseline,
    monitor_forever,
    retry_pending,
    scan_once,
    verify_state,
)


logger = logging.getLogger(__name__)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fim-monitor",
        description=(
            "Tamper-evident file integrity monitoring with durable "
            "security events and Jira incident automation."
        ),
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose console logging.",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    baseline = subparsers.add_parser(
        "baseline",
        help="Initialize or explicitly accept trusted file state.",
    )
    baseline_commands = baseline.add_subparsers(
        dest="baseline_command",
        required=True,
    )

    baseline_init = baseline_commands.add_parser(
        "init",
        help="Create the first signed baseline without generating incidents.",
    )
    baseline_init.add_argument(
        "--force",
        action="store_true",
        help="Replace an existing baseline intentionally.",
    )

    baseline_accept = baseline_commands.add_parser(
        "accept",
        help="Accept the current filesystem as the new trusted baseline.",
    )
    baseline_accept.add_argument(
        "--reason",
        required=True,
        help="Audit reason for accepting detected changes.",
    )

    scan = subparsers.add_parser(
        "scan",
        help="Run one integrity scan.",
    )
    scan.add_argument(
        "--no-deliver",
        action="store_true",
        help="Persist detections but do not attempt Jira delivery.",
    )

    subparsers.add_parser(
        "monitor",
        help="Continuously scan at FIM_INTERVAL_SECONDS.",
    )
    subparsers.add_parser(
        "verify",
        help="Verify the signed baseline and tamper-evident event chain.",
    )

    events = subparsers.add_parser(
        "events",
        help="Display recent immutable security events as JSON lines.",
    )
    events.add_argument(
        "--limit",
        type=int,
        default=20,
        help="Maximum events to display (default: 20).",
    )

    subparsers.add_parser(
        "retry",
        help="Retry due Jira deliveries without running a new scan.",
    )

    jira = subparsers.add_parser(
        "jira",
        help="Jira integration operations.",
    )
    jira_commands = jira.add_subparsers(
        dest="jira_command",
        required=True,
    )
    jira_commands.add_parser(
        "check",
        help="Validate Jira credentials and connectivity.",
    )

    subparsers.add_parser(
        "status",
        help="Show local delivery queue status and integrity verification.",
    )

    return parser


def _print_scan_summary(summary) -> None:
    print(
        json.dumps(
            {
                "detections": summary.detections,
                "new_events": summary.new_events,
                "delivered": summary.delivered,
                "retrying": summary.retrying,
                "dead_letter": summary.dead_letter,
            },
            sort_keys=True,
        )
    )


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        settings = Settings.from_env()
        configure_logging(settings.state_dir, verbose=args.verbose)

        if args.command == "baseline":
            if args.baseline_command == "init":
                count = initialize_baseline(
                    settings,
                    force=args.force,
                )
                print(f"Signed baseline initialized with {count} files.")
                return 0

            count = accept_current_state(
                settings,
                reason=args.reason,
            )
            print(f"Accepted new signed baseline with {count} files.")
            return 0

        if args.command == "scan":
            summary = scan_once(
                settings,
                deliver=not args.no_deliver,
            )
            _print_scan_summary(summary)
            return 0

        if args.command == "monitor":
            try:
                monitor_forever(settings)
            except KeyboardInterrupt:
                logger.info("Monitor stopped by operator")
                print("Monitor stopped.")
            return 0

        if args.command == "verify":
            ok, messages = verify_state(settings)
            for message in messages:
                print(message)
            return 0 if ok else 2

        if args.command == "events":
            limit = min(max(args.limit, 1), 500)
            store = EventStore(
                settings.database_path,
                settings.integrity_key,
            )
            for event in store.list_events(limit=limit):
                print(json.dumps(asdict(event), sort_keys=True))
            return 0

        if args.command == "retry":
            summary = retry_pending(settings)
            print(json.dumps(summary, sort_keys=True))
            return 0

        if args.command == "jira" and args.jira_command == "check":
            if not settings.jira.enabled:
                raise RuntimeError("Jira delivery is disabled")
            profile = JiraClient(settings.jira).validate_connection()
            display_name = profile.get("displayName") or profile.get("accountId")
            print(f"Jira connection valid for {display_name}.")
            return 0

        if args.command == "status":
            ok, messages = verify_state(settings)
            store = EventStore(
                settings.database_path,
                settings.integrity_key,
            )
            print(
                json.dumps(
                    {
                        "integrity_ok": ok,
                        "verification": messages,
                        "delivery_status": store.delivery_status_counts(),
                    },
                    sort_keys=True,
                )
            )
            return 0 if ok else 2

        parser.error("Unsupported command")
        return 2

    except (ConfigurationError, BaselineError, RuntimeError, ValueError) as exc:
        logging.getLogger(__name__).error("%s", exc)
        print(f"ERROR: {exc}")
        return 2
