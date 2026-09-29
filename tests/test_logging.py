import json
import logging

from fim.logging_utils import configure_logging


def test_configure_logging_writes_structured_json(settings):
    configure_logging(settings.state_dir)
    logger = logging.getLogger("fim.test")
    logger.warning("integrity event %s", "detected")

    for handler in logging.getLogger().handlers:
        handler.flush()

    log_path = settings.state_dir / "fim.log"
    payload = json.loads(log_path.read_text().splitlines()[-1])

    assert payload["level"] == "WARNING"
    assert payload["logger"] == "fim.test"
    assert payload["message"] == "integrity event detected"
    assert payload["timestamp"]
