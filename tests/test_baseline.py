import json

import pytest

from fim.baseline import (
    BaselineIntegrityError,
    BaselineNotFoundError,
    build_baseline,
    load_baseline,
    save_baseline,
)


def test_signed_baseline_round_trip(settings):
    files = {
        "config.ini": {
            "path": "config.ini",
            "sha256": "a" * 64,
            "size": 10,
            "mode": "0o644",
            "uid": 1000,
            "gid": 1000,
            "mtime_ns": 1,
            "file_type": "file",
        }
    }
    baseline = build_baseline(settings.monitor_path, files)

    save_baseline(
        settings.baseline_path,
        baseline,
        settings.integrity_key,
    )
    loaded = load_baseline(
        settings.baseline_path,
        settings.integrity_key,
    )

    assert loaded.generation == baseline.generation
    assert loaded.files == files
    assert loaded.root == str(settings.monitor_path.resolve())


def test_baseline_tampering_is_detected(settings):
    baseline = build_baseline(settings.monitor_path, {})
    save_baseline(
        settings.baseline_path,
        baseline,
        settings.integrity_key,
    )

    document = json.loads(settings.baseline_path.read_text())
    document["payload"]["files"]["backdoor"] = {"sha256": "0" * 64}
    settings.baseline_path.write_text(json.dumps(document))

    with pytest.raises(BaselineIntegrityError):
        load_baseline(
            settings.baseline_path,
            settings.integrity_key,
        )


def test_wrong_hmac_key_cannot_verify_baseline(settings):
    baseline = build_baseline(settings.monitor_path, {})
    save_baseline(
        settings.baseline_path,
        baseline,
        settings.integrity_key,
    )

    with pytest.raises(BaselineIntegrityError):
        load_baseline(
            settings.baseline_path,
            b"x" * 32,
        )


def test_missing_baseline_has_explicit_error(settings):
    with pytest.raises(BaselineNotFoundError):
        load_baseline(
            settings.baseline_path,
            settings.integrity_key,
        )


def test_malformed_baseline_is_rejected(settings):
    settings.state_dir.mkdir(parents=True)
    settings.baseline_path.write_text("{not valid json")

    with pytest.raises(BaselineIntegrityError):
        load_baseline(
            settings.baseline_path,
            settings.integrity_key,
        )
