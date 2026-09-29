from fim.baseline import Baseline
from fim.detection import detect_changes
from fim.scanner import ScanError, ScanResult


def snapshot(
    path,
    sha="a" * 64,
    mode="0o644",
    uid=1000,
    gid=1000,
    file_type="file",
):
    return {
        "path": path,
        "sha256": sha,
        "size": 10,
        "mode": mode,
        "uid": uid,
        "gid": gid,
        "mtime_ns": 1,
        "file_type": file_type,
    }


def baseline(files):
    return Baseline(
        generation="baseline-1",
        root="/tmp/protected",
        hash_algorithm="sha256",
        created_at="2026-09-30T00:00:00+00:00",
        files=files,
    )


def test_added_file_is_medium_detection():
    detections = detect_changes(
        baseline({}),
        ScanResult(files={"new.txt": snapshot("new.txt")}, errors=()),
    )

    assert [(item.event_type, item.severity) for item in detections] == [
        ("ADDED", "MEDIUM")
    ]


def test_content_change_is_high_detection():
    detections = detect_changes(
        baseline({"app.py": snapshot("app.py")}),
        ScanResult(
            files={"app.py": snapshot("app.py", sha="b" * 64)},
            errors=(),
        ),
    )

    assert detections[0].event_type == "MODIFIED"
    assert detections[0].severity == "HIGH"
    assert detections[0].details["changes"] == ["content"]


def test_permission_change_is_metadata_detection():
    detections = detect_changes(
        baseline({"script.sh": snapshot("script.sh", mode="0o644")}),
        ScanResult(
            files={"script.sh": snapshot("script.sh", mode="0o755")},
            errors=(),
        ),
    )

    assert detections[0].event_type == "METADATA_CHANGED"
    assert detections[0].details["changes"] == ["mode"]


def test_symlink_target_change_has_specific_detection():
    detections = detect_changes(
        baseline(
            {
                "current": snapshot(
                    "current",
                    sha="a" * 64,
                    file_type="symlink",
                )
            }
        ),
        ScanResult(
            files={
                "current": snapshot(
                    "current",
                    sha="b" * 64,
                    file_type="symlink",
                )
            },
            errors=(),
        ),
    )

    assert detections[0].event_type == "SYMLINK_CHANGED"


def test_deleted_file_is_high_detection():
    detections = detect_changes(
        baseline({"removed.txt": snapshot("removed.txt")}),
        ScanResult(files={}, errors=()),
    )

    assert detections[0].event_type == "DELETED"
    assert detections[0].severity == "HIGH"


def test_read_error_is_not_misclassified_as_deletion():
    detections = detect_changes(
        baseline({"secret.txt": snapshot("secret.txt")}),
        ScanResult(
            files={},
            errors=(
                ScanError(
                    path="secret.txt",
                    reason="PermissionError: denied",
                ),
            ),
        ),
    )

    assert [item.event_type for item in detections] == ["SCAN_ERROR"]


def test_directory_walk_error_suppresses_child_deletion():
    detections = detect_changes(
        baseline({"secure/a.txt": snapshot("secure/a.txt")}),
        ScanResult(
            files={},
            errors=(
                ScanError(
                    path="secure",
                    reason="PermissionError: denied",
                    is_scope=True,
                ),
            ),
        ),
    )

    assert [item.event_type for item in detections] == ["SCAN_ERROR"]


def test_file_type_change_is_high_modification():
    detections = detect_changes(
        baseline({"value": snapshot("value", file_type="file")}),
        ScanResult(
            files={"value": snapshot("value", file_type="symlink")},
            errors=(),
        ),
    )

    assert detections[0].event_type == "MODIFIED"
    assert detections[0].details["changes"] == ["file_type"]
