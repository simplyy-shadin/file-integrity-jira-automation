import os
from pathlib import Path

import pytest

from fim.scanner import scan_tree


def test_scanner_hashes_nested_files(settings):
    (settings.monitor_path / "nested").mkdir()
    file_path = settings.monitor_path / "nested" / "config.txt"
    file_path.write_text("secure configuration")

    result = scan_tree(
        settings.monitor_path,
        settings.exclude_patterns,
    )

    snapshot = result.files["nested/config.txt"]
    assert snapshot["file_type"] == "file"
    assert snapshot["size"] == len("secure configuration")
    assert len(snapshot["sha256"]) == 64
    assert result.errors == ()


def test_scanner_excludes_configured_patterns(settings):
    (settings.monitor_path / ".git").mkdir()
    (settings.monitor_path / ".git" / "index").write_text("ignored")
    (settings.monitor_path / "visible.txt").write_text("tracked")

    result = scan_tree(
        settings.monitor_path,
        settings.exclude_patterns,
    )

    assert "visible.txt" in result.files
    assert ".git/index" not in result.files


@pytest.mark.skipif(
    not hasattr(os, "symlink"),
    reason="symlink support is unavailable",
)
def test_scanner_hashes_symlink_target_without_following_it(settings):
    outside = settings.monitor_path.parent / "outside-secret.txt"
    outside.write_text("outside contents")
    link = settings.monitor_path / "linked"
    os.symlink(outside, link)

    result = scan_tree(
        settings.monitor_path,
        settings.exclude_patterns,
    )

    snapshot = result.files["linked"]
    assert snapshot["file_type"] == "symlink"
    assert snapshot["size"] > 0


def test_scanner_records_unreadable_file_error(monkeypatch, settings):
    file_path = settings.monitor_path / "protected.txt"
    file_path.write_text("content")

    original_open = Path.open

    def deny_open(self, *args, **kwargs):
        if self.name == "protected.txt":
            raise PermissionError("denied")
        return original_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", deny_open)

    result = scan_tree(
        settings.monitor_path,
        settings.exclude_patterns,
    )

    assert "protected.txt" not in result.files
    assert result.errors
    assert result.errors[0].path == "protected.txt"
