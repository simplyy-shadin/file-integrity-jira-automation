from __future__ import annotations

import fnmatch
import hashlib
import os
import stat
from dataclasses import asdict, dataclass
from pathlib import Path


class UnstableFileError(OSError):
    """Raised when a file changes while it is being hashed."""


@dataclass(frozen=True)
class FileSnapshot:
    path: str
    sha256: str
    size: int
    mode: str
    uid: int | None
    gid: int | None
    mtime_ns: int
    file_type: str

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class ScanError:
    path: str
    reason: str
    is_scope: bool = False


@dataclass(frozen=True)
class ScanResult:
    files: dict[str, dict]
    errors: tuple[ScanError, ...]


def _matches_exclude(relative_path: str, patterns: tuple[str, ...]) -> bool:
    normalized = relative_path.replace(os.sep, "/")
    return any(
        fnmatch.fnmatch(normalized, pattern)
        or normalized == pattern.rstrip("/**")
        for pattern in patterns
    )


def _hash_regular_file(path: Path, attempts: int = 2) -> tuple[str, os.stat_result]:
    last_error: Exception | None = None

    for _ in range(attempts):
        flags = os.O_RDONLY
        flags |= getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)

        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            last_error = exc
            continue

        digest = hashlib.sha256()
        try:
            with os.fdopen(descriptor, "rb", closefd=True) as handle:
                before = os.fstat(handle.fileno())
                if not stat.S_ISREG(before.st_mode):
                    raise OSError(f"Refusing to hash non-regular file: {path}")

                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)

                after = os.fstat(handle.fileno())
        except OSError as exc:
            last_error = exc
            continue

        if (
            before.st_size == after.st_size
            and before.st_mtime_ns == after.st_mtime_ns
            and before.st_ino == after.st_ino
            and before.st_dev == after.st_dev
        ):
            return digest.hexdigest(), after

        last_error = UnstableFileError(
            f"File changed while hashing: {path}"
        )

    if last_error:
        raise last_error
    raise UnstableFileError(f"Could not hash stable file: {path}")


def _snapshot(path: Path, relative_path: str) -> FileSnapshot:
    metadata = path.lstat()

    if stat.S_ISLNK(metadata.st_mode):
        target = os.readlink(path)
        digest = hashlib.sha256(
            ("SYMLINK:" + target).encode("utf-8", errors="surrogateescape")
        ).hexdigest()
        file_type = "symlink"
        size = len(target.encode("utf-8", errors="surrogateescape"))
    elif stat.S_ISREG(metadata.st_mode):
        digest, metadata = _hash_regular_file(path)
        file_type = "file"
        size = metadata.st_size
    else:
        digest = hashlib.sha256(
            f"SPECIAL:{stat.S_IFMT(metadata.st_mode)}".encode()
        ).hexdigest()
        file_type = "special"
        size = metadata.st_size

    return FileSnapshot(
        path=relative_path,
        sha256=digest,
        size=size,
        mode=oct(stat.S_IMODE(metadata.st_mode)),
        uid=getattr(metadata, "st_uid", None),
        gid=getattr(metadata, "st_gid", None),
        mtime_ns=metadata.st_mtime_ns,
        file_type=file_type,
    )


def scan_tree(root: Path, exclude_patterns: tuple[str, ...]) -> ScanResult:
    root = root.resolve()
    files: dict[str, dict] = {}
    errors: list[ScanError] = []

    def on_walk_error(exc: OSError) -> None:
        filename = Path(exc.filename).resolve() if exc.filename else root
        try:
            relative = filename.relative_to(root).as_posix()
        except ValueError:
            relative = str(filename)
        errors.append(
            ScanError(
                path=relative or ".",
                reason=f"{type(exc).__name__}: {exc}",
                is_scope=True,
            )
        )

    for current_root, directories, filenames in os.walk(
        root,
        topdown=True,
        followlinks=False,
        onerror=on_walk_error,
    ):
        current = Path(current_root)

        retained_dirs: list[str] = []
        for directory in directories:
            full_path = current / directory
            relative = full_path.relative_to(root).as_posix()

            if _matches_exclude(relative, exclude_patterns):
                continue

            if full_path.is_symlink():
                try:
                    files[relative] = _snapshot(full_path, relative).as_dict()
                except OSError as exc:
                    errors.append(
                        ScanError(
                            path=relative,
                            reason=f"{type(exc).__name__}: {exc}",
                        )
                    )
                continue

            retained_dirs.append(directory)

        directories[:] = retained_dirs

        for filename in filenames:
            full_path = current / filename
            relative = full_path.relative_to(root).as_posix()

            if _matches_exclude(relative, exclude_patterns):
                continue

            try:
                files[relative] = _snapshot(full_path, relative).as_dict()
            except OSError as exc:
                errors.append(
                    ScanError(
                        path=relative,
                        reason=f"{type(exc).__name__}: {exc}",
                    )
                )

    return ScanResult(files=files, errors=tuple(errors))
