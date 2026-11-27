"""Atomic, inter-process-locked persistence primitives for local JSON stores.

Writes use a sibling lock file and same-directory atomic replace. The transaction
helper keeps read/modify/write under the same lock; callers must use it when they
need to update a shared JSON document rather than replace a snapshot.
"""
from __future__ import annotations

import json
import os
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Iterator, Any


@contextmanager
def file_lock(path: str | Path) -> Iterator[None]:
    """Exclusive cross-process lock associated with a data-file path."""
    target = Path(path)
    lock_path = Path(str(target) + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+b") as handle:
        if os.name == "nt":  # pragma: no cover - Windows CI/platform path
            import msvcrt
            handle.seek(0)
            if not handle.read(1):
                handle.seek(0)
                handle.write(b"0")
                handle.flush()
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
            try:
                yield
            finally:
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def atomic_write_text_locked(path: str | Path, text: str,
                             mode: int | None = None) -> None:
    """Atomic replace for callers that already hold file_lock(path)."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temp_name = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=target.parent,
            prefix=f".{target.name}.", suffix=".tmp", delete=False,
        ) as handle:
            temp_name = handle.name
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        if mode is not None:
            os.chmod(temp_name, mode)
        os.replace(temp_name, target)
        # Persist the directory entry where supported.
        try:
            dir_fd = os.open(target.parent, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:  # Windows and some filesystems do not fsync directories.
            pass
    finally:
        if temp_name and os.path.exists(temp_name):
            try:
                os.unlink(temp_name)
            except OSError:
                pass


def atomic_write_text(path: str | Path, text: str,
                      mode: int | None = None) -> None:
    target = Path(path)
    with file_lock(target):
        atomic_write_text_locked(target, text, mode=mode)


def atomic_write_json(path: str | Path, value: Any, *, indent: int = 2,
                      ensure_ascii: bool = False) -> None:
    atomic_write_text(path, json.dumps(value, indent=indent, ensure_ascii=ensure_ascii))


def locked_json_update(path: str | Path, update: Callable[[Any], Any],
                       default: Any = None, *, indent: int = 2,
                       ensure_ascii: bool = False) -> Any:
    """Perform a cross-process-safe JSON read/modify/write transaction."""
    target = Path(path)
    with file_lock(target):
        try:
            current = json.loads(target.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            current = default
        updated = update(current)
        atomic_write_text_locked(
            target, json.dumps(updated, indent=indent, ensure_ascii=ensure_ascii))
        return updated
