"""Private, atomic session storage for a single local OS user."""

import fcntl
import json
import os
import stat
import tempfile
import uuid
from contextlib import contextmanager
from pathlib import Path

DEFAULT_DIRECTORY = Path.home() / ".config" / "chatgpt-plan-cli"


class StorageError(Exception):
    pass


class Store:
    def __init__(self, directory=DEFAULT_DIRECTORY):
        self.directory = directory
        self.path = directory / "sessions.json"

    @contextmanager
    def locked(self):
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = self.directory.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise StorageError(f"Session directory must be owned by you and have mode 0700: {self.directory}")
        with self._open_private(self.directory / "sessions.lock", os.O_RDWR | os.O_CREAT) as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise StorageError("Another CLI command is using the sessions. Try again when it finishes.") from None
            yield self._load()

    def _open_private(self, path, flags):
        fd = os.open(path, flags | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        try:
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600
            ):
                raise StorageError(f"Session file must be a private regular file with mode 0600: {path}")
            return os.fdopen(fd, "r", encoding="utf-8")
        except BaseException:
            os.close(fd)
            raise

    def _load(self):
        try:
            file = self._open_private(self.path, os.O_RDONLY)
        except FileNotFoundError:
            return {"version": 1, "host_id": uuid.uuid4().urn, "profiles": {}, "active": None}
        try:
            with file:
                state = json.load(file)
            if (
                not isinstance(state, dict)
                or state.get("version") != 1
                or not isinstance(state.get("profiles"), dict)
                or uuid.UUID(state.get("host_id", "")).version != 4
                or not state["host_id"].startswith("urn:uuid:")
                or (state.get("active") is not None and state["active"] not in state["profiles"])
            ):
                raise ValueError
        except (ValueError, TypeError, AttributeError):
            raise StorageError("The session file is unreadable or has an unsupported format.") from None
        return state

    def save(self, state):
        # Call while holding the lock. Keep the lock file's inode stable across writes.
        fd, name = tempfile.mkstemp(prefix=".sessions-", dir=self.directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as file:
                os.fchmod(file.fileno(), 0o600)
                json.dump(state, file, separators=(",", ":"), allow_nan=False)
                file.flush()
                os.fsync(file.fileno())
            os.replace(name, self.path)
            directory_fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            Path(name).unlink(missing_ok=True)
