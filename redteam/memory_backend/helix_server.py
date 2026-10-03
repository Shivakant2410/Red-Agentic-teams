"""HelixServer — manage the local HelixDB Docker container, the same lifecycle pattern
sandbox/docker_kali.py uses for the Kali sandbox: pull/run, wait for readiness, stop.

HelixDB's embedded (in-process, no server) mode is async-only (AsyncClient.embedded()),
and this project's agent/tool code is entirely synchronous — bridging every memory
read/write through asyncio.run() would be the wrong trade for a store that's read/written
dozens of times per run, not once. Running it as a managed local service (like Kali) keeps
every call on the synchronous helixdb.Client, consistent with the rest of the codebase.

PERSISTENCE (root-caused, not a Docker/mount bug): the previously-pinned v0.0.3 image's
standalone server is in-memory only by design — its DB_PATH env var is an internal key
prefix, not a filesystem path, and no volume mount or path fix makes v0.0.3 persist data
(confirmed: writes never touch the mounted volume at all, even mid-session, regardless of
mount location). Real on-disk persistence needs either an S3-compatible object store
(HelixDB's docs: MinIO is deprecated there in favor of SeaweedFS) or, simpler, v0.0.9's
native HELIX_DATA_DIR option used below — confirmed working end-to-end (write, stop
container, start a FRESH container on the same named volume, read the value back).
"""

from __future__ import annotations

import shutil
import subprocess
import time
from dataclasses import dataclass

DEFAULT_IMAGE = "ghcr.io/helixdb/helixdb:v0.0.9"
DEFAULT_CONTAINER = "redteam-helixdb"
DEFAULT_HOST_PORT = 6969   # container always listens on 8080 internally
# Where HELIX_DATA_DIR points INSIDE the container; the named volume below is mounted here.
_DATA_DIR = "/var/lib/helix"


class HelixServerError(Exception):
    pass


def _run(cmd: list[str], timeout: int | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


@dataclass
class HelixServer:
    image: str = DEFAULT_IMAGE
    container_name: str = DEFAULT_CONTAINER
    host_port: int = DEFAULT_HOST_PORT
    # Persist the DB across restarts via a named volume rather than default in-memory
    # storage, so learned lessons/patterns survive the container stopping between runs —
    # the whole point of this being PERSISTENT memory.
    volume_name: str = "redteam-helixdb-data"

    def __post_init__(self) -> None:
        self._started = False

    @property
    def url(self) -> str:
        return f"http://localhost:{self.host_port}"

    @staticmethod
    def _require_docker() -> None:
        if shutil.which("docker") is None:
            raise HelixServerError("docker CLI not found on PATH. Install Docker to use persistent memory.")

    def start(self, timeout_s: int = 60) -> None:
        self._require_docker()
        _run(["docker", "rm", "-f", self.container_name])  # clear any stale container
        cmd = [
            "docker", "run", "-d", "--rm", "--name", self.container_name,
            "-p", f"{self.host_port}:8080",
            "-v", f"{self.volume_name}:{_DATA_DIR}",
            "-e", f"HELIX_DATA_DIR={_DATA_DIR}",
            self.image,
        ]
        proc = _run(cmd, timeout=30)
        if proc.returncode != 0:
            raise HelixServerError(f"failed to start HelixDB container:\n{proc.stderr[-1500:]}")

        import urllib.error
        import urllib.request
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            try:
                # Any HTTP response (even 404) means the server is up and answering;
                # only a connection failure means it isn't ready yet.
                urllib.request.urlopen(self.url, timeout=2)
                self._started = True
                return
            except urllib.error.HTTPError:
                self._started = True
                return
            except Exception:
                time.sleep(1)
        self.stop()
        raise HelixServerError(f"HelixDB did not become reachable at {self.url} within {timeout_s}s")

    def client(self):
        """Return a connected helixdb.Client. Imports helixdb lazily so the rest of the
        codebase doesn't require it installed unless persistent memory is actually used."""
        if not self._started:
            raise HelixServerError("HelixServer not started")
        import helixdb as hx
        return hx.Client(self.url)

    def stop(self) -> None:
        _run(["docker", "rm", "-f", self.container_name])
        self._started = False
