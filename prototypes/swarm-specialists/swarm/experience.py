"""ExperienceStore — the per-specialist memory seam, made swappable (G5, M4).

Used to be: registry_tool's local `memory()` closure hard-wired to
MemoryNamespace files, with the swap note living in a docstring. Now:
a protocol with two implementations the Orchestrator accepts by injection.

  - FileExperienceStore   — byte-for-byte the old behavior (Beta posteriors
                            + insights + history per namespace, persisted
                            under memory_dir); default for lab runs.
  - InMemoryExperienceStore — same interface, no disk; for tests and
                            embedding (platform adapter shape; the
                            platform's semantic backend — HelixDB, see
                            redteam/memory_backend/ — implements this
                            protocol on the other side of the seam).

Research basis (RESEARCH-M4.md R3): AWM (arXiv:2409.07429) is the
published existence proof that experience-as-curated-workflow pays
(+24.6%/+51.1% relative success AND fewer steps) — our M5 exit (run-2
request efficiency >= +20%) is an AWM-shaped claim. AWM's own ablations
put the value in the SELECTIVE provisioning, which is why this store keeps
the M7/A2/A3 guards: target-agnostic insights only, target-controlled
credit capped, and nothing here can ever influence the policy gate.
"""
from .memory import MemoryNamespace


class ExperienceStore:
    """Protocol: namespace(name) -> MemoryNamespace-like object;
    namespaces() -> {name: ns} for snapshotting."""

    name = "experience-store"

    def namespace(self, name):
        raise NotImplementedError

    def namespaces(self):
        raise NotImplementedError

    def snapshots(self):
        return {n: ns.snapshot() for n, ns in self.namespaces().items()}


class FileExperienceStore(ExperienceStore):
    """The old FileMemoryStore behavior, behind the protocol."""

    name = "file-experience-store"

    def __init__(self, memory_dir):
        self.memory_dir = memory_dir
        self._cache = {}

    def namespace(self, name):
        if name not in self._cache:
            self._cache[name] = MemoryNamespace(name, self.memory_dir)
        return self._cache[name]

    def namespaces(self):
        return dict(self._cache)


class InMemoryExperienceStore(ExperienceStore):
    """Diskless twin: identical bandit semantics, nothing persisted."""

    name = "in-memory-experience-store"

    def __init__(self):
        self._cache = {}

    def namespace(self, name):
        if name not in self._cache:
            self._cache[name] = MemoryNamespace(name, None, persist=False)
        return self._cache[name]

    def namespaces(self):
        return dict(self._cache)
