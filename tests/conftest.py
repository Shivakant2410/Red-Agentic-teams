"""Shared test fixtures.

Hermeticity: the on-requirement toolbox venv (.tools/venv) belongs to the
OPERATOR, not to tests — an autouse fixture points the resolver at an empty
path so engine tests never execute real provisioned binaries (real arjun
runs inside E2E tests made the suite 8x slower and network-dependent).
Tests that exercise resolution/provisioning explicitly override this with
their own stubs (tests/test_provision.py does exactly that).
"""
import pytest

from redteam.sandbox import provision as _provision


@pytest.fixture(autouse=True)
def _isolate_toolbox_venv(tmp_path_factory, monkeypatch):
    empty = tmp_path_factory.mktemp("toolbox-empty")
    monkeypatch.setattr(_provision, "_DEFAULT_VENV", empty)
    yield
