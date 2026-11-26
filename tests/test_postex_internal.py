"""Internal-network postex primitives: the triple gate + adapter honesty.

Failure modes this must prevent:

1. Lateral movement without explicit authorization — internal_sweep /
   kerberoast / bloodhound_collect refuse unless authorized_internal=true AND
   the RoE covers the private ranges (fail closed, per target).
2. Credential material leakage — kerberoast output must be reported as COUNTS
   and MASKED previews; the raw $krb5tgs$ material must never reach a finding,
   the audit log, or the access graph.
3. Adapter dishonesty — a missing impacket / bloodhound-python is reported as
   unavailable; nothing is sent to the DC on their behalf.
"""

from __future__ import annotations

import json
import socket

import pytest

from redteam.tools import ToolContext
from redteam.tools import postex as px
from redteam.tools.postex import BloodHoundTool, InternalSweepTool, KerberoastTool

from test_artex_features import _ctx, _engagement


def _internal_ctx(tmp_path, allow_private=True):
    eng = _engagement(allowed_hosts=("10.0.0.0/24",), allowed_ports=(88, 389, 445, 9999),
                      allow_private=allow_private)
    return _ctx(tmp_path, eng=eng)


def test_internal_sweep_refused_without_explicit_authorization(tmp_path):
    ctx = _internal_ctx(tmp_path)
    out = json.loads(InternalSweepTool().run(ctx, "10.0.0.0/24"))
    assert out["blocked"] is True and "authorized_internal" in out["note"]
    assert ctx.findings.all() == []


def test_internal_sweep_blocked_when_roe_excludes_private_ranges(tmp_path):
    # The CIDR is NOT listed in the RoE and allow_private_ranges is false: every
    # host:port fails scope.check → nothing swept, honest blocked note.
    eng = _engagement(allowed_hosts=("127.0.0.1",), allowed_ports=(88, 389, 445),
                      allow_private=False)
    ctx = _ctx(tmp_path, eng=eng)
    out = json.loads(InternalSweepTool().run(ctx, "10.0.0.0/24", authorized_internal=True))
    assert out["blocked"] is True and "outside the RoE" in out["note"]


def test_internal_sweep_flags_domain_controller_shape(tmp_path, monkeypatch):
    real_create = socket.create_connection

    def fake_create(address, timeout=None, **kw):
        host, port = address
        if host == "10.0.0.5" and port in (88, 389, 445):
            import io
            return real_create(("127.0.0.1", 59998), timeout=0.01) if False else _FakeSock()
        raise OSError("refused")

    class _FakeSock:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def close(self):
            pass

    monkeypatch.setattr(socket, "create_connection", fake_create)
    ctx = _internal_ctx(tmp_path)
    out = json.loads(InternalSweepTool().run(
        ctx, "10.0.0.0/24", authorized_internal=True,
        ports=[88, 389, 445, 9999], max_hosts=8))
    assert out["likely_dcs"] == ["10.0.0.5"]
    assert out["open_ports"] == [{"host": "10.0.0.5", "port": p} for p in (88, 389, 445)]
    assert ctx.findings.all()[0].title.startswith("Domain controller exposed")
    assert ctx.findings.all()[0].confidence == "tentative"


def test_kerberoast_refused_without_authorization(tmp_path):
    ctx = _internal_ctx(tmp_path)
    out = json.loads(KerberoastTool().run(ctx, "10.0.0.5", "corp.lab", "lowuser",
                                          "pw", authorized_internal=False))
    assert out["blocked"] is True


def test_kerberoast_honest_when_impacket_missing(tmp_path, monkeypatch):
    import shutil
    monkeypatch.setattr(shutil, "which", lambda name: None)
    ctx = _internal_ctx(tmp_path)
    out = json.loads(KerberoastTool().run(ctx, "10.0.0.5", "corp.lab", "lowuser",
                                          "pw", authorized_internal=True))
    assert out["available"] is False and "impacket" in out["note"]


def test_kerberoast_masks_ticket_material_and_audits_without_password(tmp_path, monkeypatch):
    import shutil
    ctx = _internal_ctx(tmp_path)
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/fake-GetUserSPNs")

    class _Proc:
        stdout = "$krb5tgs$23$*svc-backup@CORP.LAB*REAL-HASH-MATERIAL-1\n" \
                 "$krb5tgs$23$*svc-sql@CORP.LAB*REAL-HASH-MATERIAL-2\n"
        stderr = ""

    monkeypatch.setattr(px, "_run_adapter", lambda argv, **kw: _Proc())
    out = json.loads(KerberoastTool().run(ctx, "10.0.0.5", "corp.lab", "lowuser",
                                          "SUPERSECRETPW", authorized_internal=True))
    assert out["tickets"] == 2
    f = ctx.findings.get(out["finding_ids"][0])
    assert "REAL-HASH-MATERIAL-1" not in f.evidence  # raw material never stored
    assert "withheld" in f.evidence
    # The audit trail carries the run facts, not the credential:
    audits = [e for e in ctx.audit.events if e["event"] == "kerberoast.run"]
    assert audits and "SUPERSECRETPW" not in json.dumps(audits)
    # Access graph holds a masked preview, not the hash:
    nodes = json.dumps([n.attrs for n in ctx.access._nodes.values()])
    assert "REAL-HASH-MATERIAL" not in nodes


def test_bloodhound_honest_when_missing_and_gated(tmp_path, monkeypatch):
    import shutil
    ctx = _internal_ctx(tmp_path)
    out = json.loads(BloodHoundTool().run(ctx, "10.0.0.5", "corp.lab", "u", "p",
                                          authorized_internal=False))
    assert out["blocked"] is True
    monkeypatch.setattr(shutil, "which", lambda name: None)
    out = json.loads(BloodHoundTool().run(ctx, "10.0.0.5", "corp.lab", "u", "p",
                                          authorized_internal=True))
    assert out["available"] is False


def test_bloodhound_references_files_without_pasting_graph_data(tmp_path, monkeypatch):
    import shutil
    ctx = _internal_ctx(tmp_path)
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/fake-bloodhound-python")

    def fake_adapter(argv, timeout=0, cwd=None):
        from pathlib import Path
        Path(cwd, "20260101235959_users.json").write_text("{}")
        Path(cwd, "collector.zip").write_text("PK")

        class _Proc:
            stdout = "done"
            stderr = ""

        return _Proc()

    monkeypatch.setattr(px, "_run_adapter", fake_adapter)
    out = json.loads(BloodHoundTool().run(ctx, "10.0.0.5", "corp.lab", "u", "p",
                                          authorized_internal=True))
    assert sorted(out["files"]) == ["20260101235959_users.json", "collector.zip"]
    f = ctx.findings.get(out["finding_id"])
    assert "users.json" in f.evidence
