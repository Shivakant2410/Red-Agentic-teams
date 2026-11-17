"""T2 — the C1 identity contract.

mission_id (logical) and run_id (physical) are SEPARATE fields everywhere:
equal in Phase 2 by CONSTRUCTION (the mission is hosted in the run directory
whose name the existing RunRegistry contract minted), never by hard-coded
equality downstream. run_ids is a list, so a future 1 mission : N runs model
is a schema extension, not an identity migration. Events carry mission_id;
API responses echo both.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from redteam.mission.mission import Mission
from redteam.mission.errors import ValidationError
from redteam.swarm.journal import EventJournal

import mission_helpers as H


def test_identity_triple_by_construction(tmp_path):
    """mission.json: mission_id == run_id == the run directory NAME (the same
    filesystem-oracle identity RunRegistry mints), stored as separate fields
    with run_ids the authoritative list."""
    mission_dir, _ = H.make_mission_dir(tmp_path)
    raw = json.loads((mission_dir / "mission.json").read_text())
    assert raw["mission_id"] == raw["run_id"] == mission_dir.name
    assert raw["run_ids"] == [mission_dir.name]
    # Separate fields in the OBJECT too — equality is a property of the minting
    # step, not of the model.
    mission = Mission.load(mission_dir / "mission.json")
    assert mission.mission_id == mission.primary_run_id
    assert mission.run_ids == [mission.mission_id]


def test_future_one_to_many_round_trips(tmp_path):
    """The model supports 1 mission : N runs TODAY: a crafted mission with two
    run_ids loads, keeps both, and primary_run_id is the first — no downstream
    code had to change to represent it."""
    mission = Mission(mission_id="mission-42", run_ids=["run-alpha", "run-beta"],
                      engagement="eng-1")
    mission.save(tmp_path / "mission.json")
    loaded = Mission.load(tmp_path / "mission.json")
    assert loaded.run_ids == ["run-alpha", "run-beta"]
    assert loaded.primary_run_id == "run-alpha"
    assert loaded.mission_id == "mission-42"      # NOT equal to any run_id
    assert loaded.mission_id != loaded.primary_run_id


def test_downstream_components_never_conflate_identity(tmp_path):
    """Craft a mission whose mission_id != run_id and push a task + events
    through the Commander: every event payload and task record carries BOTH
    values VERBATIM — nothing compares, derives, or overwrites one from the
    other."""
    mission_dir = tmp_path / "run-alpha"
    mission_dir.mkdir()
    Mission(mission_id="mission-42", run_ids=["run-alpha"],
            engagement="eng-1").save(mission_dir / "mission.json")
    commander = H.make_commander(mission_dir, H.FakeClock())
    commander.start_mission("op")
    task = commander.create_task(title="t", role="exploit", actor="op")
    assert task.mission_id == "mission-42"
    assert task.run_id == "run-alpha"
    events = [json.loads(line) for line in
              (mission_dir / "mission_journal.jsonl").read_text().splitlines()]
    mission_events = [e for e in events if e["type"].startswith(("MISSION_", "TASK_"))]
    assert mission_events, "mission events must be journaled"
    for event in mission_events:
        assert event["mission_id"] == "mission-42"
        if event["type"].startswith("TASK_"):
            assert event["task_id"] == task.task_id
    # The task view echoes the triple for API consumers.
    view = commander.task_view(task.task_id)
    assert (view["mission_id"], view["run_id"]) == ("mission-42", "run-alpha")


def test_journal_engagement_matches_swarm_semantics(tmp_path):
    """The mission journal uses the SAME engagement_id value the swarm journal
    uses (the RoE engagement name) — one engagement's journals stay
    cross-referenceable; files stay per-concern."""
    mission_dir, _ = H.make_mission_dir(tmp_path)
    journal = EventJournal("eng-1", path=mission_dir / "mission_journal.jsonl")
    assert journal.engagement_id == "eng-1"
    swarm_journal = EventJournal("eng-1")   # the swarm layer's default ctor
    assert swarm_journal.engagement_id == journal.engagement_id


def test_load_accepts_legacy_singular_shape(tmp_path):
    raw = {"mission_id": "m-1", "run_id": "r-1", "engagement": "eng-1"}
    (tmp_path / "mission.json").write_text(json.dumps(raw))
    mission = Mission.load(tmp_path / "mission.json")
    assert mission.run_ids == ["r-1"]
    with pytest.raises(ValidationError):
        (tmp_path / "broken.json").write_text(json.dumps({"mission_id": "m"}))
        Mission.load(tmp_path / "broken.json")


def test_api_echoes_identity(tmp_path):
    """The additive API surfaces the identity contract: list + detail echo
    mission_id, run_id, AND run_ids (never just one of them)."""
    from redteam.server import create_app
    runs_root = tmp_path / "runs"
    mission_dir = runs_root / "20260101-120000-probe"
    mission_dir.mkdir(parents=True)
    Mission(mission_id=mission_dir.name, run_ids=[mission_dir.name],
            engagement="eng-1", ticket="ROE-2026-17",
            objective="probe").save(mission_dir / "mission.json")
    app = create_app(runs_root, dashboard_dir=None)
    client = TestClient(app)
    listed = client.get("/api/missions").json()["missions"]
    assert len(listed) == 1
    row = listed[0]
    assert row["mission_id"] == row["run_id"] == mission_dir.name
    assert row["run_ids"] == [mission_dir.name]
    detail = client.get(f"/api/missions/{mission_dir.name}").json()
    assert detail["mission_id"] == mission_dir.name
    assert detail["run_ids"] == [mission_dir.name]
    assert client.get("/api/missions/missing").status_code == 404
    assert client.get("/api/runs").status_code == 200   # runs API untouched


def test_run_api_contract_untouched(tmp_path):
    """The /api/runs contract is byte-identical in shape: mission rows must
    NOT leak into it (a run directory with mission.json is both — the runs
    listing reads manifest.json, exactly as before)."""
    from redteam.server import create_app
    from redteam.runtime import RunManifest
    runs_root = tmp_path / "runs"
    mission_dir = runs_root / "20260101-120000-probe"
    mission_dir.mkdir(parents=True)
    Mission(mission_id=mission_dir.name, run_ids=[mission_dir.name],
            engagement="eng-1").save(mission_dir / "mission.json")
    RunManifest(objective="probe", engagement="eng-1").save(
        mission_dir / "manifest.json")
    app = create_app(runs_root, dashboard_dir=None)
    client = TestClient(app)
    runs = client.get("/api/runs").json()["runs"]
    assert len(runs) == 1 and runs[0]["run_id"] == mission_dir.name
    missions = client.get("/api/missions").json()["missions"]
    assert len(missions) == 1
