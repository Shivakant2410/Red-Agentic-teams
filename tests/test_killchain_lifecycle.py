"""Phase E2 — KillChain locking + achieved_at (Stage 1B).

Thread-safe mark/status; achieved_at stamped on first ACHIEVED, cleared on an
operator revert, preserved on idempotent re-marks; persistence roundtrip.
"""

from __future__ import annotations

import json
import threading

from redteam.killchain import ACHIEVED, CREDENTIAL_ACCESS, KillChain, NOT_STARTED, RECON


def test_achieved_at_stamped_on_first_transition(tmp_path):
    kc = KillChain(tmp_path / "killchain.json")
    assert kc.summary()["stages"][RECON] == NOT_STARTED
    kc.mark(RECON, ACHIEVED, "surface mapped")
    st = json.loads((tmp_path / "killchain.json").read_text())[0]
    assert st["achieved_at"] != ""
    # server.py / graph_view.py read this exact field — it now exists
    assert st["stage"] == RECON and st["status"] == "achieved"


def test_remark_keeps_first_achieved_at(tmp_path):
    kc = KillChain(tmp_path / "killchain.json")
    kc.mark(RECON, ACHIEVED)
    first = kc._stages[RECON].achieved_at
    kc.mark(RECON, ACHIEVED, "reconfirmed")
    assert kc._stages[RECON].achieved_at == first


def test_revert_clears_achieved_at():
    kc = KillChain()
    kc.mark(CREDENTIAL_ACCESS, ACHIEVED)
    kc.mark(CREDENTIAL_ACCESS, NOT_STARTED, "over-claimed — operator revert")
    st = kc._stages[CREDENTIAL_ACCESS]
    assert st.status == NOT_STARTED and st.achieved_at == ""
    assert any("over-claimed" in n for n in st.notes)   # the revert note stays


def test_unknown_stage_safe():
    kc = KillChain()
    kc.mark("not-a-stage", ACHIEVED)   # no crash, no stage invented
    assert kc.status("not-a-stage") == NOT_STARTED


def test_concurrent_marks_race_clean(tmp_path):
    kc = KillChain(tmp_path / "killchain.json")
    def worker(i):
        for _ in range(25):
            kc.mark(RECON, ACHIEVED if i % 2 else NOT_STARTED, f"w{i}")
    threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    loaded = json.loads((tmp_path / "killchain.json").read_text())
    assert len(loaded) == len(kc._stages)   # file intact under races
    assert all("achieved_at" in row for row in loaded)


def test_persistence_roundtrip_with_timestamp(tmp_path):
    p = tmp_path / "killchain.json"
    kc = KillChain(p)
    kc.mark(CREDENTIAL_ACCESS, ACHIEVED, "tok harvested")
    kc2 = KillChain(p)
    assert kc2.status(CREDENTIAL_ACCESS) == ACHIEVED
    assert kc2._stages[CREDENTIAL_ACCESS].achieved_at != ""


def test_legacy_killchain_file_without_achieved_at(tmp_path):
    p = tmp_path / "killchain.json"
    p.write_text(json.dumps([{"stage": RECON, "status": "achieved", "notes": []}]),
                 encoding="utf-8")
    kc = KillChain(p)
    assert kc.status(RECON) == ACHIEVED
    assert kc._stages[RECON].achieved_at == ""   # legacy row loads, default applied
