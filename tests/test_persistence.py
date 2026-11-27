"""Cross-process persistence primitive regression tests."""
import json
from concurrent.futures import ThreadPoolExecutor

from redteam.memory import ExperienceStore
from redteam.persistence import atomic_write_json, locked_json_update


def test_locked_json_update_is_a_serialized_read_modify_write(tmp_path):
    path = tmp_path / "counter.json"

    def increment(_):
        locked_json_update(
            path,
            lambda current: {"count": (current or {}).get("count", 0) + 1},
            default={},
        )

    with ThreadPoolExecutor(max_workers=12) as pool:
        list(pool.map(increment, range(240)))
    assert json.loads(path.read_text(encoding="utf-8"))["count"] == 240
    assert (tmp_path / "counter.json.lock").exists()


def test_atomic_json_replace_leaves_only_complete_json(tmp_path):
    path = tmp_path / "snapshot.json"
    atomic_write_json(path, {"generation": 1, "payload": "a" * 10000})
    atomic_write_json(path, {"generation": 2, "payload": "b" * 10000})
    row = json.loads(path.read_text(encoding="utf-8"))
    assert row["generation"] == 2
    assert row["payload"] == "b" * 10000
    assert not list(tmp_path.glob(".snapshot.json.*.tmp"))


def test_memory_hmac_key_creation_is_shared_between_concurrent_stores(tmp_path):
    path = tmp_path / "memory.json"
    with ThreadPoolExecutor(max_workers=8) as pool:
        stores = list(pool.map(lambda _: ExperienceStore(path), range(24)))
    keys = {store._key for store in stores}
    assert len(keys) == 1
    assert (tmp_path / "memory.json.key").exists()
    assert (tmp_path / "memory.json.key.lock").exists()
