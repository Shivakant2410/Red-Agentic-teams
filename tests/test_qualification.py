import pytest

from agentic_setup.qualification import QualificationStore


def test_qualification_is_phase_specific_and_replaces_prior_score(tmp_path):
    store = QualificationStore(tmp_path / "qualified.json")

    first = store.add("vendor/model:free", "analysis", 0.7, "run-1", "eval-1")
    second = store.add("vendor/model:free", "analysis", 0.9, "run-2", "eval-2")
    store.add("vendor/model:free", "reporting", 0.8, "run-3", "eval-1")

    records = store.all()
    assert first.score == 0.7
    assert second.score == 0.9
    assert len(records) == 2
    assert [record.phase for record in store.for_phase("analysis")] == ["analysis"]


@pytest.mark.parametrize(
    ("phase", "score"),
    [("unknown", 0.5), ("analysis", -0.1), ("analysis", 1.1)],
)
def test_qualification_rejects_invalid_values(tmp_path, phase, score):
    store = QualificationStore(tmp_path / "qualified.json")

    with pytest.raises(ValueError):
        store.add("vendor/model:free", phase, score, "run", "v1")
