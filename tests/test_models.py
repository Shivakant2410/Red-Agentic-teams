import json

import pytest

from agentic_setup.models import ModelCatalog, ModelInfo


def test_free_models_are_identified_by_variant_or_zero_text_pricing():
    payload = {
        "data": [
            {
                "id": "provider/variant:free",
                "name": "Free variant",
                "context_length": 8192,
                "pricing": {"prompt": "0", "completion": "0"},
            },
            {
                "id": "provider/zero-priced",
                "pricing": {"prompt": "0", "completion": "0"},
                "supported_parameters": ["tools"],
            },
            {
                "id": "provider/paid",
                "pricing": {"prompt": "0.1", "completion": "0.2"},
            },
            {
                "id": "provider/mislabeled:free",
                "pricing": {"prompt": "0.1", "completion": "0"},
            },
            {
                "id": "provider/unknown-price",
                "pricing": {"prompt": "0"},
            },
        ]
    }

    catalog = ModelCatalog.from_api_payload(payload)

    assert [model.model_id for model in catalog.free_text_models()] == [
        "provider/variant:free",
        "provider/zero-priced",
    ]
    zero_priced = next(
        model for model in catalog.models if model.model_id == "provider/zero-priced"
    )
    assert zero_priced.supports_tools


def test_catalog_round_trips_local_cache(tmp_path):
    catalog = ModelCatalog.from_api_payload(
        {"data": [{"id": "provider/model:free", "pricing": {}}]}
    )
    path = tmp_path / "catalog.json"

    catalog.save(path)
    loaded = ModelCatalog.load(path)

    assert loaded == catalog
    assert json.loads(path.read_text(encoding="utf-8"))["models"][0]["free"] is True


def test_catalog_rejects_invalid_payload():
    with pytest.raises(ValueError, match="data list"):
        ModelCatalog.from_api_payload({"data": {}})


def test_catalog_item_requires_model_id():
    with pytest.raises(ValueError, match="model id"):
        ModelInfo.from_api({"name": "missing id"})
