import pytest

from anchore_engine.db.entities import policy_engine


class TestNvdv2MetadataGetScore:

    params = [
        pytest.param(
            {
                "metric": {"base_metrics": {"test": 2.0}},
                "score_key": "test",
                "expected": 2.0,
            },
            id="basic-metric",
        ),
        pytest.param(
            {"metric": None, "score_key": "test", "expected": -1.0},
            id="basic-none-metric",
        ),
        pytest.param(
            {"metric": {}, "score_key": "test", "expected": -1.0},
            id="basic-empty-metric",
        ),
        pytest.param(
            {
                "metric": {"base_metrics": {"test": "value"}},
                "score_key": "test",
                "expected": -1.0,
            },
            id="basic-non-float",
        ),
    ]

    @pytest.mark.parametrize("param", params)
    def test_get_score(self, param):
        actual_score = policy_engine.NvdV2Metadata()._get_score(
            param["metric"], param["score_key"]
        )
        assert actual_score == param["expected"]


class TestVulnDBMetadataGetScore:

    params = [
        pytest.param(
            {
                "metric": {"base_metrics": {"test": 2.0}},
                "score_key": "test",
                "expected": 2.0,
            },
            id="basic-metric",
        ),
        pytest.param(
            {"metric": None, "score_key": "test", "expected": -1.0},
            id="basic-none-metric",
        ),
        pytest.param(
            {"metric": {}, "score_key": "test", "expected": -1.0},
            id="basic-empty-metric",
        ),
        pytest.param(
            {
                "metric": {"base_metrics": {"test": "value"}},
                "score_key": "test",
                "expected": -1.0,
            },
            id="basic-non-float",
        ),
    ]

    @pytest.mark.parametrize("param", params)
    def test_get_score(self, param):
        actual_score = policy_engine.VulnDBMetadata()._get_score(
            param["metric"], param["score_key"]
        )
        assert actual_score == param["expected"]
