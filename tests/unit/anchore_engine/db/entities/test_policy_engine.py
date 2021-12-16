import zlib

import pytest

from anchore_engine.db.entities import policy_engine
from anchore_engine.db.entities.policy_engine import FilesystemAnalysis


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


class TestFilesystemAnalysis:
    @pytest.mark.parametrize(
        "param",
        [
            pytest.param(
                {
                    "compression_algorithm": "gzip",
                    "compressed_file_json": zlib.compress(bytes("{}", "utf8")),
                    "expected": {},
                },
                id="success-empty-json-gzip",
            ),
            pytest.param(
                {
                    "compression_algorithm": "gzip",
                    "compressed_file_json": zlib.compress(
                        bytes('{"test":"value"}', "utf8")
                    ),
                    "expected": {"test": "value"},
                },
                id="success-basic-json-gzip",
            ),
            pytest.param(
                {
                    "compression_algorithm": "tar",
                    "compressed_file_json": None,
                    "expected": ValueError(
                        "Got unexpected compression algorithm value: tar. Expected ['gzip']"
                    ),
                },
                id="invalid-algorithm",
            ),
        ],
    )
    def test_files_json(self, param):
        fsa_obj = FilesystemAnalysis()
        fsa_obj.compression_algorithm = param["compression_algorithm"]
        fsa_obj.compressed_file_json = param["compressed_file_json"]

        if isinstance(param["expected"], Exception):
            with pytest.raises(param["expected"].__class__) as e:
                fsa_obj._files_json()
                assert e == param["expected"]
        else:
            actual = fsa_obj._files_json()
            assert actual == param["expected"]
