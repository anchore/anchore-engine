import base64

import pytest

from anchore_engine.subsys.object_store import DbDriver
from anchore_engine.subsys.object_store.drivers import LegacyDbDriver


class TestLegacyDbDriver:
    @pytest.mark.parametrize(
        "param",
        [
            pytest.param(
                {
                    "uri": "postgresql://other@localhost/bucket/key?connect_timeout=10&application_name=myapp",
                    "expected": ("other@localhost", "bucket", "key"),
                },
                id="success",
            ),
            pytest.param(
                {
                    "uri": "postgresql://other@localhost?connect_timeout=10&application_name=myapp",
                    "expected": ValueError(),
                },
                id="expected-failure",
            ),
        ],
    )
    def test_parse_uri(self, param):
        driver = LegacyDbDriver({})
        if isinstance(param["expected"], Exception):
            with pytest.raises(param["expected"].__class__):
                driver._parse_uri(param["uri"])
        else:
            assert driver._parse_uri(param["uri"]) == param["expected"]

    @pytest.mark.parametrize(
        "param",
        [
            pytest.param(
                {
                    "userId": "dakaneye",
                    "bucket": "dakabucket",
                    "key": "dakakey",
                    "expected": "db://dakaneye/dakabucket/dakakey",
                },
                id="success",
            )
        ],
    )
    def test_uri_for(self, param):
        assert (
            LegacyDbDriver({}).uri_for(param["userId"], param["bucket"], param["key"])
            == param["expected"]
        )

    @pytest.mark.parametrize(
        "param",
        [
            pytest.param(
                {
                    "input": bytes("dakaneye", "utf-8"),
                    "expected_encoding": "dakaneye",
                    "expected_b64": False,
                },
                id="success-unicode",
            ),
            pytest.param(
                {
                    "input": b"\x80abc",
                    "expected_encoding": str(base64.encodebytes(b"\x80abc"), "utf-8"),
                    "expected_b64": True,
                },
                id="non-unicode-success",
            ),
        ],
    )
    def test_encode(self, param):
        driver = LegacyDbDriver({})
        actual_encoding, is_b64 = driver._encode(param["input"])
        assert is_b64 is param["expected_b64"]
        assert actual_encoding == param["expected_encoding"]

    @pytest.mark.parametrize(
        "param",
        [
            pytest.param(
                {
                    "input": {"b64_encoded": False, "jsondata": "dakaneye"},
                    "expected_decoding": "dakaneye",
                },
                id="success-unicode",
            ),
            pytest.param(
                {
                    "input": {
                        "b64_encoded": True,
                        "jsondata": str(base64.encodebytes(b"\x80abc"), "utf-8"),
                    },
                    "expected_decoding": b"\x80abc",
                },
                id="non-unicode-success",
            ),
            pytest.param(
                {
                    "input": {"b64_encoded": False, "jsondata": None},
                    "expected_decoding": b"",
                },
                id="nodata",
            ),
        ],
    )
    def test_decode(self, param):
        driver = LegacyDbDriver({})
        actual_decoding = driver._decode(param["input"])
        assert actual_decoding == param["expected_decoding"]


class TestDbDriver:
    @pytest.mark.parametrize(
        "param",
        [
            pytest.param(
                {
                    "uri": "postgresql://other@localhost/bucket/key?connect_timeout=10&application_name=myapp",
                    "expected": ("other@localhost", "bucket", "key"),
                },
                id="success",
            ),
            pytest.param(
                {
                    "uri": "postgresql://other@localhost?connect_timeout=10&application_name=myapp",
                    "expected": ValueError(),
                },
                id="expected-failure",
            ),
        ],
    )
    def test_parse_uri(self, param):
        driver = DbDriver({})
        if isinstance(param["expected"], Exception):
            with pytest.raises(param["expected"].__class__):
                driver._parse_uri(param["uri"])
        else:
            assert driver._parse_uri(param["uri"]) == param["expected"]

    @pytest.mark.parametrize(
        "param",
        [
            pytest.param(
                {
                    "userId": "dakaneye",
                    "bucket": "dakabucket",
                    "key": "dakakey",
                    "expected": "db2://dakaneye/dakabucket/dakakey",
                },
                id="success",
            )
        ],
    )
    def test_uri_for(self, param):
        assert (
            DbDriver({}).uri_for(param["userId"], param["bucket"], param["key"])
            == param["expected"]
        )
