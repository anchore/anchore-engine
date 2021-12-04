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
