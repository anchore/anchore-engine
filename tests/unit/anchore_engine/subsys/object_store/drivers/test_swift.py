import pytest

from anchore_engine.subsys.object_store import SwiftObjectStorageDriver


class TestSwiftObjectStorageDriver:
    @pytest.mark.parametrize(
        "param",
        [
            pytest.param(
                {
                    "uri": "swift://bucket/key",
                    "expected": ("bucket", "key"),
                },
                id="success",
            )
        ],
    )
    def test_parse_uri(self, param):
        assert (
            SwiftObjectStorageDriver({"unittest": True})._parse_uri(param["uri"])
            == param["expected"]
        )

    # Implicitly tests build_key too
    @pytest.mark.parametrize(
        "param",
        [
            pytest.param(
                {
                    "userId": "dakaneye",
                    "bucket": "dakabucket",
                    "key": "dakakey",
                    "expected": "swift://dakacontainername/dakaneye/dakabucket/dakakey",
                },
                id="success",
            )
        ],
    )
    def test_uri_for(self, param):
        assert (
            SwiftObjectStorageDriver(
                {"unittest": True, "container": "dakacontainername"}
            ).uri_for(param["userId"], param["bucket"], param["key"])
            == param["expected"]
        )
