import pytest

from anchore_engine.subsys.object_store import S3ObjectStorageDriver


class TestS3ObjectStorageDriver:
    @pytest.mark.parametrize(
        "param",
        [
            pytest.param(
                {
                    "uri": "s3://bucket/key",
                    "expected": ("bucket", "key"),
                },
                id="success",
            )
        ],
    )
    def test_parse_uri(self, param):
        assert (
            S3ObjectStorageDriver({"unittest": True})._parse_uri(param["uri"])
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
                    "expected": "s3://dakabucketname/dakaneye/dakabucket/dakakey",
                },
                id="success",
            )
        ],
    )
    def test_uri_for(self, param):
        assert (
            S3ObjectStorageDriver(
                {"unittest": True, "bucket": "dakabucketname"}
            ).uri_for(param["userId"], param["bucket"], param["key"])
            == param["expected"]
        )
