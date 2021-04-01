import base64
import json
from datetime import datetime

import pytest

from anchore_engine.services.catalog import catalog_impl
from anchore_engine.utils import datetime_to_rfc3339


class TestImageAddWorkflow:
    now_str = datetime_to_rfc3339(datetime.now())

    @pytest.mark.parametrize(
        "param",
        [
            pytest.param(
                {
                    "input": {},
                    "expected_dockerfile": None,
                    "expected_dockerfile_mode": None,
                    "expected_error_prefix": None,
                },
                id="no-dockerfile-data",
            ),
            pytest.param(
                {
                    "input": {"dockerfile": "not-encoded!"},
                    "expected_dockerfile": None,
                    "expected_dockerfile_mode": None,
                    "expected_error_prefix": "input dockerfile data must be base64 encoded - exception on decode",
                },
                id="not-encoded",
            ),
            pytest.param(
                {
                    "input": {
                        "dockerfile": str(
                            base64.b64encode("dockerfile contents".encode("utf-8")),
                            "utf-8",
                        )
                    },
                    "expected_dockerfile": str(
                        base64.b64encode("dockerfile contents".encode("utf-8")), "utf-8"
                    ),
                    "expected_dockerfile_mode": "Actual",
                    "expected_error_prefix": None,
                },
                id="success",
            ),
        ],
    )
    def test_get_dockerfile_info(self, param):
        if param["expected_error_prefix"] is not None:
            with pytest.raises(Exception) as err:
                catalog_impl.get_dockerfile_info(param["input"])
                assert str(err).startswith(param["expected_error_prefix"])
        else:
            (
                actual_dockerfile,
                actual_dockerfile_mode,
            ) = catalog_impl.get_dockerfile_info(param["input"])
            assert actual_dockerfile == param["expected_dockerfile"]
            assert actual_dockerfile_mode == param["expected_dockerfile_mode"]

    @pytest.mark.parametrize(
        "param",
        [
            pytest.param(
                {
                    "params": {
                        "digest": "sha256:714511030a442b48f37791a817ce6e124d9ea4b0158f93ce914520549bd6bc30",
                    },
                    "image_info": {
                        "repo": "anchore/kai",
                        "registry": "docker.io",
                        "tag": None,
                    },
                    "input_string": "test",
                    "expected_overrides": {},
                    "expected_input_string": "test",
                },
                id="missing-tag",
            ),
            pytest.param(
                {
                    "params": {"tag": "anchore/kai:latest"},
                    "image_info": {
                        "repo": "anchore/kai",
                        "registry": "docker.io",
                        "tag": None,
                    },
                    "input_string": "test",
                    "expected_overrides": {},
                    "expected_input_string": "test",
                },
                id="missing-digest",
            ),
            pytest.param(
                {
                    "params": {
                        "tag": "anchore/kai:latest",
                        "digest": "sha256:714511030a442b48f37791a817ce6e124d9ea4b0158f93ce914520549bd6bc30",
                    },
                    "image_info": {
                        "repo": "anchore/kai",
                        "registry": "docker.io",
                        "tag": "latest",
                    },
                    "input_string": "test",
                    "expected_overrides": {
                        "fulltag": "anchore/kai:latest",
                        "tag": "latest",
                    },
                    "expected_input_string": "docker.io/anchore/kai@sha256:714511030a442b48f37791a817ce6e124d9ea4b0158f93ce914520549bd6bc30",
                },
                id="success-no-created-at",
            ),
            pytest.param(
                {
                    "params": {
                        "tag": "anchore/kai:latest",
                        "digest": "sha256:714511030a442b48f37791a817ce6e124d9ea4b0158f93ce914520549bd6bc30",
                        "created_at": now_str,
                    },
                    "image_info": {
                        "repo": "anchore/kai",
                        "registry": "docker.io",
                        "tag": "latest",
                    },
                    "input_string": "test",
                    "expected_overrides": {
                        "fulltag": "anchore/kai:latest",
                        "tag": "latest",
                        "created_at_override": now_str,
                    },
                    "expected_input_string": "docker.io/anchore/kai@sha256:714511030a442b48f37791a817ce6e124d9ea4b0158f93ce914520549bd6bc30",
                },
                id="success-with-created-at",
            ),
        ],
    )
    def test_resolve_image_info_overrides_and_input_string(self, param):
        (
            actual_overrides,
            actual_input_string,
        ) = catalog_impl.resolve_image_info_overrides_and_input_string(
            param["params"], param["image_info"], param["input_string"]
        )
        assert actual_overrides == param["expected_overrides"]
        assert actual_input_string == param["expected_input_string"]

    @pytest.mark.parametrize(
        "param",
        [
            pytest.param(
                {
                    "image_info": {},
                    "expected_manifest": None,
                    "expected_error_prefix": "could not fetch/parse manifest - exception: no manifest from get_image_info",
                },
                id="no-manifest",
            ),
            pytest.param(
                {
                    "image_info": {"manifest": "hey there"},
                    "expected_manifest": None,
                    "expected_error_prefix": "could not fetch/parse manifest - exception: ",
                },
                id="non-json-manifest",
            ),
            pytest.param(
                {
                    "image_info": {"manifest": {"layers": [{"this": "is a layer"}]}},
                    "expected_manifest": json.dumps(
                        {"layers": [{"this": "is a layer"}]}
                    ),
                    "expected_error_prefix": "could not fetch/parse manifest - exception: no manifest from get_image_info",
                },
                id="valid-manifest",
            ),
        ],
    )
    def test_get_manifest(self, param):
        if param["expected_error_prefix"] is not None:
            with pytest.raises(Exception) as err:
                catalog_impl.get_manifest(param["image_info"])
                assert str(err).startswith(param["expected_error_prefix"])
        else:
            actual_manifest = catalog_impl.get_manifest(param["image_info"])
            assert actual_manifest == param["expected_manifest"]
