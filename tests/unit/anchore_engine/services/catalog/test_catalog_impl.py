import base64
import json
from datetime import datetime

import pytest

from anchore_engine.services.catalog import catalog_impl
from anchore_engine.services.catalog.catalog_impl import is_new_tag
from anchore_engine.util.time import datetime_to_rfc3339


@pytest.mark.parametrize(
    "image_record, registry, repo, tag, expected_output",
    [
        # Missing an image_detail block, returns true
        ({}, "myRegistry", "myRepo", "myTag", True),
        # Missing an image_detail.registry field, returns true
        (
            {
                "image_detail": [
                    {
                        "repo": "myRepo",
                        "tag": "myTag",
                    },
                ]
            },
            "myRegistry",
            "myRepo",
            "myTag",
            True,
        ),
        # Missing an image_detail.repo field, returns true
        (
            {
                "image_detail": [
                    {
                        "registry": "myRegistry",
                        "tag": "myTag",
                    },
                ]
            },
            "myRegistry",
            "myRepo",
            "myTag",
            True,
        ),
        # Missing an image_detail.tag field, returns true
        (
            {
                "image_detail": [
                    {
                        "registry": "myRegistry",
                        "repo": "myRepo",
                    },
                ]
            },
            "myRegistry",
            "myRepo",
            "myTag",
            True,
        ),
        # registry doesn't match, returns true
        (
            {
                "image_detail": [
                    {
                        "registry": "docker.io",
                        "repo": "myRepo",
                        "tag": "myTag",
                    }
                ]
            },
            "myRegistry",
            "myRepo",
            "myTag",
            True,
        ),
        # repo doesn't match, returns true
        (
            {
                "image_detail": [
                    {
                        "registry": "myRegistry",
                        "repo": "centos",
                        "tag": "myTag",
                    }
                ]
            },
            "myRegistry",
            "myRepo",
            "myTag",
            True,
        ),
        # tag doesn't match, returns true
        (
            {
                "image_detail": [
                    {
                        "registry": "myRegistry",
                        "repo": "myRepo",
                        "tag": "7",
                    }
                ]
            },
            "myRegistry",
            "myRepo",
            "myTag",
            True,
        ),
        # No fields match, returns true
        (
            {
                "image_detail": [
                    {
                        "registry": "docker.io",
                        "repo": "centos",
                        "tag": "7",
                    }
                ]
            },
            "myRegistry",
            "myRepo",
            "myTag",
            True,
        ),
        # Exact match, returns false
        (
            {
                "image_detail": [
                    {
                        "registry": "myRegistry",
                        "repo": "myRepo",
                        "tag": "myTag",
                    },
                ]
            },
            "myRegistry",
            "myRepo",
            "myTag",
            False,
        ),
        # Exact match, returns false
        (
            {
                "image_detail": [
                    {
                        "registry": "docker.io",
                        "repo": "centos",
                        "tag": "7",
                    },
                    {
                        "registry": "myRegistry",
                        "repo": "myRepo",
                        "tag": "myTag",
                    },
                ]
            },
            "myRegistry",
            "myRepo",
            "myTag",
            False,
        ),
    ],
)
def test_is_new_tag(image_record, registry, repo, tag, expected_output):
    # Function under test
    result = is_new_tag(image_record, registry, repo, tag)

    assert result == expected_output


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

    @pytest.mark.parametrize(
        "param",
        [
            pytest.param(
                {
                    "image_key": catalog_impl.ImageKey(
                        tag="docker.io/anchore/test_images:centos8", digest=""
                    ),
                    "expected": "docker.io/anchore/test_images:centos8",
                },
                id="no-digest",
            ),
            pytest.param(
                {
                    "image_key": catalog_impl.ImageKey(
                        tag="docker.io/anchore/test_images:centos8", digest="unknown"
                    ),
                    "expected": "docker.io/anchore/test_images:centos8",
                },
                id="digest-unknown",
            ),
            pytest.param(
                {
                    "image_key": catalog_impl.ImageKey(tag="", digest=""),
                    "expected": "",
                },
                id="no-digest-no-tag",
            ),
            pytest.param(
                {
                    "image_key": catalog_impl.ImageKey(
                        tag="docker.io/anchore/test_images:centos8",
                        digest="sha256:1234abcd",
                    ),
                    "expected": "docker.io/anchore/test_images@sha256:1234abcd",
                },
                id="valid-digest-valid-tag",
            ),
            pytest.param(
                {
                    "image_key": catalog_impl.ImageKey(
                        tag="nexus.aveng.me:5000/beats/filebeat:3.9.8",
                        digest="sha256:1b5677e1cc3ad16dd700a1d61e488ffdc5",
                    ),
                    "expected": "nexus.aveng.me:5000/beats/filebeat@sha256:1b5677e1cc3ad16dd700a1d61e488ffdc5",
                },
                id="registry-with-port-number",
            ),
        ],
    )
    def test_get_input_string(self, param):
        actual = catalog_impl.get_input_string(param["image_key"])
        assert actual == param["expected"]
