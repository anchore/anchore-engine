"""
Unit tests for the api controller utils of external API service
"""
import base64
import json
import yaml
import pytest
from anchore_engine.apis.exceptions import BadRequest
from anchore_engine.services.apiext.api.controllers import utils as api_utils
from anchore_engine.subsys import logger

logger.enable_test_logging("INFO")

spec_path = "anchore_engine/services/apiext/swagger/swagger.yaml"
b64_dockerfile = str(
    base64.encodebytes(b'FROM stratch\nRUN echo "hello" > file\n'), "utf-8"
)
raw_dockerfile = 'FROM stratch\nRUN echo "hello" > file\n'


def _load_spec(path):
    with open(path) as f:
        if path.endswith("yaml") or path.endswith("yml"):
            return yaml.safe_load(f)
        else:
            return json.load(f)


api_spec = _load_spec(spec_path)

test_digest = "sha256:0123456789012345678901234567890123456789012345678901234567890123"
test_ts = "2019-01-01T01:01:01Z"


def test_valid_digest():
    matrix = [
        (test_digest, True),
        (test_digest[:-1], False),
        ("sha", False),
        ("sha256:abc", False),
    ]

    for input, result in matrix:
        assert bool(api_utils.DIGEST_REGEX.match(input) is not None) == result


def test_validate_pullstring_tag():
    logger.info("Testing tag-based pullstring validator")

    matrix = [
        ("docker.io/library/nginx:latest", True),
        ("docker.io/nginx:latest", True),
        ("docker.io/library/nginx", True),
        ("docker.io/nginx", True),
        ("docker.io/nginx@{}".format(test_digest), False),
        ("docker.io/library/nginx@{}".format(test_digest), False),
        ("nginx@{}".format(test_digest), False),
    ]

    for input, result in matrix:
        assert api_utils.validate_pullstring_is_tag(input) == result


def test_validate_pullstring_digest():
    logger.info("Testing digest-based pullstring validator")

    matrix = [
        ("docker.io/library/nginx:latest", False),
        ("docker.io/nginx:latest", False),
        ("docker.io/library/nginx", False),
        ("docker.io/nginx", False),
        ("docker.io/library/nginx@{}".format(test_digest), True),
        ("docker.io/nginx@{}".format(test_digest), True),
        ("nginx@{}".format(test_digest), True),
        ("localhost:5000/my_nginx@{}".format(test_digest), True),
    ]

    for input, result in matrix:
        assert api_utils.validate_pullstring_is_digest(input) == result


def test_tag_source_validator():
    logger.info("Testing tag source validator")

    api_utils.validate_tag_source(
        tag_source={"pullstring": "docker.io/nginx:latest"}, api_schema=api_spec
    )

    with pytest.raises(Exception):
        api_utils.validate_tag_source(
            tag_source={"t": "docker.io/nginx:latest"}, api_schema=api_spec
        )

    with pytest.raises(Exception):
        api_utils.validate_tag_source(
            tag_source={"pullstring": "docker.io/nginx@{}".format(test_digest)},
            api_schema=api_spec,
        )


def test_digest_source_validator():
    logger.info("Testing digest source validator")

    api_utils.validate_digest_source(
        digest_source={
            "pullstring": "docker.io/nginx@{}".format(test_digest),
            "tag": "docker.io/nginx:latest",
            "creation_timestamp_override": "2019-01-01T01:01:01Z",
        },
        api_schema=api_spec,
    )
    api_utils.validate_digest_source(
        digest_source={
            "pullstring": "docker.io/library/nginx@{}".format(test_digest),
            "tag": "docker.io/librarynginx:latest",
            "creation_timestamp_override": "2019-01-01T01:01:01Z",
        },
        api_schema=api_spec,
    )
    api_utils.validate_digest_source(
        digest_source={
            "pullstring": "nginx@{}".format(test_digest),
            "tag": "nginx:latest",
            "creation_timestamp_override": "2019-01-01T01:01:01Z",
        },
        api_schema=api_spec,
    )
    api_utils.validate_digest_source(
        digest_source={
            "pullstring": "docker.io/nginx@{}".format(test_digest),
            "tag": "docker.io/nginx:latest",
            "creation_timestamp_override": "2019-01-01T01:01:01Z",
        },
        api_schema=api_spec,
    )

    with pytest.raises(Exception):
        api_utils.validate_digest_source(
            digest_source={"t": "docker.io/nginx:latest"}, api_schema=api_spec
        )

    with pytest.raises(Exception):
        api_utils.validate_digest_source(
            digest_source={"pullstring": "docker.io/nginx@{}".format(test_digest)},
            api_schema=api_spec,
        )


def test_tag_normalization():
    matrix = [
        (
            {"tag": "docker.io/library/nginx:1.7"},
            {"source": {"tag": {"pullstring": "docker.io/library/nginx:1.7"}}},
        ),
        (
            {"tag": "docker.io/nginx"},
            {"source": {"tag": {"pullstring": "docker.io/nginx"}}},
        ),
        (
            {"tag": "docker.io/nginx@sha256:abc"},
            {"source": {"tag": {"pullstring": "docker.io/nginx@sha256:abc"}}},
        ),
    ]

    for test_input, result in matrix:
        if type(result) == type and issubclass(result, Exception):
            with pytest.raises(result):
                api_utils.normalize_image_add_source(test_input)
        else:
            assert api_utils.normalize_image_add_source(test_input) == result


def test_digest_normalization():
    matrix = [
        (
            {
                "created_at": "2019-01-01T01:01:01Z",
                "tag": "docker.io/nginx",
                "digest": test_digest,
            },
            {
                "source": {
                    "digest": {
                        "creation_timestamp_override": "2019-01-01T01:01:01Z",
                        "pullstring": "docker.io/nginx@{}".format(test_digest),
                        "tag": "docker.io/nginx",
                    }
                }
            },
        ),
        (
            {
                "created_at": "2019-01-01T01:01:01Z",
                "tag": "docker.io/nginx:latest",
                "digest": test_digest,
            },
            {
                "source": {
                    "digest": {
                        "creation_timestamp_override": "2019-01-01T01:01:01Z",
                        "pullstring": "docker.io/nginx@{}".format(test_digest),
                        "tag": "docker.io/nginx:latest",
                    }
                }
            },
        ),
    ]

    for test_input, result in matrix:
        assert api_utils.normalize_image_add_source(test_input) == result


@pytest.mark.parametrize(
    "test_input, result",
    [
        # Basic Tag Case
        ({"tag": "nginx"}, {"source": {"tag": {"pullstring": "nginx"}}}),
        # Basic Tag w/Dockerfile
        (
            {"tag": "docker.io/nginx", "dockerfile": b64_dockerfile},
            {
                "source": {
                    "tag": {
                        "pullstring": "docker.io/nginx",
                        "dockerfile": b64_dockerfile,
                    }
                }
            },
        ),
        # Basic Digest + Tag
        (
            {
                "tag": "docker.io/library/nginx:latest",
                "digest": test_digest,
                "created_at": test_ts,
            },
            {
                "source": {
                    "digest": {
                        "pullstring": "docker.io/library/nginx@{}".format(test_digest),
                        "tag": "docker.io/library/nginx:latest",
                        "creation_timestamp_override": test_ts,
                    }
                }
            },
        ),
        # Basic Digest + Tag
        (
            {
                "tag": "docker.io/library/nginx:latest",
                "digest": test_digest,
                "created_at": test_ts,
            },
            {
                "source": {
                    "digest": {
                        "pullstring": "docker.io/library/nginx@{}".format(test_digest),
                        "tag": "docker.io/library/nginx:latest",
                        "creation_timestamp_override": test_ts,
                    }
                }
            },
        ),
        # Basic Digest + Tag + Dodckerfile
        (
            {
                "tag": "docker.io/library/nginx:latest",
                "digest": test_digest,
                "created_at": test_ts,
                "dockerfile": b64_dockerfile,
            },
            {
                "source": {
                    "digest": {
                        "pullstring": "docker.io/library/nginx@{}".format(test_digest),
                        "tag": "docker.io/library/nginx:latest",
                        "creation_timestamp_override": test_ts,
                        "dockerfile": b64_dockerfile,
                    }
                }
            },
        ),
        # Digest pullstring + Tag + ts
        (
            {
                "tag": "docker.io/library/nginx:latest",
                "digest": "docker.io/library/nginx@{}".format(test_digest),
                "created_at": test_ts,
            },
            {
                "source": {
                    "digest": {
                        "pullstring": "docker.io/library/nginx@{}".format(test_digest),
                        "tag": "docker.io/library/nginx:latest",
                        "creation_timestamp_override": test_ts,
                    }
                }
            },
        ),
        # Digest pullstring + Tag + ts
        (
            {
                "source": {
                    "archive": {
                        "digest": "sha256:b9e8479820fb3a1a2f8ec426dd4ffc129e3a320392ce28dde6ae2d2d29ce2682"
                    }
                }
            },
            {
                "source": {
                    "archive": {
                        "digest": "sha256:b9e8479820fb3a1a2f8ec426dd4ffc129e3a320392ce28dde6ae2d2d29ce2682"
                    }
                }
            },
        ),
        # Tag + Digest only (no ts)
        (
            {
                "tag": "docker.io/library/nginx:latest",
                "digest": test_digest,
            },
            {
                "source": {
                    "digest": {
                        "pullstring": "docker.io/library/nginx@{}".format(test_digest),
                        "tag": "docker.io/library/nginx:latest",
                    }
                }
            },
        ),
        # Malformed tag
        ({"tag": "docker.io/library/nginx@{}".format(test_digest)}, BadRequest),
        # Digest Only
        ({"digest": test_digest}, ValueError),
        # Digest pullstring only
        ({"digest": "docker.io/nginx@{}".format(test_digest)}, BadRequest),
    ],
)
def test_normalization_and_validation(test_input, result):
    if type(result) == type and issubclass(result, Exception):
        with pytest.raises(result):
            normalized = api_utils.normalize_image_add_source(test_input)
            api_utils.validate_image_add_source(normalized, api_spec)
    else:
        normalized = api_utils.normalize_image_add_source(test_input)
        api_utils.validate_image_add_source(normalized, api_spec)
        assert normalized == result


def test_archive_source_validator():
    logger.info("Testing archive source validator")

    api_utils.validate_archive_source(
        archive_source={
            "digest": "sha256:b9e8479820fb3a1a2f8ec426dd4ffc129e3a320392ce28dde6ae2d2d29ce2682"
        },
        api_schema=api_spec,
    )
