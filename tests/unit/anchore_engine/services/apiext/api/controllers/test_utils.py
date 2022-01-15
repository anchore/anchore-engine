"""
Unit tests for the api controller utils of external API service
"""
import base64
import json

import pytest
import yaml

from anchore_engine.apis.exceptions import BadRequest
from anchore_engine.common.models.policy_engine import CVSS, NVDReference, Vulnerability
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


class TestMakeVulnerabilityResponse:
    @pytest.mark.parametrize(
        "test_input, expected",
        [
            # same id as nvd, different namespaces
            (
                {
                    "cpe": "cpe:/a:-:foo:4.0:-:~~~python~~",
                    "cpe23": "cpe:2.3:a:-:foo:4.0:-:-:-:-:-:-:~~~python~~",
                    "feed_name": "blah",
                    "feed_namespace": "blah:vulnerabilities",
                    "fixed_in": ["4.5.2"],
                    "link": "http://api:8228/v1/query/vulnerabilities?id=BLAH-123456",
                    "name": "foo",
                    "nvd_data": [
                        {"cvss_v2": {}, "cvss_v3": {}, "id": "CVE-0000-0000"}
                    ],  # connecting data! id should match nvd
                    "pkg_path": "/usr/lib/python2.7/dist-packages/foo",
                    "pkg_type": "python",
                    "severity": "Medium",
                    "vendor_data": [
                        {"cvss_v2": {}, "cvss_v3": None, "id": "BLAH-123456"}
                    ],
                    "version": "4.0",
                    "vulnerability_id": "CVE-0000-0000",
                },
                {
                    "vuln": "CVE-0000-0000",
                    "url": "http://api:8228/v1/query/vulnerabilities?id=BLAH-123456",
                    "feed": "blah",
                    "feed_group": "blah:vulnerabilities",
                },
            ),
            # different id than nvd, different namespaces
            (
                {
                    "cpe": "cpe:/a:-:foo:4.0:-:~~~python~~",
                    "cpe23": "cpe:2.3:a:-:foo:4.0:-:-:-:-:-:-:~~~python~~",
                    "feed_name": "meh",
                    "feed_namespace": "meh:vulnerabilities",
                    "fixed_in": ["4.5.2"],
                    "link": "http://api:8228/v1/query/vulnerabilities?id=MEH-123456",
                    "name": "foo",
                    "nvd_data": [
                        {"cvss_v2": {}, "cvss_v3": {}, "id": "CVE-0000-0000"}
                    ],  # connecting data! id should match nvd
                    "pkg_path": "/usr/lib/python2.7/dist-packages/foo",
                    "pkg_type": "python",
                    "severity": "Medium",
                    "vendor_data": [
                        {"cvss_v2": {}, "cvss_v3": None, "id": "MEH-123456"}
                    ],
                    "version": "4.0",
                    "vulnerability_id": "MEH-123456",
                },
                {
                    "vuln": "MEH-123456",
                    "url": "http://api:8228/v1/query/vulnerabilities?id=MEH-123456",
                    "feed": "meh",
                    "feed_group": "meh:vulnerabilities",
                },
            ),
        ],
    )
    def test_non_os_vulns_dedup(self, test_input, expected):
        """
        Given nvd and non-os vulnerabilities affecting the same package, test that dedup prioritizes non-nvd record if they are the same.
        A non-nvd vulnerability is considered the same as an nvd vulnerability if it contains a reference to the CVE

        """
        nvd_vuln = {
            "cpe": "cpe:/a:-:foo:4.0:-:~~~python~~",
            "cpe23": "cpe:2.3:a:-:foo:4.0:-:-:-:-:-:-:~~~python~~",
            "feed_name": "nvdv2",
            "feed_namespace": "nvdv2:cves",
            "fixed_in": [],
            "link": "https://nvd.nist.gov/vuln/detail/CVE-0000-0000",
            "name": "foo",
            "nvd_data": [{"cvss_v2": {}, "cvss_v3": None, "id": "CVE-0000-0000"}],
            "pkg_path": "/usr/lib/python2.7/dist-packages/foo",
            "pkg_type": "python",
            "severity": "Critical",
            "vendor_data": [],
            "version": "4.0",
            "vulnerability_id": "CVE-0000-0000",
        }
        a = {
            "cpe_report": [test_input, nvd_vuln],
            "image_id": "xyz",
            "legacy_report": {},
        }

        results = api_utils.make_response_vulnerability("all", a)
        assert results and len(results) == 1
        result = results[0]
        assert result
        for key, value in expected.items():
            assert result.get(key) == value

    @pytest.mark.parametrize(
        "test_input, expected",
        [
            (
                [
                    "GHSA-abcd-efgh-1234",
                    "High",
                    1,
                    "foo-4.0",
                    "4.1.3",
                    "xyz",
                    "None",
                    "https://github.com/advisories/GHSA-abcd-efgh-1234",
                    "python",
                    "vulnerabilities",
                    "github:python",
                    "foo",
                    "/usr/lib/python2.7/dist-packages/foo",
                    "4.0",
                    '{"nvd_data": [{"id": "CVE-1111-1111", "cvss_v2": {}, "cvss_v3": {}}], "vendor_data": []}',
                ],
                {
                    "vuln": "GHSA-abcd-efgh-1234",
                    "url": "https://github.com/advisories/GHSA-abcd-efgh-1234",
                    "feed": "vulnerabilities",
                    "feed_group": "github:python",
                },
            )
        ],
    )
    def test_vulns_dedup_1(self, test_input, expected):
        """
        Given nvd and os vulnerabilities affecting the same package, test that dedup prioritizes non-nvd record if they are the same.
        A non-nvd vulnerability is considered the same as an nvd vulnerability if it contains a reference to the CVE

        """
        a = {
            "cpe_report": [
                {
                    "cpe": "cpe:/a:-:foo:4.0:-:~~~python~~",
                    "cpe23": "cpe:2.3:a:-:foo:4.0:-:-:-:-:-:-:~~~python~~",
                    "feed_name": "nvdv2",
                    "feed_namespace": "nvdv2:cves",
                    "fixed_in": [],
                    "link": "https://nvd.nist.gov/vuln/detail/CVE-1111-1111",
                    "name": "foo",
                    "nvd_data": [{"cvss_v2": {}, "cvss_v3": {}, "id": "CVE-1111-1111"}],
                    "pkg_path": "/usr/lib/python2.7/dist-packages/foo",
                    "pkg_type": "python",
                    "severity": "High",
                    "vendor_data": [],
                    "version": "4.0",
                    "vulnerability_id": "CVE-1111-1111",
                }
            ],
            "image_id": "xyz",
            "legacy_report": {
                "multi": {
                    "result": {
                        "colcount": 15,
                        "header": [
                            "CVE_ID",
                            "Severity",
                            "*Total_Affected",
                            "Vulnerable_Package",
                            "Fix_Available",
                            "Fix_Images",
                            "Rebuild_Images",
                            "URL",
                            "Package_Type",
                            "Feed",
                            "Feed_Group",
                            "Package_Name",
                            "Package_Path",
                            "Package_Version",
                            "CVES",
                        ],
                        "rowcount": 1,
                        "rows": [test_input],
                    }
                }
            },
        }

        results = api_utils.make_response_vulnerability("all", a)
        assert results and len(results) == 1
        result = results[0]
        assert result
        for key, value in expected.items():
            assert result.get(key) == value

    @pytest.mark.parametrize(
        "test_input, test_repeats, expected",
        [
            # same id as nvd, different namespaces
            (
                {
                    "cpe": "cpe:/a:-:foo:4.0:-:~~~python~~",
                    "cpe23": "cpe:2.3:a:-:foo:4.0:-:-:-:-:-:-:~~~python~~",
                    "feed_name": "blah",
                    "feed_namespace": "blah:vulnerabilities",
                    "fixed_in": ["4.5.2"],
                    "link": "http://api:8228/v1/query/vulnerabilities?id=BLAH-123456",
                    "name": "foo",
                    "nvd_data": [{"cvss_v2": {}, "cvss_v3": {}, "id": "CVE-0000-0000"}],
                    "pkg_path": "/usr/lib/python2.7/dist-packages/foo",
                    "pkg_type": "python",
                    "severity": "Medium",
                    "vendor_data": [
                        {"cvss_v2": {}, "cvss_v3": None, "id": "BLAH-123456"}
                    ],
                    "version": "4.0",
                    "vulnerability_id": "CVE-0000-0000",
                },
                3,
                {
                    "vuln": "CVE-0000-0000",
                    "url": "http://api:8228/v1/query/vulnerabilities?id=BLAH-123456",
                    "feed": "blah",
                    "feed_group": "blah:vulnerabilities",
                },
            ),
            # different id than nvd, different namespaces
            (
                {
                    "cpe": "cpe:/a:-:foo:4.0:-:~~~python~~",
                    "cpe23": "cpe:2.3:a:-:foo:4.0:-:-:-:-:-:-:~~~python~~",
                    "feed_name": "meh",
                    "feed_namespace": "meh:vulnerabilities",
                    "fixed_in": ["4.5.2"],
                    "link": "http://api:8228/v1/query/vulnerabilities?id=MEH-123456",
                    "name": "foo",
                    "nvd_data": [{"cvss_v2": {}, "cvss_v3": {}, "id": "CVE-0000-0000"}],
                    "pkg_path": "/usr/lib/python2.7/dist-packages/foo",
                    "pkg_type": "python",
                    "severity": "Medium",
                    "vendor_data": [
                        {"cvss_v2": {}, "cvss_v3": None, "id": "MEH-123456"}
                    ],
                    "version": "4.0",
                    "vulnerability_id": "MEH-123456",
                },
                7,
                {
                    "vuln": "MEH-123456",
                    "url": "http://api:8228/v1/query/vulnerabilities?id=MEH-123456",
                    "feed": "meh",
                    "feed_group": "meh:vulnerabilities",
                },
            ),
        ],
    )
    def test_repeats(self, test_input, test_repeats, expected):
        """
        Given a non-os vulnerability repeated multiple times, test that dedup filters out all but one instance
        A vulnerability is considered the same as another vulnerability if it has the same id, feed namespace and package path
        """
        a = {
            "cpe_report": [test_input.copy() for counter in range(test_repeats)],
            "image_id": "xyz",
            "legacy_report": {},
        }

        results = api_utils.make_response_vulnerability("all", a)
        assert results and len(results) == 1
        result = results[0]
        assert result
        for key, value in expected.items():
            assert result.get(key) == value


class TestMakeVulnerabilityReport:
    @pytest.mark.parametrize(
        "test_input, expected",
        [
            pytest.param(CVSS(version="2"), "cvss_v2", id="v2"),
            pytest.param(CVSS(version="2.0"), "cvss_v2", id="v2.0"),
            pytest.param(CVSS(version="2.1"), "cvss_v2", id="v2.1"),
            pytest.param(CVSS(version="2.x"), "cvss_v2", id="v2.x"),
            pytest.param(CVSS(version="3"), "cvss_v3", id="v3"),
            pytest.param(CVSS(version="3.0"), "cvss_v3", id="v3.0"),
            pytest.param(CVSS(version="3.3"), "cvss_v3", id="v3.3"),
            pytest.param(CVSS(version="3.y"), "cvss_v3", id="v3.y"),
        ],
    )
    def test_to_cvss_score_valid(self, test_input, expected):
        test_input.base_score = 5.7
        test_input.exploitability_score = 6.8
        test_input.impact_score = 4.3

        expected_output = {
            expected: {
                "base_score": test_input.base_score,
                "exploitability_score": test_input.exploitability_score,
                "impact_score": test_input.impact_score,
            }
        }

        assert api_utils.to_cvss_score(test_input) == expected_output

    @pytest.mark.parametrize(
        "test_input",
        [
            pytest.param(CVSS(version="1"), id="v1"),
            pytest.param(CVSS(version="4"), id="v1"),
            pytest.param(CVSS(version="foo"), id="vfoo"),
            pytest.param(CVSS(version=""), id="blank"),
            pytest.param(CVSS(), id="none"),
        ],
    )
    def test_to_cvss_score_invalid_version(self, test_input):
        assert api_utils.to_cvss_score(test_input) is None

    @pytest.mark.parametrize(
        "test_input",
        [
            pytest.param(
                [NVDReference(vulnerability_id="CVE-x", cvss=[])], id="empty-list"
            ),
            pytest.param(
                [NVDReference(vulnerability_id="CVE-x", cvss=None)], id="none"
            ),
            pytest.param(
                [
                    NVDReference(vulnerability_id="CVE-x", cvss=[]),
                    NVDReference(vulnerability_id="CVE-x", cvss=None),
                ],
                id="combo",
            ),
        ],
    )
    def test_get_nvd_data_from_nvd_references_no_cvss(self, test_input):
        actual_output = api_utils.get_nvd_data_from_nvd_references(test_input)
        assert len(test_input) == len(actual_output)
        for input_item, output_item in zip(test_input, actual_output):
            assert output_item == {
                "id": input_item.vulnerability_id,
                "cvss_v2": {
                    "base_score": -1.0,
                    "exploitability_score": -1.0,
                    "impact_score": -1.0,
                },
                "cvss_v3": {
                    "base_score": -1.0,
                    "exploitability_score": -1.0,
                    "impact_score": -1.0,
                },
            }

    def test_get_nvd_data_from_nvd_references_multiple_cvss(self):
        test_input = NVDReference(
            vulnerability_id="CVE-x",
            cvss=[
                CVSS(
                    version="2.0",
                    base_score=1.1,
                    exploitability_score=1.2,
                    impact_score=1.3,
                ),
                CVSS(
                    version="3.0",
                    base_score=2.1,
                    exploitability_score=2.2,
                    impact_score=2.3,
                ),
                CVSS(
                    version="3.1",
                    base_score=3.1,
                    exploitability_score=3.2,
                    impact_score=3.3,
                ),
            ],
        )

        expected_output = {
            "id": test_input.vulnerability_id,
            "cvss_v2": {
                "base_score": 1.1,
                "exploitability_score": 1.2,
                "impact_score": 1.3,
            },
            "cvss_v3": {
                "base_score": 3.1,
                "exploitability_score": 3.2,
                "impact_score": 3.3,
            },
        }

        actual_output = api_utils.get_nvd_data_from_nvd_references([test_input])

        assert len(actual_output) == 1
        assert actual_output[0] == expected_output

    @pytest.mark.parametrize(
        "test_input",
        [
            pytest.param(Vulnerability(cvss=[]), id="empty-list"),
            pytest.param(Vulnerability(cvss=None), id="none"),
        ],
    )
    def test_get_vendor_data_from_vulnerability_no_cvss(self, test_input):
        assert api_utils.get_vendor_data_from_vulnerability(test_input) == []

    @pytest.mark.parametrize(
        "test_input, expected_output",
        [
            pytest.param(
                Vulnerability(
                    vulnerability_id="CVE-x",
                    cvss=[
                        CVSS(
                            version="2.3",
                            base_score=1.1,
                            exploitability_score=1.2,
                            impact_score=1.3,
                        )
                    ],
                ),
                [
                    {
                        "id": "CVE-x",
                        "cvss_v2": {
                            "base_score": 1.1,
                            "exploitability_score": 1.2,
                            "impact_score": 1.3,
                        },
                        "cvss_v3": {
                            "base_score": -1.0,
                            "exploitability_score": -1.0,
                            "impact_score": -1.0,
                        },
                    }
                ],
                id="single_cvss",
            ),
            pytest.param(
                Vulnerability(
                    vulnerability_id="CVE-x",
                    cvss=[
                        CVSS(
                            version="2.3",
                            base_score=1.1,
                            exploitability_score=1.2,
                            impact_score=1.3,
                        ),
                        CVSS(
                            version="3.1",
                            base_score=2.1,
                            exploitability_score=2.2,
                            impact_score=2.3,
                        ),
                    ],
                ),
                [
                    {
                        "id": "CVE-x",
                        "cvss_v2": {
                            "base_score": 1.1,
                            "exploitability_score": 1.2,
                            "impact_score": 1.3,
                        },
                        "cvss_v3": {
                            "base_score": -1.0,
                            "exploitability_score": -1.0,
                            "impact_score": -1.0,
                        },
                    },
                    {
                        "id": "CVE-x",
                        "cvss_v2": {
                            "base_score": -1.0,
                            "exploitability_score": -1.0,
                            "impact_score": -1.0,
                        },
                        "cvss_v3": {
                            "base_score": 2.1,
                            "exploitability_score": 2.2,
                            "impact_score": 2.3,
                        },
                    },
                ],
                id="multiple_cvss",
            ),
        ],
    )
    def test_get_vendor_data_from_vulnerability(self, test_input, expected_output):
        actual_output = api_utils.get_vendor_data_from_vulnerability(test_input)
        assert len(actual_output) == len(expected_output)
        for actual_item, expected_item in zip(actual_output, expected_output):
            assert actual_item == expected_item

    @pytest.mark.parametrize(
        "test_input",
        [
            pytest.param(Vulnerability(cvss=[]), id="empty-list"),
            pytest.param(Vulnerability(cvss=None), id="none"),
        ],
    )
    def test_get_nvd_data_from_vulnerability_no_cvss(self, test_input):
        assert api_utils.get_nvd_data_from_vulnerability(test_input) == []

    @pytest.mark.parametrize(
        "test_input, expected_output",
        [
            pytest.param(
                Vulnerability(
                    vulnerability_id="CVE-x",
                    cvss=[
                        CVSS(
                            version="2.3",
                            base_score=1.1,
                            exploitability_score=1.2,
                            impact_score=1.3,
                        )
                    ],
                ),
                [
                    {
                        "id": "CVE-x",
                        "cvss_v2": {
                            "base_score": 1.1,
                            "exploitability_score": 1.2,
                            "impact_score": 1.3,
                        },
                        "cvss_v3": {
                            "base_score": -1.0,
                            "exploitability_score": -1.0,
                            "impact_score": -1.0,
                        },
                    }
                ],
                id="single_cvss",
            ),
            pytest.param(
                Vulnerability(
                    vulnerability_id="CVE-x",
                    cvss=[
                        CVSS(
                            version="2.3",
                            base_score=1.1,
                            exploitability_score=1.2,
                            impact_score=1.3,
                        ),
                        CVSS(
                            version="3.1",
                            base_score=2.1,
                            exploitability_score=2.2,
                            impact_score=2.3,
                        ),
                    ],
                ),
                [
                    {
                        "id": "CVE-x",
                        "cvss_v2": {
                            "base_score": 1.1,
                            "exploitability_score": 1.2,
                            "impact_score": 1.3,
                        },
                        "cvss_v3": {
                            "base_score": 2.1,
                            "exploitability_score": 2.2,
                            "impact_score": 2.3,
                        },
                    },
                ],
                id="multiple_cvss",
            ),
        ],
    )
    def test_get_nvd_data_from_vulnerability(self, test_input, expected_output):
        actual_output = api_utils.get_nvd_data_from_vulnerability(test_input)
        assert len(actual_output) == len(expected_output)
        for actual_item, expected_item in zip(actual_output, expected_output):
            assert actual_item == expected_item

    @pytest.mark.parametrize(
        "report_type, package_type, expected",
        [
            pytest.param("all", "apkg", True, id="all-apkg"),
            pytest.param("all", "gem", True, id="all-gem"),
            pytest.param("os", "python", False, id="os-python"),
            pytest.param("non-os", "dpkg", False, id="nonos-dpkg"),
            pytest.param("foo", "bar", True, id="foo-bar"),
            pytest.param("os", "bar", True, id="os-bar"),
        ],
    )
    def test_is_type_match(self, report_type, package_type, expected):
        assert api_utils.is_type_match(report_type, package_type) == expected
