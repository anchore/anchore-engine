"""
Tests Feed mapping objects
"""
import json

import pytest

from anchore_engine.services.policy_engine.engine.feeds.mappers import (
    GemMetadata,
    GemPackageDataMapper,
    NpmMetadata,
    NpmPackageDataMapper,
    Vulnerability,
    VulnerabilityFeedDataMapper,
)

test_cve = {
    "Vulnerability": {
        "Description": "Async Http Client (aka AHC or async-http-client) before 1.9.0 skips X.509 certificate verification unless both a keyStore location and a trustStore location are explicitly set, which allows man-in-the-middle attackers to spoof HTTPS servers by presenting an arbitrary certificate during use of a typical AHC configuration, as demonstrated by a configuration that does not send client certificates.",
        "FixedIn": [
            {
                "Name": "async-http-client",
                "NamespaceName": "debian:9",
                "Version": "1.6.5-3",
                "VersionFormat": "dpkg",
                "VendorAdvisory": {
                    "NoAdvisory": False,
                    "AdvisorySummary": [
                        {
                            "ID": "DSA-0000-0",
                            "Link": "https://security-tracker.debian.org/tracker/DSA-0000-0",
                        }
                    ],
                },
            }
        ],
        "Link": "https://security-tracker.debian.org/tracker/CVE-2013-7397",
        "Metadata": {
            "NVD": {"CVSSv2": {"Score": 4.3, "Vectors": "AV:N/AC:M/Au:N/C:N/I:P"}}
        },
        "Name": "CVE-2013-7397",
        "NamespaceName": "debian:9",
        "Severity": "Medium",
    }
}

test_cve2 = {
    "Vulnerability": {
        "Description": "Async Http Client (aka AHC or async-http-client) before 1.9.0 skips X.509 certificate verification unless both a keyStore location and a trustStore location are explicitly set, which allows man-in-the-middle attackers to spoof HTTPS servers by presenting an arbitrary certificate during use of a typical AHC configuration, as demonstrated by a configuration that does not send client certificates.",
        "FixedIn": [],
        "Link": "https://security-tracker.debian.org/tracker/CVE-2013-7397",
        "Metadata": {},
        "Name": "CVE-2013-7397",
        "NamespaceName": "debian:9",
        "Severity": "Medium",
    }
}

test_cve3 = {
    "Vulnerability": {
        "Description": "Async Http Client (aka AHC or async-http-client) before 1.9.0 skips X.509 certificate verification unless both a keyStore location and a trustStore location are explicitly set, which allows man-in-the-middle attackers to spoof HTTPS servers by presenting an arbitrary certificate during use of a typical AHC configuration, as demonstrated by a configuration that does not send client certificates.",
        "FixedIn": [],
        "VulnerableIn": [
            {
                "Name": "notasync-http-client",
                "NamespaceName": "debian:9",
                "Version": "1.2.3.4",
                "VersionFormat": "dpkg",
            }
        ],
        "Link": "https://security-tracker.debian.org/tracker/CVE-2013-7397",
        "Metadata": {},
        "Name": "CVE-2013-7397",
        "NamespaceName": "debian:9",
        "Severity": "Medium",
    }
}

long_cve = {
    "Vulnerability": {
        "Description": "0".join([str(i) for i in range(65000)])
        + "Async Http Client (aka AHC or async-http-client) before 1.9.0 skips X.509 certificate verification unless both a keyStore location and a trustStore location are explicitly set, which allows man-in-the-middle attackers to spoof HTTPS servers by presenting an arbitrary certificate during use of a typical AHC configuration, as demonstrated by a configuration that does not send client certificates.",
        "FixedIn": [],
        "Link": "https://security-tracker.debian.org/tracker/CVE-2013-7397",
        "Metadata": {},
        "Name": "CVE-2013-7397",
        "NamespaceName": "debian:9",
        "Severity": "Medium",
    }
}

vuln_invalid_1 = {"NotAVulnerability": {}}
vuln_invalid_2 = {"Vulnerability": {"Nameer": "SomeCVE"}}

vuln_mapper = VulnerabilityFeedDataMapper(
    feed_name="vulnerabilities", group_name="debian:9", key_name="Name"
)
npm_mapper = NpmPackageDataMapper(
    feed_name="packages", group_name="npm", key_name="name"
)
gem_mapper = GemPackageDataMapper(
    feed_name="packages", group_name="gem", key_name="name"
)


def test_vuln_valid():
    r = vuln_mapper.map(test_cve)
    assert r.id == test_cve["Vulnerability"]["Name"]
    assert r.namespace_name == test_cve["Vulnerability"]["NamespaceName"]
    assert len(r.fixed_in) == 1
    assert len(r.vulnerable_in) == 0
    assert r.severity == test_cve["Vulnerability"]["Severity"]


def test_vuln_invalid():

    with pytest.raises(Exception) as f:
        vuln_mapper.map(vuln_invalid_1)

    with pytest.raises(Exception) as f:
        vuln_mapper.map(vuln_invalid_2)


def test_vuln_overflow():
    r = vuln_mapper.map(long_cve)
    print(
        (
            "Truncated description length: {} from {}".format(
                len(r.description), len(long_cve["Vulnerability"]["Description"])
            )
        )
    )
    assert r.id == test_cve["Vulnerability"]["Name"]
    assert r.namespace_name == test_cve["Vulnerability"]["NamespaceName"]
    assert len(r.fixed_in) == 0
    assert len(r.vulnerable_in) == 0
    assert len(r.description) < 1024 * 64


def test_vuln_full_data(test_data_env):
    c = test_data_env.feed_client
    for g in c.list_feed_groups("vulnerabilities").groups:
        print(("Group: {}".format(g.name)))
        for v in json.loads(c.get_feed_group_data("vulnerabilities", g.name).data).get(
            "data"
        ):
            r = vuln_mapper.map(v)
            assert vuln_validator(r), "Failed validation on: {}".format(v)


def vuln_validator(v):
    if not isinstance(v, Vulnerability):
        return False

    if v.id is None or v.severity is None or v.namespace_name is None:
        return False

    if v.severity not in ["Unknown", "Negligible", "Low", "Medium", "High", "Critical"]:
        return False

    return True


npm_valid = [
    {
        "testnpm": {
            "name": "testnpm",
            "origins": ["origin1", "origin2"],
            "versions": ["1.0.0", "1.0", "1.4"],
            "sourcepkg": "testnpm-src",
            "lics": ["mit", "bsd"],
            "latest": "1.4",
        }
    },
    {
        "testnpm": {
            "name": "testnpm",
            "origins": None,
            "versions": ["1.0.0", "1.0", "1.4"],
            "sourcepkg": "testnpm-src",
            "lics": ["mit", "bsd"],
            "latest": None,
        }
    },
    {
        "testnpm": {
            "name": "testnpm",
            "origins": ["origin1", "origin2"],
            "versions": [],
            "sourcepkg": "testnpm-src",
            "lics": None,
            "latest": "1.4",
        }
    },
]

npm_invalid = [{}, {"failnpm": None}]

overflow_1 = {"name": "MyName", "versions": [str(i) for i in range(100000)]}


def test_npms_valid():
    for e in npm_valid:
        _npm_validator(npm_mapper.map(e))


# @pytest.mark.skip("Since relaxed mappers to support more. Revisit and fix this test")
def test_npms_invalid():
    for e in npm_invalid:
        with pytest.raises(Exception):
            mapped = npm_mapper.map(e)
            _npm_validator(mapped)
            pytest.fail("Should have raised exception on {}".format(e))


def test_npms_full_data(test_data_env):
    c = test_data_env.feed_client
    count = 1
    for v in json.loads(c.get_feed_group_data("packages", "npm").data).get("data", []):
        r = npm_mapper.map(v)
        _npm_validator(r)
        count += 1


def _npm_validator(n):
    assert isinstance(n, NpmMetadata)
    assert n.name, "Name cannot be null or empty: {}".format(n.name)


def test_gems_full_data(test_data_env):
    count = 1
    c = test_data_env.feed_client
    for v in json.loads(c.get_feed_group_data("packages", "gem").data).get("data", []):
        r = gem_mapper.map(v)
        _gem_validator(r)
        count += 1


def _gem_validator(n):
    assert isinstance(n, GemMetadata)
    assert n.name, "Name cannot be null or empty: {}".format(n.name)
    assert n.id, "Id cannot be null or empty: {}".format(n.id)
