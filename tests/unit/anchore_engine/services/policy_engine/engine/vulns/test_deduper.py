import copy
import datetime

import pytest

from anchore_engine.common.models.policy_engine import (
    Artifact,
    FixedArtifact,
    Match,
    NVDReference,
    Vulnerability,
    VulnerabilityMatch,
)
from anchore_engine.services.policy_engine.engine.vulns.dedup import (
    FeedGroupRank,
    ImageVulnerabilitiesDeduplicator,
    RankedVulnerabilityMatch,
    VulnerabilityIdentity,
    transfer_vulnerability_timestamps,
)


class TestFeedGroupRank:
    @pytest.mark.parametrize(
        "test_group, expected_rank",
        [
            pytest.param("nvdv2:cves", 1, id="nvdv2"),
            pytest.param("github:java", 10, id="github"),
            pytest.param("alpine:3.9", 100, id="os-distro"),
            pytest.param("foobar", 100, id="random"),
        ],
    )
    def test_get(self, test_group, expected_rank):
        assert FeedGroupRank().get(test_group) == expected_rank


class TestVulnerabilityIdentity:
    @pytest.mark.parametrize(
        "test_input",
        [
            pytest.param(
                [NVDReference(vulnerability_id="CVE-abc")],
                id="single-nvd",
            ),
            pytest.param(
                [
                    NVDReference(vulnerability_id="CVE-abc"),
                    NVDReference(vulnerability_id="CVE-def"),
                    NVDReference(vulnerability_id="CVE-ghi"),
                ],
                id="multiple-nvd",
            ),
        ],
    )
    def test_from_with_nvd(self, test_input):
        match = VulnerabilityMatch(
            artifact=Artifact(
                name="blah",
                location="/usr/local/java/blah",
                pkg_type="java",
                version="1.2.3maven",
            ),
            vulnerability=Vulnerability(
                feed="vulnerabilities",
                feed_group="whatever:hello",
                vulnerability_id="meh",
            ),
        )
        match.nvd = test_input
        identity_objects = VulnerabilityIdentity.from_match(match)

        assert identity_objects
        assert isinstance(identity_objects, list) and len(identity_objects) == len(
            test_input
        )
        for identity_object, input_nvd in zip(identity_objects, test_input):
            assert identity_object.vuln_id == input_nvd.vulnerability_id
            assert identity_object.pkg_name == match.artifact.name
            assert identity_object.pkg_type == match.artifact.pkg_type
            assert identity_object.pkg_version == match.artifact.version
            assert identity_object.pkg_path == match.artifact.location

    def test_from_without_nvd(self):
        match = VulnerabilityMatch(
            artifact=Artifact(
                name="blah",
                location="/usr/local/java/blah",
                pkg_type="java",
                version="1.2.3maven",
            ),
            vulnerability=Vulnerability(
                feed="vulnerabilities",
                feed_group="whatever:hello",
                vulnerability_id="meh",
            ),
            nvd=[],
        )
        identity_objects = VulnerabilityIdentity.from_match(match)

        assert identity_objects
        assert isinstance(identity_objects, list) and len(identity_objects) == 1

        identity_object = identity_objects[0]
        assert identity_object.vuln_id == match.vulnerability.vulnerability_id
        assert identity_object.pkg_name == match.artifact.name
        assert identity_object.pkg_type == match.artifact.pkg_type
        assert identity_object.pkg_version == match.artifact.version
        assert identity_object.pkg_path == match.artifact.location

    @pytest.mark.parametrize(
        "lhs, rhs, expected",
        [
            pytest.param(
                VulnerabilityMatch(
                    vulnerability=Vulnerability(
                        feed="trusty",
                        feed_group="trusty:chameleon",
                        vulnerability_id="meh",
                    ),
                    nvd=[NVDReference(vulnerability_id="CVE-abc")],
                ),
                VulnerabilityMatch(
                    Vulnerability(
                        feed="hedgehog",
                        feed_group="hedgy:thorny",
                        vulnerability_id="foo",
                    ),
                    nvd=[NVDReference(vulnerability_id="CVE-abc")],
                ),
                True,
                id="equal-different-namespaces",
            ),
            pytest.param(
                VulnerabilityMatch(
                    vulnerability=Vulnerability(
                        feed="trusty",
                        feed_group="trusty:chameleon",
                        vulnerability_id="meh",
                    ),
                    nvd=[
                        NVDReference(vulnerability_id="CVE-abc"),
                        NVDReference(vulnerability_id="CVE-def"),
                        NVDReference(vulnerability_id="CVE-ghi"),
                    ],
                ),
                VulnerabilityMatch(
                    vulnerability=Vulnerability(
                        feed="hedgehog",
                        feed_group="hedgy:thorny",
                        vulnerability_id="foo",
                    ),
                    nvd=[
                        NVDReference(vulnerability_id="CVE-abc"),
                        NVDReference(vulnerability_id="CVE-def"),
                        NVDReference(vulnerability_id="CVE-ghi"),
                    ],
                ),
                True,
                id="equal-multiple-cvss",
            ),
            pytest.param(
                VulnerabilityMatch(
                    vulnerability=Vulnerability(
                        feed="trusty",
                        feed_group="trusty:chameleon",
                        vulnerability_id="meh",
                    ),
                    nvd=[NVDReference(vulnerability_id="CVE-abc")],
                ),
                VulnerabilityMatch(
                    vulnerability=Vulnerability(
                        feed="hedgehog",
                        feed_group="hedgy:thorny",
                        vulnerability_id="foo",
                    ),
                    nvd=[NVDReference(vulnerability_id="CVE-def")],
                ),
                False,
                id="not-equal",
            ),
        ],
    )
    def test_equality_constant_artifact(self, lhs, rhs, expected):
        artifact = Artifact(
            name="blah",
            location="/usr/local/java/blah",
            pkg_type="java",
            version="1.2.3maven",
        )
        lhs.artifact = artifact

        rhs.artifact = artifact

        assert (
            VulnerabilityIdentity.from_match(lhs)
            == VulnerabilityIdentity.from_match(rhs)
        ) == expected

    @pytest.mark.parametrize("count", [1, 2, 3, 4, 5])
    def test_hash(self, count):
        record = VulnerabilityIdentity(
            vuln_id="meh",
            pkg_name="blah",
            pkg_version="1.2.3maven",
            pkg_type="java",
            pkg_path="blah",
        )

        test_input = [record for x in range(count)]
        result = set(test_input)
        assert result and len(result) == 1


class TestRankedVulnerabilityMatch:
    def test_from(self):
        match = VulnerabilityMatch(
            artifact=Artifact(
                name="blah",
                location="/usr/local/java/blah",
                pkg_type="java",
                version="1.2.3maven",
            ),
            vulnerability=Vulnerability(
                feed="vulnerabilities",
                feed_group="whatever:hello",
                vulnerability_id="meh",
            ),
            nvd=[NVDReference(vulnerability_id="CVE-abc")],
        )
        rank_strategy = FeedGroupRank()
        ranked_match = RankedVulnerabilityMatch.from_match(match, FeedGroupRank())

        assert ranked_match
        assert ranked_match.vuln_id == match.vulnerability.vulnerability_id
        assert ranked_match.vuln_namespace == match.vulnerability.feed_group
        assert ranked_match.pkg_name == match.artifact.name
        assert ranked_match.pkg_type == match.artifact.pkg_type
        assert ranked_match.pkg_version == match.artifact.version
        assert ranked_match.pkg_path == match.artifact.location
        assert ranked_match.rank == rank_strategy.__default__

    @pytest.mark.parametrize(
        "lhs, rhs, expected",
        [
            pytest.param(
                VulnerabilityMatch(
                    vulnerability=Vulnerability(
                        feed="trusty",
                        feed_group="trusty:chameleon",
                        vulnerability_id="meh",
                    ),
                    nvd=[NVDReference(vulnerability_id="CVE-abc")],
                ),
                VulnerabilityMatch(
                    vulnerability=Vulnerability(
                        feed="hedgehog",
                        feed_group="hedgy:thorny",
                        vulnerability_id="foo",
                    ),
                    nvd=[NVDReference(vulnerability_id="CVE-abc")],
                ),
                False,
                id="not-equal-different-ids",
            ),
            pytest.param(
                VulnerabilityMatch(
                    vulnerability=Vulnerability(
                        feed="trusty",
                        feed_group="trusty:chameleon",
                        vulnerability_id="meh",
                    ),
                    nvd=[
                        NVDReference(vulnerability_id="CVE-abc"),
                        NVDReference(vulnerability_id="CVE-def"),
                        NVDReference(vulnerability_id="CVE-ghi"),
                    ],
                ),
                VulnerabilityMatch(
                    vulnerability=Vulnerability(
                        feed="trusty",
                        feed_group="trusty:chameleon",
                        vulnerability_id="meh",
                    ),
                    nvd=[NVDReference(vulnerability_id="CVE-abc")],
                ),
                True,
                id="equal-different-cvss",
            ),
            pytest.param(
                VulnerabilityMatch(
                    vulnerability=Vulnerability(
                        feed="trusty",
                        feed_group="trusty:chameleon",
                        vulnerability_id="meh",
                    ),
                    nvd=[NVDReference(vulnerability_id="CVE-abc")],
                ),
                VulnerabilityMatch(
                    vulnerability=Vulnerability(
                        feed="trusty",
                        feed_group="trusty:python",
                        vulnerability_id="meh",
                    ),
                    nvd=[NVDReference(vulnerability_id="CVE-abc")],
                ),
                False,
                id="not-equal-different-namespaces",
            ),
        ],
    )
    def test_equality_constant_artifact(self, lhs, rhs, expected):
        artifact = Artifact(
            name="blah",
            location="/usr/local/java/blah",
            pkg_type="java",
            version="1.2.3maven",
        )
        lhs.artifact = artifact

        rhs.artifact = artifact

        assert (
            RankedVulnerabilityMatch.from_match(lhs, FeedGroupRank())
            == RankedVulnerabilityMatch.from_match(rhs, FeedGroupRank())
        ) == expected

    @pytest.mark.parametrize("count", [1, 2, 3, 4, 5])
    def test_hash_empty_match(self, count):
        record = RankedVulnerabilityMatch(
            vuln_id="meh",
            vuln_namespace="trusty:chameleon",
            pkg_name="blah",
            pkg_version="1.2.3maven",
            pkg_type="java",
            pkg_path="blah",
            rank=100,
            match_obj=VulnerabilityMatch(),
        )

        test_input = [record for x in range(count)]
        result = set(test_input)
        assert result and len(result) == 1

    @pytest.mark.parametrize(
        "test_input",
        [
            pytest.param(
                [
                    VulnerabilityMatch(
                        artifact=Artifact(
                            name="blah",
                            location="/usr/local/java/blah",
                            pkg_type="java",
                            version="1.2.3maven",
                        ),
                        vulnerability=Vulnerability(
                            feed="twisty",
                            feed_group="twisty:python",
                            vulnerability_id="meh",
                        ),
                        nvd=[NVDReference(vulnerability_id="CVE-abc")],
                    ),
                    VulnerabilityMatch(
                        artifact=Artifact(
                            name="foo",
                            location="/usr/local/java/foo",
                            pkg_type="unknown",
                            version="1.2.3",
                        ),
                        vulnerability=Vulnerability(
                            feed="tricky",
                            feed_group="tricky:chameleon",
                            vulnerability_id="meh",
                        ),
                        nvd=[NVDReference(vulnerability_id="CVE-def")],
                    ),
                ],
                id="different-matches",
            ),
            pytest.param(
                [
                    VulnerabilityMatch(
                        artifact=Artifact(
                            name="blah",
                            location="/usr/local/java/blah",
                            pkg_type="java",
                            version="1.2.3maven",
                        ),
                        vulnerability=Vulnerability(
                            feed="twisty",
                            feed_group="twisty:python",
                            vulnerability_id="meh",
                        ),
                        nvd=[NVDReference(vulnerability_id="CVE-abc")],
                    ),
                ]
                * 3,
                id="same-matches",
            ),
        ],
    )
    def test_hash(self, test_input):
        vuln_rank_objects = [
            RankedVulnerabilityMatch(
                vuln_id="meh",
                vuln_namespace="trusty:chameleon",
                pkg_name="blah",
                pkg_version="1.2.3maven",
                pkg_type="java",
                pkg_path="/usr/local/blah",
                rank=100,
                match_obj=item,
            )
            for item in test_input
        ]
        result = set(vuln_rank_objects)
        assert result and len(result) == 1

        result = list(result)[0]
        assert result.vuln_id == "meh"
        assert result.vuln_namespace == "trusty:chameleon"
        assert result.pkg_name == "blah"
        assert result.pkg_type == "java"
        assert result.pkg_path == "/usr/local/blah"
        assert result.rank == 100


class TestImageVulnerabilitiesDeduplicator:
    @pytest.mark.parametrize(
        "test_input, expected_index",
        [
            pytest.param(
                [
                    VulnerabilityMatch(
                        vulnerability=Vulnerability(
                            feed="vulnerabilities",
                            feed_group="nvdv2:cves",
                            vulnerability_id="CVE-2019-12904",
                        ),
                        nvd=[NVDReference(vulnerability_id="CVE-2019-12904")],
                    ),
                    VulnerabilityMatch(
                        vulnerability=Vulnerability(
                            feed="vulnerabilities",
                            feed_group="ubuntu:20.04",
                            vulnerability_id="CVE-2019-12904",
                        ),
                        nvd=[NVDReference(vulnerability_id="CVE-2019-12904")],
                    ),
                ],
                1,
                id="different-namespaces",
            ),
            pytest.param(
                [
                    VulnerabilityMatch(
                        vulnerability=Vulnerability(
                            feed="vulnerabilities",
                            feed_group="nvdv2:cves",
                            vulnerability_id="CVE-2019-12904",
                        ),
                        nvd=[NVDReference(vulnerability_id="CVE-2019-12904")],
                    ),
                    VulnerabilityMatch(
                        vulnerability=Vulnerability(
                            feed="vulnerabilities",
                            feed_group="github:java",
                            vulnerability_id="GHSA-foobar",
                        ),
                        nvd=[NVDReference(vulnerability_id="CVE-2019-12904")],
                    ),
                ],
                1,
                id="different-identifiers",
            ),
            pytest.param(
                [
                    VulnerabilityMatch(
                        vulnerability=Vulnerability(
                            feed="vulnerabilities",
                            feed_group="github:java",
                            vulnerability_id="GHSA-foobar",
                        ),
                        nvd=[NVDReference(vulnerability_id="CVE-2019-12904")],
                    ),
                    VulnerabilityMatch(
                        vulnerability=Vulnerability(
                            feed="vulnerabilities",
                            feed_group="ubuntu:20.04",
                            vulnerability_id="CVE-2019-12904",
                        ),
                        nvd=[NVDReference(vulnerability_id="CVE-2019-12904")],
                    ),
                ],
                1,
                id="non-nvd-namespaces",
            ),
            pytest.param(
                [
                    VulnerabilityMatch(
                        vulnerability=Vulnerability(
                            feed="vulnerabilities",
                            feed_group="nvdv2:cves",
                            vulnerability_id="CVE-2019-12904",
                        ),
                        nvd=[NVDReference(vulnerability_id="CVE-2019-12904")],
                    ),
                    VulnerabilityMatch(
                        vulnerability=Vulnerability(
                            feed="vulnerabilities",
                            feed_group="ubuntu:20.04",
                            vulnerability_id="CVE-2019-12904",
                        ),
                        nvd=[],
                    ),
                ],
                1,
                id="no-nvd-refs",
            ),
            pytest.param(
                [
                    VulnerabilityMatch(
                        vulnerability=Vulnerability(
                            feed="vulnerabilities",
                            feed_group="nvdv2:cves",
                            vulnerability_id="CVE-2019-12904",
                        ),
                        nvd=[NVDReference(vulnerability_id="CVE-2019-12345")],
                    ),
                    VulnerabilityMatch(
                        vulnerability=Vulnerability(
                            feed="vulnerabilities",
                            feed_group="nvdv2:cves",
                            vulnerability_id="CVE-2019-12904",
                        ),
                        nvd=[NVDReference(vulnerability_id="CVE-2019-12904")],
                    ),
                    VulnerabilityMatch(
                        vulnerability=Vulnerability(
                            feed="vulnerabilities",
                            feed_group="github:java",
                            vulnerability_id="GHSA-foobar",
                        ),
                        nvd=[
                            NVDReference(vulnerability_id="CVE-2019-12904"),
                            NVDReference(vulnerability_id="CVE-2019-12345"),
                        ],
                    ),
                ],
                2,
                id="multiple-nvd-refs",
            ),
        ],
    )
    def test_execute(self, test_input, expected_index):
        artifact = Artifact(
            name="blah",
            location="/usr/local/java/blah",
            pkg_type="java",
            version="1.2.3maven",
        )
        for item in test_input:
            item.artifact = artifact

        results = ImageVulnerabilitiesDeduplicator(FeedGroupRank()).execute(test_input)
        assert len(results) == 1

        actual = results[0].vulnerability
        expected = test_input[expected_index]
        assert actual.vulnerability_id == expected.vulnerability.vulnerability_id
        assert actual.feed_group == expected.vulnerability.feed_group

    @pytest.mark.parametrize("count", [1, 2, 3, 4, 5])
    def test_execute_absolute_duplicates(self, count):
        a = VulnerabilityMatch(
            artifact=Artifact(
                name="blah",
                location="/usr/local/java/blah",
                pkg_type="java",
                version="1.2.3maven",
            ),
            vulnerability=Vulnerability(
                feed="vulnerabilities",
                feed_group="whatever:hello",
                vulnerability_id="meh",
            ),
            nvd=[NVDReference(vulnerability_id="CVE-2019-12904")],
        )

        input_matches = [a for x in range(count)]

        results = ImageVulnerabilitiesDeduplicator(FeedGroupRank()).execute(
            input_matches
        )
        assert len(results) == 1

    @pytest.mark.parametrize(
        "test_input",
        [pytest.param([], id="empty-list"), pytest.param(None, id="none")],
    )
    def test_execute_invalid_input(self, test_input):
        assert (
            ImageVulnerabilitiesDeduplicator(FeedGroupRank()).execute(test_input)
            == list()
        )


class TestTimestampMerger:
    @pytest.mark.parametrize(
        "test_source, test_destination, expected",
        [
            pytest.param([], [], [], id="empty"),
            pytest.param(None, None, [], id="none"),
            pytest.param([], None, [], id="destination-none"),
            pytest.param(None, [], [], id="source-none"),
        ],
    )
    def test_transfer_vulnerability_timestamps_invalid_input(
        self, test_source, test_destination, expected
    ):
        assert (
            transfer_vulnerability_timestamps(
                source=test_source, destination=test_destination
            )
            == expected
        )

    @pytest.mark.parametrize(
        "test_source, test_destination",
        [
            pytest.param(
                datetime.datetime.utcnow(),
                datetime.datetime.utcnow() + datetime.timedelta(days=1),
                id="source-behind-destination",
            ),
            pytest.param(
                datetime.datetime.utcnow() + datetime.timedelta(days=1),
                datetime.datetime.utcnow(),
                id="source-ahead-destination",
            ),
        ],
    )
    def test_transfer_vulnerability_timestamps_single(
        self, test_source, test_destination
    ):
        random = VulnerabilityMatch(
            artifact=Artifact(
                name="blah",
                location="/usr/local/java/blah",
                pkg_type="java",
                version="1.2.3maven",
            ),
            vulnerability=Vulnerability(
                feed="vulnerabilities",
                feed_group="whatever:hello",
                vulnerability_id="meh",
            ),
            fix=FixedArtifact(),
        )

        source = copy.deepcopy(random)
        source.match = Match(detected_at=test_source)

        destination = copy.deepcopy(random)
        destination.match = Match(detected_at=test_destination)

        results = transfer_vulnerability_timestamps(
            source=[source], destination=[destination]
        )

        assert results and len(results) == 1
        assert results[0].match.detected_at == test_source

    def test_transfer_vulnerability_timestamps_multiple(self):
        dest_ts = datetime.datetime.utcnow()
        src_ts = datetime.datetime.utcnow() - datetime.timedelta(days=1)

        destination = [
            VulnerabilityMatch(
                artifact=Artifact(
                    name="blah",
                    location="/usr/local/java/blah",
                    pkg_type="java",
                    version="1.2.3maven",
                ),
                vulnerability=Vulnerability(
                    feed="vulnerabilities",
                    feed_group="whatever:hello",
                    vulnerability_id="meh",
                ),
                match=Match(detected_at=dest_ts),
                fix=FixedArtifact(),
            ),
            VulnerabilityMatch(
                artifact=Artifact(
                    name="blah",
                    location="/usr/local/java/blah",
                    pkg_type="java",
                    version="1.2.3maven",
                ),
                vulnerability=Vulnerability(
                    feed="vulnerabilities",
                    feed_group="whatever:hello",
                    vulnerability_id="foo",
                ),
                match=Match(detected_at=dest_ts),
                fix=FixedArtifact(),
            ),
        ]

        source = [
            VulnerabilityMatch(
                artifact=Artifact(
                    name="blah",
                    location="/usr/local/java/blah",
                    pkg_type="java",
                    version="1.2.3maven",
                ),
                vulnerability=Vulnerability(
                    feed="vulnerabilities",
                    feed_group="whatever:hello",
                    vulnerability_id="meh",
                ),
                match=Match(detected_at=src_ts),
                fix=FixedArtifact(),
            )
        ]

        results = transfer_vulnerability_timestamps(
            source=source, destination=destination
        )

        assert results and len(results) == 2
        for result in results:
            if (
                result.vulnerability.vulnerability_id
                == source[0].vulnerability.vulnerability_id
            ):
                assert result.match.detected_at == src_ts
            else:
                assert result.match.detected_at == dest_ts

    @pytest.mark.parametrize(
        "test_source, test_destination, expected",
        [
            pytest.param(
                FixedArtifact(
                    versions=[], observed_at=datetime.datetime.utcfromtimestamp(0)
                ),
                FixedArtifact(
                    versions=[], observed_at=datetime.datetime.utcfromtimestamp(10)
                ),
                datetime.datetime.utcfromtimestamp(10),
                id="empty-versions",
            ),
            pytest.param(
                FixedArtifact(
                    versions=None, observed_at=datetime.datetime.utcfromtimestamp(0)
                ),
                FixedArtifact(
                    versions=None, observed_at=datetime.datetime.utcfromtimestamp(10)
                ),
                datetime.datetime.utcfromtimestamp(10),
                id="none-versions",
            ),
            pytest.param(
                FixedArtifact(
                    versions=[], observed_at=datetime.datetime.utcfromtimestamp(0)
                ),
                FixedArtifact(
                    versions=["foo"], observed_at=datetime.datetime.utcfromtimestamp(10)
                ),
                datetime.datetime.utcfromtimestamp(10),
                id="different-versions",
            ),
            pytest.param(
                FixedArtifact(
                    versions=["bar", "foo", "meh"],
                    observed_at=datetime.datetime.utcfromtimestamp(0),
                ),
                FixedArtifact(
                    versions=["meh", "bar", "foo"],
                    observed_at=datetime.datetime.utcfromtimestamp(10),
                ),
                datetime.datetime.utcfromtimestamp(0),
                id="same-versions-ordered-differently",
            ),
        ],
    )
    def test_transfer_vulnerability_timestamps_fix_observed_at(
        self, test_source, test_destination, expected
    ):
        random = VulnerabilityMatch(
            artifact=Artifact(
                name="blah",
                location="/usr/local/java/blah",
                pkg_type="java",
                version="1.2.3maven",
            ),
            vulnerability=Vulnerability(
                feed="vulnerabilities",
                feed_group="whatever:hello",
                vulnerability_id="meh",
            ),
            match=Match(detected_at=datetime.datetime.utcnow()),
        )

        source = copy.deepcopy(random)
        source.fix = test_source

        destination = copy.deepcopy(random)
        destination.fix = test_destination

        results = transfer_vulnerability_timestamps(
            source=[source], destination=[destination]
        )

        assert results and len(results) == 1
        assert results[0].fix.observed_at == expected
