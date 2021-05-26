import pytest

from anchore_engine.common.models.policy_engine import (
    VulnerabilityMatch,
    Vulnerability,
    Artifact,
    CvssCombined,
    Match,
)
from anchore_engine.services.policy_engine.engine.vulns.dedup import (
    ImageVulnerabilitiesDeduplicator,
    VulnerabilityIdentity,
    RankedVulnerabilityMatch,
    FeedGroupRank,
    transfer_vulnerability_timestamps,
)
import datetime
import copy


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
                [CvssCombined(id="CVE-abc")],
                id="single-cvss",
            ),
            pytest.param(
                [
                    CvssCombined(id="CVE-abc"),
                    CvssCombined(id="CVE-def"),
                    CvssCombined(id="CVE-ghi"),
                ],
                id="multiple-cvss",
            ),
        ],
    )
    def test_from_with_cvss(self, test_input):
        match = VulnerabilityMatch(
            artifact=Artifact(
                name="blah",
                pkg_path="/usr/local/java/blah",
                pkg_type="java",
                version="1.2.3maven",
            ),
            vulnerability=Vulnerability(
                feed="vulnerabilities",
                feed_group="whatever:hello",
                vulnerability_id="meh",
                cvss_scores_nvd=test_input,
            ),
        )
        identity_objects = VulnerabilityIdentity.from_match(match)

        assert identity_objects
        assert isinstance(identity_objects, list) and len(identity_objects) == len(
            test_input
        )
        for identity_object, input_cvss in zip(identity_objects, test_input):
            assert identity_object.vuln_id == input_cvss.id
            assert identity_object.pkg_name == match.artifact.name
            assert identity_object.pkg_type == match.artifact.pkg_type
            assert identity_object.pkg_version == match.artifact.version
            assert identity_object.pkg_path == match.artifact.pkg_path

    def test_from_no_cvss(self):
        match = VulnerabilityMatch(
            artifact=Artifact(
                name="blah",
                pkg_path="/usr/local/java/blah",
                pkg_type="java",
                version="1.2.3maven",
            ),
            vulnerability=Vulnerability(
                feed="vulnerabilities",
                feed_group="whatever:hello",
                vulnerability_id="meh",
                cvss_scores_nvd=[],
            ),
        )
        identity_objects = VulnerabilityIdentity.from_match(match)

        assert identity_objects
        assert isinstance(identity_objects, list) and len(identity_objects) == 1

        identity_object = identity_objects[0]
        assert identity_object.vuln_id == match.vulnerability.vulnerability_id
        assert identity_object.pkg_name == match.artifact.name
        assert identity_object.pkg_type == match.artifact.pkg_type
        assert identity_object.pkg_version == match.artifact.version
        assert identity_object.pkg_path == match.artifact.pkg_path

    @pytest.mark.parametrize(
        "lhs, rhs, expected",
        [
            pytest.param(
                Vulnerability(
                    feed="trusty",
                    feed_group="trusty:chameleon",
                    vulnerability_id="meh",
                    cvss_scores_nvd=[CvssCombined(id="CVE-abc")],
                ),
                Vulnerability(
                    feed="hedgehog",
                    feed_group="hedgy:thorny",
                    vulnerability_id="foo",
                    cvss_scores_nvd=[CvssCombined(id="CVE-abc")],
                ),
                True,
                id="equal-different-namespaces",
            ),
            pytest.param(
                Vulnerability(
                    feed="trusty",
                    feed_group="trusty:chameleon",
                    vulnerability_id="meh",
                    cvss_scores_nvd=[
                        CvssCombined(id="CVE-abc"),
                        CvssCombined(id="CVE-def"),
                        CvssCombined(id="CVE-ghi"),
                    ],
                ),
                Vulnerability(
                    feed="hedgehog",
                    feed_group="hedgy:thorny",
                    vulnerability_id="foo",
                    cvss_scores_nvd=[
                        CvssCombined(id="CVE-abc"),
                        CvssCombined(id="CVE-def"),
                        CvssCombined(id="CVE-ghi"),
                    ],
                ),
                True,
                id="equal-multiple-cvss",
            ),
            pytest.param(
                Vulnerability(
                    feed="trusty",
                    feed_group="trusty:chameleon",
                    vulnerability_id="meh",
                    cvss_scores_nvd=[CvssCombined(id="CVE-abc")],
                ),
                Vulnerability(
                    feed="hedgehog",
                    feed_group="hedgy:thorny",
                    vulnerability_id="foo",
                    cvss_scores_nvd=[CvssCombined(id="CVE-def")],
                ),
                False,
                id="not-equal",
            ),
        ],
    )
    def test_equality_constant_artifact(self, lhs, rhs, expected):
        artifact = Artifact(
            name="blah",
            pkg_path="/usr/local/java/blah",
            pkg_type="java",
            version="1.2.3maven",
        )
        lhs_record = VulnerabilityMatch(
            artifact=artifact,
            vulnerability=lhs,
        )

        rhs_record = VulnerabilityMatch(
            artifact=artifact,
            vulnerability=rhs,
        )

        assert (
            VulnerabilityIdentity.from_match(lhs_record)
            == VulnerabilityIdentity.from_match(rhs_record)
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
                pkg_path="/usr/local/java/blah",
                pkg_type="java",
                version="1.2.3maven",
            ),
            vulnerability=Vulnerability(
                feed="vulnerabilities",
                feed_group="whatever:hello",
                vulnerability_id="meh",
                cvss_scores_nvd=[CvssCombined(id="CVE-abc")],
            ),
        )
        rank_strategy = FeedGroupRank()
        ranked_match = RankedVulnerabilityMatch.from_match(match, FeedGroupRank())

        assert ranked_match
        assert ranked_match.vuln_id == match.vulnerability.vulnerability_id
        assert ranked_match.vuln_namespace == match.vulnerability.feed_group
        assert ranked_match.pkg_name == match.artifact.name
        assert ranked_match.pkg_type == match.artifact.pkg_type
        assert ranked_match.pkg_version == match.artifact.version
        assert ranked_match.pkg_path == match.artifact.pkg_path
        assert ranked_match.rank == rank_strategy.__default__

    @pytest.mark.parametrize(
        "lhs, rhs, expected",
        [
            pytest.param(
                Vulnerability(
                    feed="trusty",
                    feed_group="trusty:chameleon",
                    vulnerability_id="meh",
                    cvss_scores_nvd=[CvssCombined(id="CVE-abc")],
                ),
                Vulnerability(
                    feed="hedgehog",
                    feed_group="hedgy:thorny",
                    vulnerability_id="foo",
                    cvss_scores_nvd=[CvssCombined(id="CVE-abc")],
                ),
                False,
                id="not-equal-different-ids",
            ),
            pytest.param(
                Vulnerability(
                    feed="trusty",
                    feed_group="trusty:chameleon",
                    vulnerability_id="meh",
                    cvss_scores_nvd=[
                        CvssCombined(id="CVE-abc"),
                        CvssCombined(id="CVE-def"),
                        CvssCombined(id="CVE-ghi"),
                    ],
                ),
                Vulnerability(
                    feed="trusty",
                    feed_group="trusty:chameleon",
                    vulnerability_id="meh",
                    cvss_scores_nvd=[
                        CvssCombined(id="CVE-abc"),
                    ],
                ),
                True,
                id="equal-different-cvss",
            ),
            pytest.param(
                Vulnerability(
                    feed="trusty",
                    feed_group="trusty:chameleon",
                    vulnerability_id="meh",
                    cvss_scores_nvd=[CvssCombined(id="CVE-abc")],
                ),
                Vulnerability(
                    feed="trusty",
                    feed_group="trusty:python",
                    vulnerability_id="meh",
                    cvss_scores_nvd=[CvssCombined(id="CVE-abc")],
                ),
                False,
                id="not-equal-different-namespaces",
            ),
        ],
    )
    def test_equality_constant_artifact(self, lhs, rhs, expected):
        artifact = Artifact(
            name="blah",
            pkg_path="/usr/local/java/blah",
            pkg_type="java",
            version="1.2.3maven",
        )
        lhs_record = VulnerabilityMatch(
            artifact=artifact,
            vulnerability=lhs,
        )

        rhs_record = VulnerabilityMatch(
            artifact=artifact,
            vulnerability=rhs,
        )

        assert (
            RankedVulnerabilityMatch.from_match(lhs_record, FeedGroupRank())
            == RankedVulnerabilityMatch.from_match(rhs_record, FeedGroupRank())
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
                            pkg_path="/usr/local/java/blah",
                            pkg_type="java",
                            version="1.2.3maven",
                        ),
                        vulnerability=Vulnerability(
                            feed="twisty",
                            feed_group="twisty:python",
                            vulnerability_id="meh",
                            cvss_scores_nvd=[CvssCombined(id="CVE-abc")],
                        ),
                    ),
                    VulnerabilityMatch(
                        artifact=Artifact(
                            name="foo",
                            pkg_path="/usr/local/java/foo",
                            pkg_type="unknown",
                            version="1.2.3",
                        ),
                        vulnerability=Vulnerability(
                            feed="tricky",
                            feed_group="tricky:chameleon",
                            vulnerability_id="meh",
                            cvss_scores_nvd=[CvssCombined(id="CVE-def")],
                        ),
                    ),
                ],
                id="different-matches",
            ),
            pytest.param(
                [
                    VulnerabilityMatch(
                        artifact=Artifact(
                            name="blah",
                            pkg_path="/usr/local/java/blah",
                            pkg_type="java",
                            version="1.2.3maven",
                        ),
                        vulnerability=Vulnerability(
                            feed="twisty",
                            feed_group="twisty:python",
                            vulnerability_id="meh",
                            cvss_scores_nvd=[CvssCombined(id="CVE-abc")],
                        ),
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
                    Vulnerability(
                        feed="vulnerabilities",
                        feed_group="nvdv2:cves",
                        vulnerability_id="CVE-2019-12904",
                        cvss_scores_nvd=[CvssCombined(id="CVE-2019-12904")],
                    ),
                    Vulnerability(
                        feed="vulnerabilities",
                        feed_group="ubuntu:20.04",
                        vulnerability_id="CVE-2019-12904",
                        cvss_scores_nvd=[CvssCombined(id="CVE-2019-12904")],
                    ),
                ],
                1,
                id="different-namespaces",
            ),
            pytest.param(
                [
                    Vulnerability(
                        feed="vulnerabilities",
                        feed_group="nvdv2:cves",
                        vulnerability_id="CVE-2019-12904",
                        cvss_scores_nvd=[CvssCombined(id="CVE-2019-12904")],
                    ),
                    Vulnerability(
                        feed="vulnerabilities",
                        feed_group="github:java",
                        vulnerability_id="GHSA-foobar",
                        cvss_scores_nvd=[CvssCombined(id="CVE-2019-12904")],
                    ),
                ],
                1,
                id="different-identifiers",
            ),
            pytest.param(
                [
                    Vulnerability(
                        feed="vulnerabilities",
                        feed_group="github:java",
                        vulnerability_id="GHSA-foobar",
                        cvss_scores_nvd=[CvssCombined(id="CVE-2019-12904")],
                    ),
                    Vulnerability(
                        feed="vulnerabilities",
                        feed_group="ubuntu:20.04",
                        vulnerability_id="CVE-2019-12904",
                        cvss_scores_nvd=[CvssCombined(id="CVE-2019-12904")],
                    ),
                ],
                1,
                id="non-nvd-namespaces",
            ),
            pytest.param(
                [
                    Vulnerability(
                        feed="vulnerabilities",
                        feed_group="nvdv2:cves",
                        vulnerability_id="CVE-2019-12904",
                        cvss_scores_nvd=[CvssCombined(id="CVE-2019-12904")],
                    ),
                    Vulnerability(
                        feed="vulnerabilities",
                        feed_group="ubuntu:20.04",
                        vulnerability_id="CVE-2019-12904",
                        cvss_scores_nvd=[],
                    ),
                ],
                1,
                id="no-nvd-refs",
            ),
            pytest.param(
                [
                    Vulnerability(
                        feed="vulnerabilities",
                        feed_group="nvdv2:cves",
                        vulnerability_id="CVE-2019-12904",
                        cvss_scores_nvd=[CvssCombined(id="CVE-2019-12345")],
                    ),
                    Vulnerability(
                        feed="vulnerabilities",
                        feed_group="nvdv2:cves",
                        vulnerability_id="CVE-2019-12904",
                        cvss_scores_nvd=[CvssCombined(id="CVE-2019-12904")],
                    ),
                    Vulnerability(
                        feed="vulnerabilities",
                        feed_group="github:java",
                        vulnerability_id="GHSA-foobar",
                        cvss_scores_nvd=[
                            CvssCombined(id="CVE-2019-12904"),
                            CvssCombined(id="CVE-2019-12345"),
                        ],
                    ),
                ],
                2,
                id="multiple-nvd-refs",
            ),
        ],
    )
    def test_execute(self, test_input, expected_index):
        matches_input = [
            VulnerabilityMatch(
                artifact=Artifact(
                    name="blah",
                    pkg_path="/usr/local/java/blah",
                    pkg_type="java",
                    version="1.2.3maven",
                ),
                vulnerability=item,
            )
            for item in test_input
        ]

        results = ImageVulnerabilitiesDeduplicator(FeedGroupRank()).execute(
            matches_input
        )
        assert len(results) == 1

        actual = results[0].vulnerability
        expected = test_input[expected_index]
        assert actual.vulnerability_id == expected.vulnerability_id
        assert actual.feed_group == expected.feed_group

    @pytest.mark.parametrize("count", [1, 2, 3, 4, 5])
    def test_execute_absolute_duplicates(self, count):
        a = VulnerabilityMatch(
            artifact=Artifact(
                name="blah",
                pkg_path="/usr/local/java/blah",
                pkg_type="java",
                version="1.2.3maven",
            ),
            vulnerability=Vulnerability(
                feed="vulnerabilities",
                feed_group="whatever:hello",
                vulnerability_id="meh",
                cvss_scores_nvd=[CvssCombined(id="CVE-2019-12904")],
            ),
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
                pkg_path="/usr/local/java/blah",
                pkg_type="java",
                version="1.2.3maven",
            ),
            vulnerability=Vulnerability(
                feed="vulnerabilities",
                feed_group="whatever:hello",
                vulnerability_id="meh",
            ),
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
                    pkg_path="/usr/local/java/blah",
                    pkg_type="java",
                    version="1.2.3maven",
                ),
                vulnerability=Vulnerability(
                    feed="vulnerabilities",
                    feed_group="whatever:hello",
                    vulnerability_id="meh",
                ),
                match=Match(detected_at=dest_ts),
            ),
            VulnerabilityMatch(
                artifact=Artifact(
                    name="blah",
                    pkg_path="/usr/local/java/blah",
                    pkg_type="java",
                    version="1.2.3maven",
                ),
                vulnerability=Vulnerability(
                    feed="vulnerabilities",
                    feed_group="whatever:hello",
                    vulnerability_id="foo",
                ),
                match=Match(detected_at=dest_ts),
            ),
        ]

        source = [
            VulnerabilityMatch(
                artifact=Artifact(
                    name="blah",
                    pkg_path="/usr/local/java/blah",
                    pkg_type="java",
                    version="1.2.3maven",
                ),
                vulnerability=Vulnerability(
                    feed="vulnerabilities",
                    feed_group="whatever:hello",
                    vulnerability_id="meh",
                ),
                match=Match(detected_at=src_ts),
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
