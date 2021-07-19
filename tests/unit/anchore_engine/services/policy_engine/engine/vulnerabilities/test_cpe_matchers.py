import datetime
from typing import List, Tuple

import pytest

import anchore_engine.db.entities.common
import anchore_engine.services.policy_engine.engine.vulns.cpe_matchers
import anchore_engine.services.policy_engine.engine.vulns.db
from anchore_engine.db.entities.policy_engine import (
    Vulnerability,
    CpeV2Vulnerability,
    ImageCpe,
    DistroNamespace,
    DistroTuple,
    ImagePackage,
)
from anchore_engine.services.policy_engine.engine.vulns.cpe_matchers import (
    cve_ids_for_vuln_record,
    filter_secdb_entries,
    cpes_for_image_packages,
)
from anchore_engine.services.policy_engine.engine.vulns.cpes import (
    dedup_cpe_vulnerabilities,
)


@pytest.mark.parametrize(
    "record, expected",
    [
        (
            Vulnerability(id="ALAS-123", metadata_json={"CVE": ["CVE-2021"]}),
            ["CVE-2021"],
        ),
        (
            Vulnerability(id="CVE-123", metadata_json={"CVE": ["CVE-2021"]}),
            ["CVE-123", "CVE-2021"],
        ),
        (Vulnerability(id="CVE-123"), ["CVE-123"]),
    ],
)
def test_cve_ids_for_vuln_record(record, expected):
    assert sorted(cve_ids_for_vuln_record(record)) == sorted(expected)


@pytest.mark.parametrize(
    "matches, expected",
    [
        (
            [
                (
                    ImageCpe(name="package1", version="1.0"),
                    CpeV2Vulnerability(
                        feed_name="nvdv2:cves",
                        vulnerability_id="CVE-123",
                        product="package1",
                        version="1.0",
                        created_at=datetime.datetime(year=2021, month=1, day=1),
                    ),
                )
            ],
            [
                (
                    ImageCpe(name="package1", version="1.0"),
                    CpeV2Vulnerability(
                        feed_name="nvdv2:cves",
                        vulnerability_id="CVE-123",
                        product="package1",
                        version="1.0",
                        created_at=datetime.datetime(year=2021, month=1, day=1),
                    ),
                )
            ],
        ),
        (
            [
                (
                    ImageCpe(name="package1", version="1.0"),
                    CpeV2Vulnerability(
                        feed_name="nvdv2:cves",
                        vulnerability_id="CVE-123",
                        product="package1",
                        version="1.0",
                        created_at=datetime.datetime(year=2021, month=1, day=1),
                    ),
                ),
                (
                    ImageCpe(name="package1", version="1.0"),
                    CpeV2Vulnerability(
                        feed_name="nvdv2:cves",
                        vulnerability_id="CVE-123",
                        product="package1",
                        version="1.0",
                        created_at=datetime.datetime(year=2021, month=1, day=1),
                    ),
                ),
            ],
            [
                (
                    ImageCpe(name="package1", version="1.0"),
                    CpeV2Vulnerability(
                        feed_name="nvdv2:cves",
                        vulnerability_id="CVE-123",
                        product="package1",
                        version="1.0",
                        created_at=datetime.datetime(year=2021, month=1, day=1),
                    ),
                )
            ],
        ),
        (
            [
                (
                    ImageCpe(name="package1", version="1.0"),
                    CpeV2Vulnerability(
                        feed_name="nvdv2:cves",
                        vulnerability_id="CVE-123",
                        product="package1",
                        version="1.0",
                        created_at=datetime.datetime(year=2021, month=1, day=1),
                    ),
                ),
                (
                    ImageCpe(name="package1", version="1.0", pkg_path="/foo"),
                    CpeV2Vulnerability(
                        feed_name="nvdv2:cves",
                        vulnerability_id="CVE-123",
                        product="package1",
                        version="1.0",
                        created_at=datetime.datetime(year=2021, month=1, day=1),
                    ),
                ),
            ],
            [
                (
                    ImageCpe(name="package1", version="1.0"),
                    CpeV2Vulnerability(
                        feed_name="nvdv2:cves",
                        vulnerability_id="CVE-123",
                        product="package1",
                        version="1.0",
                        created_at=datetime.datetime(year=2021, month=1, day=1),
                    ),
                ),
                (
                    ImageCpe(name="package1", version="1.0", pkg_path="/foo"),
                    CpeV2Vulnerability(
                        feed_name="nvdv2:cves",
                        vulnerability_id="CVE-123",
                        product="package1",
                        version="1.0",
                        created_at=datetime.datetime(year=2021, month=1, day=1),
                    ),
                ),
            ],
        ),
    ],
)
def test_dedup_cpe_vulns(matches, expected):
    # This equality check isn't very good, but __repr__ should be sufficiently unique for this test
    assert [(str(x), str(y)) for x, y in dedup_cpe_vulnerabilities(matches)] == [
        (str(x), str(y)) for x, y in expected
    ]


@pytest.fixture
def monkeypatched_records_for_namespace(monkeysession, request):
    def mock_matched_records_for_namespace(
        namespace_name: str, match_set: List[str]
    ) -> List[str]:
        return request.param

    monkeysession.setattr(
        anchore_engine.services.policy_engine.engine.vulns.db.CpeDBQueryManager,
        "matched_records_for_namespace",
        mock_matched_records_for_namespace,
    )

    return monkeysession


@pytest.fixture
def monkeypatched_distro_mappings(monkeysession):
    def mock_distros_mapped_to(name: str, version: str) -> List[DistroTuple]:
        return [DistroTuple(name, version, "")]

    def mock_distros_for(name: str, version: str, flavor: str) -> List[DistroTuple]:
        return [DistroTuple(name, version, flavor)]

    monkeysession.setattr(
        anchore_engine.db.entities.policy_engine.DistroMapping,
        "distros_mapped_to",
        mock_distros_mapped_to,
    )
    monkeysession.setattr(
        anchore_engine.db.entities.policy_engine.DistroMapping,
        "distros_for",
        mock_distros_for,
    )

    return monkeysession


@pytest.fixture
def mock_db_query_manager(monkeypatched_distro_mappings, request):
    class MockDbQueryManager:
        def matched_records_for_namespace(
            self, namespace_name: str, filter_ids: List[str]
        ) -> List[str]:
            return request.param

    return MockDbQueryManager()


@pytest.mark.parametrize(
    "image_matches, mock_db_query_manager, expected",
    [
        (["CVE-123"], ["CVE-123"], []),
        (
            ["CVE-1"],
            ["CVE-123"],
            ["CVE-1"],
        ),
        (["CVE-1", "CVE-2"], ["CVE-1"], ["CVE-2"]),
    ],
    indirect=["mock_db_query_manager"],
)
def test_filter_secdb(
    image_matches,
    mock_db_query_manager,
    expected,
):
    namespace = DistroNamespace(
        name="debian", version="9"
    )  # This is needed for lookup, but does not change results since the cves are injected
    filtered = filter_secdb_entries(
        image_distro=namespace, matches=image_matches, db_manager=mock_db_query_manager
    )
    assert filtered == expected


pkg1 = ImagePackage(name="pkg1", version="1.0.0")
pkg2 = ImagePackage(name="pkg-two", version="2.0.0")
pkg1_cpe = ImageCpe(name="pkg1", version="1.0.0")
pkg2_cpe1 = ImageCpe(name="pkg-two", version="2.0.0")
pkg2_cpe2 = ImageCpe(name="pkg_two", version="2.0.0")


@pytest.mark.parametrize(
    "packages, mapped_cpes",
    [
        (
            [pkg1],
            [(pkg1, pkg1_cpe)],
        ),
        (
            [pkg2],
            [
                (pkg2, pkg2_cpe1),
                (pkg2, pkg2_cpe2),
            ],
        ),
    ],
)
def test_cpes_for_images_packages(packages, mapped_cpes):
    def tuple_sort_key(
        cpe_tuple: Tuple[ImagePackage, ImageCpe]
    ) -> Tuple[str, str, str, str]:
        img = cpe_tuple[0]
        cpe = cpe_tuple[1]
        return (
            img.name,
            img.version,
            cpe.name,
            cpe.version,
        )

    # For this test, just use simple string tuples to identify the results for equality check
    # This should be safe since cpes are generated per package, so other package differentiating fields aren't relevant
    # for the correctness of the cpe generation logic itself
    sorted_found = sorted(map(tuple_sort_key, cpes_for_image_packages(packages)))
    sorted_expected = sorted(map(tuple_sort_key, mapped_cpes))
    assert sorted_found == sorted_expected
