from anchore_engine.db import (
    FeedGroupMetadata,
    FeedMetadata,
    FixedArtifact,
    Vulnerability,
    VulnerableArtifact,
    session_scope,
)
from anchore_engine.db.entities.upgrade import remove_incorrect_github_vuln_data


def add_records(records):
    with session_scope() as session:
        # Add some feed and group records
        for record in records:
            session.add(record)
        session.flush()


def test_remove_incorrect_github_vuln_data(anchore_db):
    """
    Tests upgrade task that removes extraneous github:os and github:unknown vuln records
    Test does not include ImagePackageVulnerability because of the overhead of setting up mock data
    """
    records = []
    records += [FeedMetadata(name="github")]
    records += [
        FeedGroupMetadata(feed_name="github", name="github:os"),
        FeedGroupMetadata(feed_name="github", name="github:unknown"),
        FeedGroupMetadata(feed_name="github", name="github:python"),
    ]
    records += [
        Vulnerability(id="GHSA-1", namespace_name="github:os", severity="Low"),
        Vulnerability(id="GHSA-2", namespace_name="github:unknown", severity="Low"),
        Vulnerability(id="GHSA-3", namespace_name="github:python", severity="Low"),
    ]
    records += [
        VulnerableArtifact(
            vulnerability_id="GHSA-1",
            namespace_name="github:os",
            name="test-1",
            version="1.0",
        ),
        VulnerableArtifact(
            vulnerability_id="GHSA-2",
            namespace_name="github:unknown",
            name="test-2",
            version="1.0",
        ),
        VulnerableArtifact(
            vulnerability_id="GHSA-3",
            namespace_name="github:python",
            name="test-3",
            version="1.0",
        ),
    ]
    records += [
        FixedArtifact(
            vulnerability_id="GHSA-1",
            namespace_name="github:os",
            name="test-1",
            version="1.1",
        ),
        FixedArtifact(
            vulnerability_id="GHSA-2",
            namespace_name="github:unknown",
            name="test-2",
            version="1.1",
        ),
        FixedArtifact(
            vulnerability_id="GHSA-3",
            namespace_name="github:python",
            name="test-3",
            version="1.1",
        ),
    ]

    add_records(records)

    remove_incorrect_github_vuln_data()

    with session_scope() as session:
        assert session.query(FeedMetadata).count() == 1
        assert session.query(FeedGroupMetadata).count() == 1
        assert session.query(Vulnerability).count() == 1
        assert session.query(VulnerableArtifact).count() == 1
        assert session.query(FixedArtifact).count() == 1
