import pytest

from anchore_engine.db import (
    FeedGroupMetadata,
    FeedMetadata,
    FixedArtifact,
    Image,
    ImagePackage,
    Vulnerability,
    session_scope,
)

mock_feeds = [
    FeedMetadata(
        name="vulnerabilities",
        description="Test version of vulnerabilities feed",
        access_tier=0,
        enabled=True,
    ),
    FeedMetadata(
        name="github",
        description="Test version of github feed",
        access_tier=0,
        enabled=True,
    ),
]

mock_feed_groups = [
    FeedGroupMetadata(
        name="debian:8",
        feed_name="vulnerabilities",
        enabled=True,
        description="Fake debian 8 vuln data",
        access_tier=0,
    ),
    FeedGroupMetadata(
        name="debian:9",
        feed_name="vulnerabilities",
        enabled=True,
        description="Fake debian 9 vuln data",
        access_tier=0,
    ),
    FeedGroupMetadata(
        name="github:pip",
        feed_name="github",
        enabled=True,
        description="Github python/pip data",
        access_tier=0,
    ),
]

mock_vulnerabilities = [
    Vulnerability(
        id="cve-1",
        namespace_name="debian:8",
        severity="high",
        fixed_in=[
            FixedArtifact(name="testpkg1", version="1.0.1", version_format="deb")
        ],
    )
]

mock_images = [
    Image(
        user_id="admin",
        id="1",
        digest="sha256:1",
        distro_name="debian",
        distro_version="9",
        like_distro="debian",
        state="analyzed",
    )
]

mock_packages = [
    ImagePackage(
        image_user_id="admin",
        image_id="1",
        name="testpkg1",
        version="1.0.0",
        size=100,
        arch="amd64",
        pkg_type="deb",
        distro_name="debian",
        distro_version="9",
        pkg_path="/usr/local/debian/pkgs/testpkg",
    )
]


@pytest.fixture()
def mock_feed_metadata(anchore_db):
    """
    Fixture for delivering mock feed and feed group metadata for metadata ops

    :param anchore_db:
    :return:
    """
    feed_names = []
    with session_scope() as db:
        for f in mock_feeds:
            feed_names.append(f["name"])
            feed = FeedMetadata()
            feed.name = f["name"]
            feed.description = f["description"]
            feed.enabled = True
            feed.access_tier = 0
            feed.groups = []

            for grp in f["groups"]:
                g = FeedGroupMetadata()
                g.name = grp["name"]
                g.access_tier = 0
                g.description = ""
                g.enabled = True
                g.feed_name = feed.name

    return feed_names


@pytest.fixture()
def mock_feed_data(mock_feed_metadata):
    with session_scope() as db:
        for v in mock_vulnerabilities:
            db.add(v)


# def test_toggle_group_enabled(mock_feed_data):
#     """
#     Test toggling of feed groups and feeds
#     :param mock_feed_data:
#     :return:
#     """
#     pass
