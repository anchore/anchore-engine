import pytest

from anchore_engine.db import get_thread_scoped_session
from anchore_engine.db.entities.policy_engine import (
    DistroMapping,
    DistroNamespace,
    DistroTuple,
    FeedGroupMetadata,
    FeedMetadata,
)
from anchore_engine.services.policy_engine import (  # _init_distro_mappings
    process_preflight,
)
from anchore_engine.services.policy_engine.engine.feeds.feeds import (
    feed_registry,
    have_vulnerabilities_for,
)
from anchore_engine.subsys import logger

logger.enable_test_logging()


class AnotherVulnClass:
    __feed_name__ = "anothervuln"


@pytest.fixture()
def initialized_mappings(anchore_db):
    process_preflight()
    feed_registry.register(AnotherVulnClass, True)
    # _init_distro_mappings()


@pytest.fixture()
def initialized_feed_metadata(anchore_db):
    """
    Add feed metadata records to the test db, but not vulns
    :param anchore_db:
    :return:
    """

    db = get_thread_scoped_session()
    feeds = [
        {"name": "anothervuln", "groups": [{"name": "adistro:1"}]},
        {
            "name": "vulnerabilities",
            "groups": [
                {"name": "amzn:2"},
                {"name": "centos:5"},
                {"name": "centos:6"},
                {"name": "centos:7"},
                {"name": "centos:8"},
                {"name": "rhel:5"},
                {"name": "rhel:6"},
                {"name": "rhel:7"},
                {"name": "rhel:8"},
                {"name": "alpine:3.6"},
                {"name": "alpine:3.7"},
                {"name": "alpine:3.8"},
                {"name": "alpine:3.9"},
                {"name": "alpine:3.10"},
                {"name": "alpine:3.11"},
                {"name": "debian:8"},
                {"name": "debian:9"},
                {"name": "debian:10"},
                {"name": "debian:11"},
                {"name": "debian:unstable"},
                {"name": "ol:5"},
                {"name": "ol:6"},
                {"name": "ol:7"},
                {"name": "ol:8"},
                {"name": "ubuntu:14.04"},
                {"name": "ubuntu:14.10"},
                {"name": "ubuntu:15.03"},
                {"name": "ubuntu:15.10"},
                {"name": "ubuntu:16.04"},
                {"name": "ubuntu:16.10"},
                {"name": "ubuntu:17.04"},
                {"name": "ubuntu:17.10"},
                {"name": "ubuntu:18.04"},
                {"name": "ubuntu:18.10"},
                {"name": "ubuntu:19.04"},
                {"name": "ubuntu:19.10"},
            ],
        },
        {"name": "nvdv2", "groups": [{"name": "nvdv2:cves"}]},
        {"name": "packages", "groups": [{"name": "npms"}, {"name": "gems"}]},
        {"name": "vulndb", "groups": [{"name": "vulndb"}]},
        {
            "name": "github",
            "groups": [
                {"name": "github:composer"},
                {"name": "github:npm"},
                {"name": "github:gem"},
                {"name": "github:pip"},
                {"name": "github:maven"},
                {"name": "github:nuget"},
            ],
        },
    ]

    try:
        for f in feeds:
            fmeta = FeedMetadata(name=f["name"], access_tier=0, enabled=True)
            fmeta.groups = [
                FeedGroupMetadata(
                    name=g["name"],
                    feed_name=f["name"],
                    access_tier=0,
                    enabled=True,
                    feed=fmeta,
                )
                for g in f.get("groups", [])
            ]
            db.add(fmeta)
            for g in fmeta.groups:
                db.add(g)
        db.commit()
    except:
        db.rollback()


# Not exhaustive, only for the feeds directly in the test data set
distros_with_vulns = [
    ("amzn", "2", "amzn"),
    ("alpine", "3.6", "alpine"),
    ("alpine", "3.7", "alpine"),
    ("alpine", "3.8", "alpine"),
    ("alpine", "3.9", "alpine"),
    ("alpine", "3.10", "alpine"),
    ("alpine", "3.11", "alpine"),
    ("centos", "7", "rhel"),
    ("centos", "7.1", "rhel"),
    ("centos", "7.3", "rhel"),
    ("centos", "6", "rhel"),
    ("centos", "5", "rhel"),
    ("centos", "8", "rhel"),
    ("centos", "8.1", "rhel"),
    ("ol", "7.3", "ol"),
    ("ol", "6", "ol"),
    ("ol", "7.3", "ol"),
    ("rhel", "6", "rhel"),
    ("rhel", "7", "rhel"),
    ("rhel", "7.1", "rhel"),
    ("rhel", "8", "rhel"),
    ("rhel", "8.1", "rhel"),
    ("debian", "8", "debian"),
    ("debian", "9", "debian"),
    ("debian", "10", "debian"),
    ("debian", "11", "debian"),
    ("debian", "unstable", "debian"),
    ("ubuntu", "14.04", "ubuntu"),
    ("ubuntu", "14.10", "ubuntu"),
    ("ubuntu", "15.03", "ubuntu"),
    ("ubuntu", "15.10", "ubuntu"),
    ("ubuntu", "16.04", "ubuntu"),
    ("ubuntu", "16.10", "ubuntu"),
    ("ubuntu", "17.04", "ubuntu"),
    ("ubuntu", "17.10", "ubuntu"),
    ("ubuntu", "18.04", "ubuntu"),
    ("ubuntu", "18.10", "ubuntu"),
    ("ubuntu", "19.04", "ubuntu"),
    ("ubuntu", "19.10", "ubuntu"),
    ("adistro", "1", "adistro"),
]

distros_no_vulns = [
    ("alpine", "3.1", "alpine"),
    ("alpine", "3.1.1", "alpine"),
    ("busybox", "3", "busybox"),
    ("linuxmint", "16", "debian"),
    ("ubuntu", "1.0", "ubuntu"),
    ("centos", "1.0", "ubuntu"),
    ("debian", "1.0", "ubuntu"),
    ("rhel", "1.0", "ubuntu"),
    ("busybox", "1.0", "busybox"),
    ("alpine", "11.0", "ubuntu"),
    ("fedora", "25", "fedora"),
    ("mageia", "5", "mandriva,fedora"),
]


def dump_metas():
    db = get_thread_scoped_session()
    logger.info("Feeds: {}".format([x for x in db.query(FeedMetadata).all()]))
    db.rollback()


def test_namespace_has_vulns(initialized_mappings):
    assert len(feed_registry.registered_vulnerability_feed_names()) > 0


@pytest.mark.parametrize("distro_tuple", distros_with_vulns)
def test_namespace_has_vulns(
    distro_tuple, initialized_mappings, initialized_feed_metadata
):
    """
    Test the mix of mappings with namespace support to ensure distro+version maps functioning as expected
    """
    i = DistroNamespace(
        name=distro_tuple[0], version=distro_tuple[1], like_distro=distro_tuple[2]
    )
    logger.info(
        "Like names for {} = {}".format(i.namespace_name, i.like_namespace_names)
    )
    logger.info("Mapping names for {} = {}".format(i.namespace_name, i.mapped_names()))
    assert (
        have_vulnerabilities_for(i) is True
    ), "Expected vulns for namespace {}".format(i.namespace_name)


@pytest.mark.parametrize("distro_tuple", distros_no_vulns)
def test_namespaces_no_vulns(
    distro_tuple, initialized_feed_metadata, initialized_mappings
):
    i = DistroNamespace(
        name=distro_tuple[0], version=distro_tuple[1], like_distro=distro_tuple[2]
    )
    logger.info(
        "Like names for {} = {}".format(i.namespace_name, i.like_namespace_names)
    )
    logger.info("Mapping names for {} = {}".format(i.namespace_name, i.mapped_names()))
    assert (
        have_vulnerabilities_for(i) is False
    ), "Did not expect vulns for namespace {}".format(i.namespace_name)


def test_distromappings(initialized_mappings):
    c7 = DistroNamespace(name="centos", version="7", like_distro="rhel")
    assert c7.mapped_names() == []
    assert c7.like_namespace_names == ["rhel:7"]

    r7 = DistroNamespace(name="rhel", version="7", like_distro="rhel")
    assert set(r7.mapped_names()) == {"centos", "fedora", "rhel", "redhat"}
    assert r7.like_namespace_names == ["rhel:7"]

    assert sorted(DistroMapping.distros_mapped_to("rhel", "7")) == sorted(
        [
            DistroTuple("redhat", "7", "RHEL"),
            DistroTuple("rhel", "7", "RHEL"),
            DistroTuple("centos", "7", "RHEL"),
            DistroTuple("fedora", "7", "RHEL"),
        ]
    )


def test_mapped_distros(initialized_mappings):
    assert DistroMapping.distros_for("centos", "5", "centos") == [
        DistroTuple("rhel", "5", "RHEL")
    ]
    assert DistroMapping.distros_for("centos", "6", "centos") == [
        DistroTuple("rhel", "6", "RHEL")
    ]
