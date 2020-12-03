from anchore_engine.services.policy_engine.engine import vulnerabilities
import logging as logger
from anchore_engine.subsys.logger import enable_test_logging

enable_test_logging(level="info")


def test_namespace_has_no_feed():
    """
    Test the caching mechanisms used during feed syncs to optimize lookups w/o db access

    :return:
    """
    # Nothing initially
    assert vulnerabilities.namespace_has_no_feed("debian", "8")

    vulnerabilities.ThreadLocalFeedGroupNameCache.add(
        [("debian:8", True), ("debian:9", True), ("centos:4", False)]
    )
    assert vulnerabilities.ThreadLocalFeedGroupNameCache.lookup("debian:8") == (
        "debian:8",
        True,
    )
    assert vulnerabilities.ThreadLocalFeedGroupNameCache.lookup("debian:9") == (
        "debian:9",
        True,
    )
    assert vulnerabilities.ThreadLocalFeedGroupNameCache.lookup("centos:4") == (
        "centos:4",
        False,
    )
    assert not vulnerabilities.namespace_has_no_feed("debian", "8")
    assert not vulnerabilities.namespace_has_no_feed("debian", "9")
    assert vulnerabilities.namespace_has_no_feed("debian", "foobar")
    assert vulnerabilities.namespace_has_no_feed("centos", "4")

    # Empty
    vulnerabilities.ThreadLocalFeedGroupNameCache.flush()
    assert vulnerabilities.namespace_has_no_feed("debian", "8")


def test_get_namespace_related_names():
    """
    Tests the older enable-filtering behavior of the namespace selector for which image/distros to update during a given
    feed sync

    :return:
    """
    assert vulnerabilities.namespace_has_no_feed("debian", "8")

    # State pre 0.7.0 upgrade
    # Assume centos -> centos, and all enabled
    mapped_to_centos = ["centos", "rhel", "fedora"]
    mapped_to_rhel = []

    vulnerabilities.ThreadLocalFeedGroupNameCache.add(
        [("centos:8", True), ("rhel:8", True)]
    )
    # When centos feed updates
    assert set(
        vulnerabilities.get_namespace_related_names("centos", "8", mapped_to_centos)
    ) == {"centos", "fedora"}

    # When rhel feed updates
    assert set(
        vulnerabilities.get_namespace_related_names("rhel", "8", mapped_to_rhel)
    ) == {"rhel"}

    vulnerabilities.ThreadLocalFeedGroupNameCache.flush()

    # State post 0.7.0 upgrade

    # Toggle enabled and see
    mapped_to_centos = []
    mapped_to_rhel = ["rhel", "centos", "fedora"]
    vulnerabilities.ThreadLocalFeedGroupNameCache.add(
        [("centos:7", False), ("rhel:7", True)]
    )

    assert (
        set(
            vulnerabilities.get_namespace_related_names("centos", "7", mapped_to_centos)
        )
        == set()
    )
    assert set(
        vulnerabilities.get_namespace_related_names("rhel", "7", mapped_to_rhel)
    ) == {"rhel", "centos", "fedora"}

    vulnerabilities.ThreadLocalFeedGroupNameCache.flush()

    # Revert from 0.7.0 upgrade if user wants RHSA again...
    mapped_to_centos = []
    mapped_to_rhel = ["rhel", "centos", "fedora"]
    vulnerabilities.ThreadLocalFeedGroupNameCache.add(
        [("centos:7", True), ("rhel:7", True)]
    )

    assert set(
        vulnerabilities.get_namespace_related_names("centos", "7", mapped_to_centos)
    ) == {"centos"}
    assert set(
        vulnerabilities.get_namespace_related_names("rhel", "7", mapped_to_rhel)
    ) == {"rhel", "fedora"}

    vulnerabilities.ThreadLocalFeedGroupNameCache.flush()
