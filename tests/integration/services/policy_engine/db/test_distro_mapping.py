from anchore_engine.db.entities.policy_engine import (
    DistroMapping,
    DistroTuple,
    VersionPreservingDistroMapper,
    get_thread_scoped_session,
)
from anchore_engine.subsys import logger
from tests.integration.services.policy_engine.utils import init_distro_mappings

logger.enable_test_logging()


def test_simple_map(anchore_db):
    init_distro_mappings()
    found = DistroMapping()
    found.from_distro = "centos"
    found.to_distro = "centos"
    found.flavor = "RHEL"
    mapper = VersionPreservingDistroMapper("centos", "7", None, found)
    logger.info("Mapped centos to: {}".format(mapper.mapping))
    assert mapper.mapping == [DistroTuple(distro="centos", version="7", flavor="RHEL")]

    found.from_distro = "fedora"
    found.to_distro = "centos"
    found.flavor = "RHEL"
    mapper = VersionPreservingDistroMapper("fedora", "27", "centos", found)
    logger.info("Mapped fedora to: {}".format(mapper.mapping))
    assert mapper.mapping == [DistroTuple(distro="centos", version="27", flavor="RHEL")]

    mapper = VersionPreservingDistroMapper("fedora", "27", "centos", None)
    logger.info("Mapped fedora to: {} on empty input".format(mapper.mapping))
    assert mapper.mapping == [DistroTuple(distro="fedora", version="27", flavor="RHEL")]


def test_distro_from(anchore_db):
    init_distro_mappings()
    session = get_thread_scoped_session()
    try:
        distros = DistroMapping.distros_for("centos", "7", "rhel")
        logger.info("Distros for centos 7 (rhel) = {}".format(distros))
        assert distros is not None
        assert len(distros) == 1

        distros = DistroMapping.distros_for("centos", "7.4.1", "rhel")
        logger.info("Distros for centos 7.4.1 (rhel) = {}".format(distros))
        assert distros is not None
        assert len(distros) == 3

        distros = DistroMapping.distros_for("debian", "9")
        logger.info("Distros for debian 9 = {}".format(distros))
        assert distros is not None
        assert len(distros) == 1

        distros = DistroMapping.distros_for("ubuntu", "16.04")
        logger.info("Distros for ubuntu 16.04 = {}".format(distros))
        assert distros is not None
        assert len(distros) == 3

        distros = DistroMapping.distros_for("busybox", "3")
        logger.info("Distros for busybox 3 = {}".format(distros))
        assert distros is not None
        assert len(distros) == 1

        distros = DistroMapping.distros_for("raspbian", "5")
        logger.info("Distros for raspbian 5 = {}".format(distros))
        assert distros is not None
        assert len(distros) == 1

        distros = DistroMapping.distros_for("magaiea", "3")
        logger.info("Distros for magaiea 3 = {}".format(distros))
        assert distros is not None
        assert len(distros) == 1

        distros = DistroMapping.distros_for("magaiea", "5", "fedora,mandriva")
        logger.info("Distros for magaiea 5 (fedora, mandriva) = {}".format(distros))
        assert distros is not None
        assert len(distros) == 1
    finally:
        session.commit()
