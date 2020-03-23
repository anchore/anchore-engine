import pytest
from anchore_engine.subsys import logger
from anchore_engine.services.policy_engine.engine import vulnerabilities
from anchore_engine.db.entities.policy_engine import DistroTuple, FeedMetadata, FeedGroupMetadata, DistroMapping, DistroNamespace
from anchore_engine.db import get_thread_scoped_session
from anchore_engine.services.policy_engine import _init_distro_mappings


logger.enable_test_logging()


@pytest.fixture()
def initialized_mappings(anchore_db):
    _init_distro_mappings()


@pytest.fixture()
def initialize_feed_metadata(anchore_db):
    """
    Add feed metadata records to the test db, but not vulns
    :param anchore_db:
    :return:
    """

    db = get_thread_scoped_session()
    feeds = [
        {'name': 'vulnerabilties', 'groups': [
            {'name': 'centos:5'},
            {'name': 'centos:6'},
            {'name': 'centos:7'},
            {'name': 'centos:8'},
            {'name': 'rhel:5'},
            {'name': 'rhel:6'},
            {'name': 'rhel:7'},
            {'name': 'rhel:8'},
            {'name': 'alpine:3.6'},
            {'name': 'alpine:3.7'},
            {'name': 'alpine:3.8'},
            {'name': 'alpine:3.9'},
            {'name': 'alpine:3.10'},
            {'name': 'alpine:3.11'},
            {'name': 'debian:8'},
            {'name': 'debian:9'},
            {'name': 'debian:10'},
            {'name': 'debian:unstable'},
            {'name': 'ol:5'},
            {'name': 'ol:6'},
            {'name': 'ol:7'},
            {'name': 'ol:8'},
            {'name': 'ubuntu:14.04'},
            {'name': 'ubuntu:14.10'},
            {'name': 'ubuntu:15.03'},
            {'name': 'ubuntu:15.10'},
            {'name': 'ubuntu:16.04'},
            {'name': 'ubuntu:16.10'},
            {'name': 'ubuntu:17.04'},
            {'name': 'ubuntu:17.10'},
            {'name': 'ubuntu:18.04'},
            {'name': 'ubuntu:18.10'},
            {'name': 'ubuntu:19.04'},
            {'name': 'ubuntu:19.10'},
            ],
         },
         {'name': 'nvdv2', 'groups': [{'name': 'nvdv2:cves'}]},
         {'name': 'packages', 'groups': [{'name': 'npms'}, {'name': 'gems'}]},
         {'name': 'vulndb', 'groups': [{'name': 'vulndb'}]},
         {'name': 'github', 'groups': [
             {'name': 'github:composer'},
             {'name': 'github:npm'},
             {'name': 'github:gem'},
             {'name': 'github:pip'},
             {'name': 'github:maven'},
             {'name': 'github:nuget'}
         ]
         }
    ]

    try:
        for f in feeds:
            f = FeedMetadata(name=f['name'], access_tier=0, enabled=True)
            f.groups = [FeedGroupMetadata(name=g['name'], feed_name=f['name'], access_tier=0, enabled=True) for g in f.get('groups', [])]
            db.add(f)
            for g in f.groups:
                db.add(g)
        db.commit()
    except:
        db.rollback()


def test_namespace_support(initialized_mappings):
    """
    Test the mix of mappings with namespace support to ensure distro+version maps functioning as expected
    """

    # Not exhaustive, only for the feeds directly in the test data set
    expected = [
        DistroNamespace(name='amzn', version='2', like_distro='amzn'),
        DistroNamespace(name='alpine', version='3.3', like_distro='alpine'),
        DistroNamespace(name='alpine', version='3.4', like_distro='alpine'),
        DistroNamespace(name='alpine', version='3.5', like_distro='alpine'),
        DistroNamespace(name='alpine', version='3.6', like_distro='alpine'),
        DistroNamespace(name='alpine', version='3.7', like_distro='alpine'),
        DistroNamespace(name='alpine', version='3.8', like_distro='alpine'),
        DistroNamespace(name='alpine', version='3.9', like_distro='alpine'),
        DistroNamespace(name='alpine', version='3.10', like_distro='alpine'),
        DistroNamespace(name='alpine', version='3.11', like_distro='alpine'),
        DistroNamespace(name='centos', version='7', like_distro='rhel'),
        DistroNamespace(name='centos', version='7.1', like_distro='rhel'),
        DistroNamespace(name='centos', version='7.3', like_distro='rhel'),
        DistroNamespace(name='centos', version='6', like_distro='rhel'),
        DistroNamespace(name='centos', version='5', like_distro='rhel'),
        DistroNamespace(name='centos', version='8', like_distro='rhel'),
        DistroNamespace(name='centos', version='8.1', like_distro='rhel'),
        DistroNamespace(name='ol', version='7.3', like_distro='ol'),
        DistroNamespace(name='ol', version='6', like_distro='ol'),
        DistroNamespace(name='ol', version='7.3', like_distro='ol'),
        DistroNamespace(name='rhel', version='6', like_distro='rhel'),
        DistroNamespace(name='rhel', version='7', like_distro='rhel'),
        DistroNamespace(name='rhel', version='7.1', like_distro='rhel'),
        DistroNamespace(name='rhel', version='8', like_distro='rhel'),
        DistroNamespace(name='rhel', version='8.1', like_distro='rhel'),
        DistroNamespace(name='debian', version='8', like_distro='debian'),
        DistroNamespace(name='debian', version='9', like_distro='debian'),
        DistroNamespace(name='debian', version='10', like_distro='debian'),
        DistroNamespace(name='debian', version='11', like_distro='debian'),
        DistroNamespace(name='debian', version='unstable', like_distro='debian'),
        DistroNamespace(name='ubuntu', version='14.04', like_distro='ubuntu'),
        DistroNamespace(name='ubuntu', version='14.10', like_distro='ubuntu'),
        DistroNamespace(name='ubuntu', version='15.03', like_distro='ubuntu'),
        DistroNamespace(name='ubuntu', version='15.10', like_distro='ubuntu'),
        DistroNamespace(name='ubuntu', version='16.04', like_distro='ubuntu'),
        DistroNamespace(name='ubuntu', version='16.10', like_distro='ubuntu'),
        DistroNamespace(name='ubuntu', version='17.04', like_distro='ubuntu'),
        DistroNamespace(name='ubuntu', version='17.10', like_distro='ubuntu'),
        DistroNamespace(name='ubuntu', version='18.04', like_distro='ubuntu'),
        DistroNamespace(name='ubuntu', version='18.10', like_distro='ubuntu'),
        DistroNamespace(name='ubuntu', version='19.04', like_distro='ubuntu'),
        DistroNamespace(name='ubuntu', version='19.10', like_distro='ubuntu')
    ]

    fail = [
        DistroNamespace(name='alpine', version='3.1', like_distro='alpine'),
        DistroNamespace(name='alpine', version='3.1.1', like_distro='alpine'),

        DistroNamespace(name='busybox', version='3', like_distro='busybox'),
        DistroNamespace(name='linuxmint', version='16', like_distro='debian'),
        DistroNamespace(name='redhat', version='4', like_distro='rhel'),
        DistroNamespace(name='redhat', version='5', like_distro='rhel'),

        DistroNamespace(name='ubuntu', version='1.0', like_distro='ubuntu'),
        DistroNamespace(name='centos', version='1.0', like_distro='ubuntu'),
        DistroNamespace(name='debian', version='1.0', like_distro='ubuntu'),
        DistroNamespace(name='rhel', version='1.0', like_distro='ubuntu'),
        DistroNamespace(name='busybox', version='1.0', like_distro='busybox'),
        DistroNamespace(name='alpine', version='11.0', like_distro='ubuntu'),
        DistroNamespace(name='fedora', version='25', like_distro='fedora'),
        DistroNamespace(name='mageia', version='5', like_distro='mandriva,fedora')
    ]

    for i in expected:
        assert vulnerabilities.have_vulnerabilities_for(i), 'Expected vulns for namespace {}'.format(i.namespace_name)

    for i in fail:
        assert not vulnerabilities.have_vulnerabilities_for(i), 'Did not expect vulns for namespace {}'.format(i.namespace_name)


def test_distromappings(initialized_feed_metadata):

    c7 = DistroNamespace(name='centos', version='7', like_distro='centos')
    assert c7.mapped_names() == []
    assert c7.like_namespace_names == ['rhel:7']

    r7 = DistroNamespace(name='rhel', version='7', like_distro='centos')
    assert set(r7.mapped_names()) == {'centos', 'fedora', 'rhel'}
    assert r7.like_namespace_names == ['rhel:7']

    assert sorted(DistroMapping.distros_mapped_to('rhel', '7')) == sorted([DistroTuple('rhel','7','RHEL'), DistroTuple('centos', '7', 'RHEL'), DistroTuple('fedora','7', 'RHEL')])


def test_mapped_distros(initialized_mappings):
    assert DistroMapping.distros_for('centos', '5', 'centos') == [DistroTuple('rhel', '5')]
    assert DistroMapping.distros_for('centos', '6', 'centos') == [DistroTuple('rhel', '6')]
