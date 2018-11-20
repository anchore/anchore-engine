import unittest
import logging
import os

from legacy_test.services.policy_engine.utils import LocalTestDataEnvironment, init_db
from anchore_engine.db.entities.policy_engine import DistroNamespace, DistroMapping, DistroTuple, VersionPreservingDistroMapper


class TestDistroMappers(unittest.TestCase):
    test_env = LocalTestDataEnvironment(os.environ['ANCHORE_ENGINE_TESTING_HOME'])

    app = None
    test_gates = [
        {
            'gate': 'DOCKERFILECHECK',
            'trigger': 'EXPOSE',
            'action': 'GO',
            'params': {
                'ALLOWEDPORTS': '80,443',
                'DENIEDPORTS': '8080,22,21'
            }
        },
        {
            'gate': 'DOCKERFILECHECK',
            'trigger': 'NOFROM',
            'action': 'GO',
            'params': {}
        }
    ]

    @classmethod
    def setUpClass(cls):
        init_db(cls.test_env.mk_db(), conn_args={})
        logging.basicConfig(level=logging.DEBUG)

    def test_simple_map(self):
        found = DistroMapping()
        found.from_distro = 'centos'
        found.to_distro = 'centos'
        found.flavor = 'RHEL'
        mapper = VersionPreservingDistroMapper('centos', '7', None, found)
        print(('Mapped centos to: {}'.format(mapper.mapping)))

        found.from_distro = 'fedora'
        found.to_distro = 'centos'
        found.flavor = 'RHEL'
        mapper = VersionPreservingDistroMapper('fedora', '27', 'centos', found)
        print(('Mapped fedora to: {}'.format(mapper.mapping)))

        mapper = VersionPreservingDistroMapper('fedora', '27', 'centos', None)
        print(('Mapped fedora to: {} on empty input'.format(mapper.mapping)))

    def test_distro_from(self):
        print((DistroMapping.distros_for('centos', '7', 'rhel')))
        print((DistroMapping.distros_for('centos', '7.4.1', 'rhel')))
        print((DistroMapping.distros_for('debian', '9')))
        print((DistroMapping.distros_for('ubuntu', '16.04')))
        print((DistroMapping.distros_for('busybox', '3')))
        print((DistroMapping.distros_for('raspbian', '5')))
        print((DistroMapping.distros_for('magaiea', '3')))
        print((DistroMapping.distros_for('magaiea', '5', 'fedora,mandriva')))




