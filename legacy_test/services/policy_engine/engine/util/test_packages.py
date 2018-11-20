"""
Unit tests for anchore_engine.services.policy_engine.engine.util.packages

"""

import unittest
import json
import os

from legacy_test.services.policy_engine import BaseDBUnitTest
from anchore_engine.db import DistroNamespace

DISTRO_VERSIONS = """alpine,3.0.0
alpine,3.1.0
alpine,3.1.2
alpine,3.1.3
alpine,3.1.4
alpine,3.2.0
alpine,3.2.3
alpine,3.3.0
alpine,3.3.1
alpine,3.3.3
alpine,3.4.0
alpine,3.4.3
alpine,3.4.4
alpine,3.4.6
alpine,3.5.0
alpine,3.5.1
alpine,3.5.2
alpine,3.6.0
alpine,3.6.0_rc1
alpine,3.6.0_rc3
alpine,3.6.1
alpine,3.6.2
amzn,2016.09
amzn,2017.03
arch,0
buildroot,2012.05
buildroot,2013.08.1
buildroot,2014.02
busybox,0
busybox,v1.18.5
busybox,v1.21.1
busybox,v1.22.1
busybox,v1.23.2
busybox,v1.24.0
busybox,v1.24.1
busybox,v1.24.2
busybox,v1.25.0
busybox,v1.25.1
busybox,v1.26.0
busybox,v1.26.1
busybox,v1.26.2
centos,5.11
centos,6
centos,7
debian,0
debian,2
debian,3
debian,4
debian,5
debian,6
debian,7
debian,8
debian,9
fedora,20
fedora,21
fedora,22
fedora,23
fedora,24
fedora,25
fedora,26
fedora,27
kali,2016.1
kali,2016.2
linuxmint,18
linuxmint,18.1
mageia,0
mageia,5
ol,6.7
ol,6.8
ol,6.9
ol,7.0
ol,7.1
ol,7.2
ol,7.3
opensuse,13.2
opensuse,20160612
opensuse,42.1
opensuse,42.2
oracle,6server
photon,1.0
raspbian,7
raspbian,8
raspbian,9
redhat,6.7
redhat,6.8
redhat,6.9
rhel,7.3
ubuntu,12.04
ubuntu,12.10
ubuntu,13.04
ubuntu,13.10
ubuntu,14.04
ubuntu,14.10
ubuntu,15.04
ubuntu,15.10
ubuntu,16.04
ubuntu,16.10
ubuntu,17.04
ubuntu,17.10
Unknown,0
Unknown,5.11
Unknown,6.2
"""

class TestDistroNamespace(BaseDBUnitTest):

    # Reasonably well known linux disto names and/or versions
    valid_distros = [
        ('centos', '6'),
        ('centos', '7'),
        ('ubuntu', '12:04'),
        ('ol', '7'),
        ('rhel', '6'),
        ('redhat', '7'),
        ('busybox', '1'),
        ('alpine', '3.5'),
        ('debian', '9'),
        ('mint', '14'),
        ('fedora', '25'),
        ('archlinux', '4'),
        ('gentoo', '14.5'),
        ('suse', '8')
    ]

    # Irregular and unexpected distro names
    unmapped_distros = [
        ('securitylinux', '12.04'),
        ('magea', '5'),
        ('tinyos', '5.6'),
        ('somerandomename', '1.2.3'),
        ('mageia', '5')
    ]


    distros = [x.strip().split(',') for x in DISTRO_VERSIONS.splitlines()]

    def test_relation_mapping(self):
        for d in self.valid_distros:
            ns = DistroNamespace(name=d[0], version=d[1])
            self.assertIsNotNone(ns)
            self.assertEqual(ns.name, d[0])
            self.assertEqual(ns.version, d[1])

        for d in self.unmapped_distros:
            ns = DistroNamespace(name=d[0], version=d[1])
            self.assertIsNotNone(ns)

    def test_cve_mapping(self):
        for d in self.distros:
            ns = DistroNamespace(name=d[0], version=d[1])
            r = {
                'flavor': ns.flavor,
                'namespace_names': ns.like_namespace_names
            }
            print((ns.namespace_name + ' ->' + json.dumps(r, indent=2)))
            self.assertIsNotNone(ns)
            self.assertEqual(ns.name, d[0])
            self.assertEqual(ns.version, d[1])





