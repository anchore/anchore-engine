"""
Unit tests for anchore_engine.services.policy_engine.engine.util.packages

"""

import unittest
import json

from anchore_engine.db import DistroNamespace


class TestDistroNamespace(unittest.TestCase):

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

    with open('data/distros.txt') as f:
        distros = [x.strip().split(',') for x in f.readlines()]

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
            print(ns.namespace_name + ' ->' + json.dumps(r, indent=2))
            self.assertIsNotNone(ns)
            self.assertEqual(ns.name, d[0])
            self.assertEqual(ns.version, d[1])





