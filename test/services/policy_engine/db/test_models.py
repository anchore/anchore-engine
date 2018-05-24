import unittest
import copy
import datetime
from anchore_engine.db import ImagePackageVulnerability


class TestImagePackageVulnerabilityHashing(unittest.TestCase):
    def test_cmp(self):
        c1 = ImagePackageVulnerability()
        c1.pkg_name = 'testpkg1'
        c1.pkg_version = '1.0'
        c1.pkg_arch = 'x86'
        c1.pkg_type = 'rpm'
        c1.pkg_image_id = 'image123'
        c1.pkg_user_id = '0'
        c1.vulnerability_namespace_name = 'centos:6'
        c1.vulnerability_id = 'CVE-2016-123'
        c1.created_at = datetime.datetime.utcnow()

        c2 = copy.deepcopy(c1)
        self.assertEqual(c1, c2)
        c3 = copy.deepcopy(c1)
        self.assertEqual(c1, c3)
        c4 = copy.deepcopy(c1)
        self.assertEqual(c1, c4)

        c3.pkg_version = '1.1'
        c4.pkg_user_id = '1'

        self.assertEqual(c1, c2)
        self.assertNotEqual(c1, c4)
        self.assertNotEqual(c1, c3)
        self.assertListEqual(list({c1, c2, c3}), list({c1, c3}))

        print(('Set: {}'.format({c1, c2, c3})))

if __name__ == '__main__':
    t = TestImagePackageVulnerabilityHashing()
    t.run()