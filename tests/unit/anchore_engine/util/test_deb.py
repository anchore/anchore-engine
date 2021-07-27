import unittest

from anchore_engine.util.deb import compare_versions, strict_compare_versions


class TestDpkgVersionHandling(unittest.TestCase):
    """
    Tests for version comparisons of the dpkg version parser and compare code.

    """

    def test_strict_version_comparison(self):
        print("Testing strict version comparison")
        test_epoch = [
            ("1:0", "0:10", "gt", True),
            ("1:0", "1", "le", False),
            ("1:2", "1", "gt", True),
            ("1:5.14-2ubuntu3", "1:5.14-2ubuntu3.1", "lt", True),
            ("1:5.14-2ubuntu3", "5.14-2ubuntu3.1", "gt", True),
            ("5.14-2ubuntu3", "1:5.14-2ubuntu3.1", "le", True),
        ]

        test_no_epoch = [
            ("1", "1", "eq", True),
            ("1.01.1", "1.1.1", "eq", True),
            ("1.01.1", "1.1.1", "lt", False),
            ("1.01.1", "1.1.1", "le", True),
            ("1.101.1", "1.100.1", "eq", False),
            ("1.100a.1", "1.9a9.100", "eq", False),
            ("1.100.1", "1.99.100", "eq", False),
        ]

        for i in test_epoch + test_no_epoch:
            self.assertEqual(
                i[3],
                strict_compare_versions(i[0], i[2], i[1]),
                "{} {} {}".format(i[0], i[2], i[1]),
            )
            print("Tested: {}".format(i))

    def test_version_comparision(self):
        print("Testing anchore engine specific version comparison")
        test_epoch = [
            ("1:0", "0:10", "gt", True),
            ("1:0", "1", "ge", False),
            ("1:2", "1", "gt", True),
            ("1:5.14-2ubuntu3", "1:5.14-2ubuntu3.1", "lt", True),
            ("1:5.14-2ubuntu3", "5.14-2ubuntu3", "eq", True),
            ("5.14-2ubuntu3", "1:5.14-2ubuntu3.1", "le", True),
        ]

        test_no_epoch = [
            ("1", "1", "eq", True),
            ("1.01.1", "1.1.1", "eq", True),
            ("1.01.1", "1.1.1", "lt", False),
            ("1.01.1", "1.1.1", "le", True),
            ("1.101.1", "1.100.1", "eq", False),
            ("1.100a.1", "1.9a9.100", "eq", False),
            ("1.100.1", "1.99.100", "eq", False),
        ]

        for i in test_epoch + test_no_epoch:
            self.assertEqual(
                i[3],
                compare_versions(i[0], i[2], i[1]),
                "{} {} {}".format(i[0], i[2], i[1]),
            )
            print("Tested: {}".format(i))
