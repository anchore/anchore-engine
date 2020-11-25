import unittest

from anchore_engine.util.rpm import compare_versions


class TestRpmVersionHandling(unittest.TestCase):
    """
    Tests for version comparisons of rpm package versions maintained in anchore engine.
    Note that this does not exactly confirm the official rpm spec

    """

    def test_version_comparison(self):
        test_epoch = [
            ("1:0", "0:1", 1),
            ("1:0", "1", -1),
            ("1:2", "1", 1),
            ("2:4.19.01-1.el7_5", "4.19.1-1.el7_5", 0),
            ("4.19.01-1.el7_5", "2:4.19.1-1.el7_5", 0),
            ("0:4.19.1-1.el7_5", "2:4.19.1-1.el7_5", -1),
            ("4.19.0-1.el7_5", "12:4.19.0-1.el7", 1),
            ("3:4.19.0-1.el7_5", "4.21.0-1.el7", -1),
            ("4:1.2.3-3-el7_5", "1.2.3-el7_5~snapshot1", 1),
        ]

        test_no_epoch = [
            ("1", "1", 0),
            ("4.19.0a-1.el7_5", "4.19.0c-1.el7", -1),
            ("4.19.0-1.el7_5", "4.21.0-1.el7", -1),
            ("4.19.01-1.el7_5", "4.19.10-1.el7_5", -1),
            ("4.19.0-1.el7_5", "4.19.0-1.el7", 1),
            ("4.19.0-1.el7_5", "4.17.0-1.el7", 1),
            ("4.19.01-1.el7_5", "4.19.1-1.el7_5", 0),
            ("4.19.1-1.el7_5", "4.19.1-01.el7_5", 0),
            ("4.19.1", "4.19.1", 0),
            ("1.2.3-el7_5~snapshot1", "1.2.3-3-el7_5", -1),
        ]

        for i in test_epoch + test_no_epoch:
            self.assertEqual(
                i[2],
                compare_versions(i[0], i[1]),
                "comparison between {} and {}".format(i[0], i[1]),
            )
            print("Tested: {}".format(i))
