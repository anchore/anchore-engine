import unittest
from anchore_engine.services.policy_engine.engine.util.deb import compare_versions


class TestDpkgVersionHandling(unittest.TestCase):
    """
    Tests for version comparisons of the dpkg version parser and compare code.

    """

    def test_version_comparision(self):
        test_epoch = [
            ('1','1', 0),
            ('1:0', '0:10', 1),
            (),
            (),
            (),
        ]

        test_no_epoch = [
            ('1.01.1', '1.1.1', 'eq', False),
            ('1.01.1', '1.1.1', 'lt', True),
            ('1.01.1', '1.1.1', 'le', True),
            ('1.101.1', '1.100.1', 'eq', False),
            ('1.100a.1', '1.9a9.100', 'eq', False),
            ('1.100.1', '1.99.100', 'eq', False),
            ('1.100.1', '1.99.100', 'eq', False),
            ('1.100.1', '1.99.100', 'eq', False)
        ]


        for i in test_no_epoch:
            print(('Testing: {}'.format(i)))
            if not i[3] == compare_versions(i[0], i[2], i[1]):
                print('Mismatch!')
            else:
                print('Match!')

        print((compare_versions('1.900.1-debian1-2.4+deb8u3', 'lt', '1.900.1-5.1')))
