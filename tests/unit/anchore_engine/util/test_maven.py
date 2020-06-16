import unittest

from anchore_engine.util.maven import MavenVersion


class TestMavenVersionHandling(unittest.TestCase):
    _versions_qualifier_ = ['1-alpha2snapshot', '1-alpha2', '1-alpha-123', '1-beta-2', '1-beta123', '1-m2', '1-m11',
                            '1-rc', '1-cr2', '1-rc123', '1-SNAPSHOT', '1', '1-sp', '1-sp2', '1-sp123', '1-abc', '1-def',
                            '1-pom-1', '1-1-snapshot', '1-1', '1-2', '1-123']

    _versions_number_ = ['2.0', '2-1', '2.0.a', '2.0.0.a', '2.0.2', '2.0.123', '2.1.0', '2.1-a', '2.1b', '2.1-c',
                         '2.1-1', '2.1.0.1', '2.2', '2.123', '11.a2', '11.a11', '11.b2', '11.b11', '11.m2', '11.m11',
                         '11', '11.a', '11b', '11c', '11m']

    def _check_ordering_(self, versions, increasing=True):
        mvs = [MavenVersion(version) for version in versions]

        for l, r in zip(range(len(mvs)), range(1, len(mvs))):
            print('lhs - actual: {}, canonical: {}'.format(mvs[l].value, mvs[l]))
            print('rhs - actual: {}, canonical: {}'.format(mvs[r].value, mvs[r]))

            if increasing:
                small = mvs[l]
                big = mvs[r]
            else:
                small = mvs[r]
                big = mvs[l]

            self.assertLess(small, big, 'Expected {} to be less than {}'.format(small.value, big.value))
            self.assertEqual(small.compare_to(big), -1, 'Expected {} to be less than {}'.format(small.value, big.value))
            self.assertGreater(big, small, 'Expected {} to be greater than {}'.format(big.value, small.value))
            self.assertEqual(big.compare_to(small), 1,
                             'Expected {} to be greater than {}'.format(big.value, small.value))

    def test_versions_qualifier_order(self):
        self._check_ordering_(self._versions_qualifier_, increasing=True)
        self._check_ordering_(reversed(self._versions_qualifier_), increasing=False)

    def test_versions_number_order(self):
        self._check_ordering_(self._versions_number_, increasing=True)
        self._check_ordering_(reversed(self._versions_number_), increasing=False)

    def _check_op_(self, v1, v2, op):
        mv1 = MavenVersion(v1)
        mv2 = MavenVersion(v2)

        print('lhs - actual: {}, canonical: {}'.format(mv1.value, mv1))
        print('rhs - actual: {}, canonical: {}'.format(mv2.value, mv2))

        if op == '==':
            self.assertEqual(mv1, mv2, 'Expected {} and {} to be equal'.format(mv1.value, mv2.value))
            self.assertEqual(mv1.compare_to(mv2), 0, 'Expected {} and {} to be equal'.format(mv1.value, mv2.value))
            self.assertEqual(mv2.compare_to(mv1), 0, 'Expected {} and {} to be equal'.format(mv1.value, mv2.value))
            self.assertEqual(mv1.__hash__(), mv2.__hash__(), 'Expected hash code to be equal')
        elif op == '>':
            self.assertGreater(mv1, mv2, 'Expected {} to be greater than {}'.format(mv1.value, mv2.value))
            self.assertLess(mv2, mv1, 'Expected {} to be greater than {}'.format(mv1.value, mv2.value))
            self.assertEqual(mv1.compare_to(mv2), 1, 'Expected {} to be greater than {}'.format(mv1.value, mv2.value))
            self.assertEqual(mv2.compare_to(mv1), -1, 'Expected {} to be greater than {}'.format(mv1.value, mv2.value))
        elif op == '<':
            self.assertGreater(mv2, mv1, 'Expected {} to be less than {}'.format(mv1.value, mv2.value))
            self.assertLess(mv1, mv2, 'Expected {} to be less than {}'.format(mv1.value, mv2.value))
            self.assertEqual(mv1.compare_to(mv2), -1, 'Expected {} to be less than {}'.format(mv1.value, mv2.value))
            self.assertEqual(mv2.compare_to(mv1), 1, 'Expected {} to be less than {}'.format(mv1.value, mv2.value))

    def test_versions_equal(self):
        self._check_op_('0', '0.0.0', '==')
        self._check_op_('0.0', '0.0-0', '==')
        self._check_op_('1', '1', '==')
        self._check_op_('1', '1.0', '==')
        self._check_op_('1', '1.0.0', '==')
        self._check_op_('1.0', '1.0.0', '==')
        self._check_op_('1', '1-0', '==')
        self._check_op_('1', '1.0-0', '==')
        self._check_op_('1.0', '1.0-0', '==')
        # self._check_equal_('1a', '1.a', '==') # incorrect
        self._check_op_('1a', '1-a', '==')
        self._check_op_('1a', '1.0-a', '==')
        self._check_op_('1a', '1.0.0-a', '==')
        # self._check_equal_('1.0a', '1.0.a', '==') # incorrect
        # self._check_equal_('1.0.0a', '1.0.0.a', '==') # incorrect

        # aliases
        self._check_op_('1ga', '1', '==')
        self._check_op_('1final', '1', '==')
        self._check_op_('1cr', '1rc', '==')

        # special 'aliases' a, b and m for alpha, beta and milestone
        self._check_op_('1a1', '1alpha1', '==')
        self._check_op_('1b2', '1beta2', '==')
        self._check_op_('1m3', '1milestone3', '==')

    def testVersionComparing(self):
    
        self._check_op_('1', '2', '<')
        self._check_op_('1.5', '2', '<')
        self._check_op_('1', '2.5', '<')
        self._check_op_('1.0', '1.1', '<')
        self._check_op_('1.1', '1.2', '<')
        self._check_op_('1.0.0', '1.1', '<')
        self._check_op_('1.0.1', '1.1', '<')
        self._check_op_('1.1', '1.2.0', '<')
    
        self._check_op_('1.0-alpha-1', '1.0', '<')
        self._check_op_('1.0-alpha-1', '1.0-alpha-2', '<')
        self._check_op_('1.0-alpha-1', '1.0-beta-1', '<')

        self._check_op_('1.0-SNAPSHOT', '1.0-beta-1', '>')  # opposite of original test
        self._check_op_('1.0-SNAPSHOT', '1.0', '<')
        self._check_op_('1.0-alpha-1-SNAPSHOT', '1.0-alpha-1', '<')
    
        self._check_op_('1.0', '1.0-1', '<')
        self._check_op_('1.0-1', '1.0-2', '<')
        self._check_op_('1.0.0', '1.0-1', '<')
    
        self._check_op_('2.0-1', '2.0.1', '<')
        self._check_op_('2.0.1-klm', '2.0.1-lmn', '<')
        self._check_op_('2.0.1', '2.0.1-xyz', '<')

        self._check_op_('2.0.1', '2.0.1-123', '<')
        self._check_op_('2.0.1-xyz', '2.0.1-123', '<')