import unittest
from anchore_engine.services.policy_engine.engine.policy.utils import barsplit_comma_delim_parser, delim_parser, CommaDelimitedNumberListValidator, \
    PipeDelimitedStringListValidator, CommaDelimitedStringListValidator, NameVersionListValidator


class TestParamParsers(unittest.TestCase):
    def _run_test_table(self, table, fn):
        for t in table:
            self.assertEqual(t['result'], fn(t['test']))

    def testDelimParser(self):
        test_table = [
            {'test': 'a,b', 'result': ['a', 'b']},
            {'test': ' a , b ', 'result': ['a', 'b']},
            {'test': 'a,b,', 'result': ['a', 'b', '']}
        ]
        self._run_test_table(test_table, delim_parser)

        test_table = [
            {'test': 'a|b', 'result': ['a', 'b']},
            {'test': ' a | b ', 'result': ['a', 'b']},
            {'test': 'a|b|', 'result': ['a', 'b', '']}
        ]
        self._run_test_table(test_table, lambda x: delim_parser(param_value=x, item_delimiter='|'))

    def testBarsplitCommaDelimParser(self):
        test_table = [
            {'test': 'a|b,c|d', 'result': {'a': 'b', 'c': 'd'}},
            {'test': ' a|b , c|d ', 'result': {'a': 'b', 'c': 'd'}},
            {'test': ' a|b,c|d ', 'result': {'a': 'b', 'c': 'd'}},
            {'test': ' a-b.c-09-e|b,c|d ', 'result': {'a-b.c-09-e': 'b', 'c': 'd'}},
        ]
        self._run_test_table(test_table, barsplit_comma_delim_parser)


class TestParamValidators(unittest.TestCase):
    def _run_test_table(self, table, fn):
        for t in table:
            self.assertEqual(t['result'], fn(t['test']), 'Failed on: {}'.format(t['test']))

    def testCommaDelimitedNumberListValidator(self):
        test_table = [
            {'test': '0,1', 'result': True},
            {'test': ' 0 , 1 ', 'result': True},
            {'test': ' 0, 1,', 'result': True},
            {'test': ' 0-2, 1,', 'result': False},
            {'test': ' a, b,', 'result': False},
            {'test': '0-10,', 'result': False},
            {'test': '', 'result': True}
        ]
        self._run_test_table(test_table, CommaDelimitedNumberListValidator())

    def testCommaDelimitedStringListValidator(self):
        test_table = [
            {'test': 'aa2sad[]0-=23sd,q!_-a-=///', 'result': True},
            {'test': ' ab[]0-1+///.... , a091as0812nb, ', 'result': True},
            {'test': ' [][].. , @##$%!@', 'result': True},
            {'test': ' 0-2, 1,', 'result': True},
            {'test': ' a, b,', 'result': True},
            {'test': '', 'result': True}
        ]
        self._run_test_table(test_table, CommaDelimitedStringListValidator())

    def testPipeDelimitedStringListValidator(self):
        test_table = [
            {'test': '0|1', 'result': True},
            {'test': ' 0 | 1 ', 'result': True},
            {'test': ' 0| 1,a', 'result': True},
            {'test': ' 0-2| 1,a', 'result': True},
            {'test': ' a | s,a', 'result': True},
            {'test': '', 'result': True}
        ]
        self._run_test_table(test_table, PipeDelimitedStringListValidator())

    def testNameVersionListValidator(self):
        test_table = [
            {'test': 'a0|b1,c2|d3-c.29', 'result': True},
            {'test': ' a0|b1 , c1|2e-4.a ', 'result': True},
            {'test': ' lib|version-0.1, lib2|v2,', 'result': True},
            {'test': '', 'result': True}
        ]
        self._run_test_table(test_table, NameVersionListValidator())
