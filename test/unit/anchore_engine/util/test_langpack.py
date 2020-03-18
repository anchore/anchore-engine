import pytest
import subprocess
import unittest
from anchore_engine.util.langpack import compare_versions

enable_training = False

class TestSemverVersionHandling(unittest.TestCase):
    versions = [
        ('=1', '1', 'all', True),
        ('=1', '2', 'all', False),

        ('<=1', '1', 'all', True),
        ('<=1', '2', 'all', False),

        ('<1', '0', 'all', True),
        ('<1', '2', 'all', False),

        ('>=1', '1', 'all', True),
        ('>=1', '0', 'all', False),

        ('>1', '2', 'all', True),
        ('>1', '1', 'all', False),

        ('=1', '1', 'all', True),
        ('=1.0', '1.0', 'all', True),
        ('=1.0.0', '1.0.0', 'all', True),
        ('=1.0.0.0', '1.0.0.0', 'all', True),

        ('>1', '2', 'all', True),
        ('>1.0', '2', 'all', True),
        ('>1.0.0', '2', 'all', True),
        ('>1.0.0.0', '2', 'all', True),

        ('>1', '2', 'all', True),
        ('>1', '2.0', 'all', True),
        ('>1', '2.0.0', 'all', True),
        ('>1', '2.0.0.0', 'all', True),

        ('>0', 'blah', 'all', True),
        ('>0.0', 'blah', 'all', True),
        ('>0.0.0', 'blah', 'all', True),
        ('>0.0.0.0', 'blah', 'all', True),

        ('<0', 'blah', 'all', False),
        ('<0.0', 'blah', 'all', False),
        ('<0.0.0', 'blah', 'all', False),
        ('<0.0.0.0', 'blah', 'all', False),

        ('<0', '0', 'all', False),
        ('<0.0', '0', 'all', False),
        ('<0.0.0', '0', 'all', False),
        ('<0.0.0.0', '0', 'all', False),

        ('>1.0.0 <2.0.0', '1.5.0', 'all', True),
        ('>1.0.0 <2.0.0', '0.0.5', 'all', False),
        ('>1.0.0 <2.0.0', '2.5.0', 'all', False),

        ('>0.0.1 <0.0.9 || >1.0.1 <1.0.9', '0.0.5', 'all', True),
        ('>0.0.1 <0.0.9 || >1.0.1 <1.0.9', '1.0.5', 'all', True),
        ('>0.0.1 <0.0.9 || >1.0.1 <1.0.9', '0.0.0', 'all', False),
        ('>0.0.1 <0.0.9 || >1.0.1 <1.0.9', '1.0.0', 'all', False),
        ('>0.0.1 <0.0.9 || >1.0.1 <1.0.9', '2.0.0', 'all', False),

        ('~1', '2', 'all', False),
        ('~1', '1', 'all', True),

        ('~1.1', '2.0', 'all', False),
        ('~1.1', '1.2', 'all', False),
        ('~1.1', '1.0', 'all', False),
        ('~1.1', '1.1', 'all', True),
        ('~1.1', '1.1.1', 'all', True),
        ('~1.1', '1.1.99', 'all', True),

        ('~1.0.0', '2.0.0', 'all', False),
        ('~1.0.0', '1.1.0', 'all', False),
        ('~1.0.0', '1.0.0', 'all', True),
        ('~1.0.0', '1.0.1', 'all', True),
        ('~1.0.0', '1.0.99', 'all', True),

        ('~1.0.0-rc.2', '2.0.0', 'all', False),
        ('~1.0.0-rc.2', '1.0.0-rc.1', 'all', False),
        ('~1.0.0-rc.2', '1.0.0-rc.3', 'all', True),

        ('^1', '2', 'all', False),
        ('^1', '1', 'all', True),
        ('^1', '1.0', 'all', True),
        ('^1', '1.1', 'all', True),
        ('^1', '1.2', 'all', True),

        ('^1.1', '2.0', 'all', False),
        ('^1.1', '1.0', 'all', False),
        ('^1.1', '1.1', 'all', True),
        ('^1.1', '1.2', 'all', True),
        ('^1.1', '1.1.1', 'all', True),
        ('^1.1', '1.1.99', 'all', True),

        ('^1.1.0', '2.0.0', 'all', False),
        ('^1.1.0', '1.0.0', 'all', False),
        ('^1.1.0', '1.1.0', 'all', True),
        ('^1.1.0', '1.2.0', 'all', True),
        ('^1.1.0', '1.1.1', 'all', True),
        ('^1.1.0', '1.1.99', 'all', True),

        ('^1.0.0-rc.2', '2.0.0', 'all', False),
        ('^1.0.0-rc.2', '1.0.0-rc.1', 'all', False),
        ('^1.0.0-rc.2', '1.0.0-rc.3', 'all', True),

        ('>1.0.0-rc1.10001.11', '1.0.0-rc1.10001.12', 'all', True),
        ('>1.0.0-rc1.10001.11', '1.0.0-rc1.10002.11', 'all', True),
        ('>1.0.0-rc1.10001.11', '1.0.0-rc2.10001.11', 'all', True),
        ('>1.0.0-rc1.10001.11', '1.0.0-rc1.10001.10', 'all', False),
        ('>1.0.0-rc1.10001.11', '1.0.0-rc1.10000.11', 'all', False),
        ('>1.0.0-rc1.10001.11', '1.0.0-rc0.10001.11', 'all', False),

        ('>0.0.1 <0.0.9 || >1.0.1 <1.0.9', '', 'all', 'exception'),
        ('>0.0.1 <0.0.9 || >1.0.1 <1.0.9', None, 'all', 'exception'),
        ('>0.0.1 <0.0.9 || >1.0.1 <1.0.9', [], 'all', 'exception'),
        ('', '1', 'all', 'exception'),
        (None, '1', 'all', 'exception'),
        ([], '1', 'all', 'exception'),
        ('>==1', '1', 'all', 'exception'),
        ('>>1', '1', 'all', 'exception'),
        ('blah', '1', 'all', 'exception'),

        #add some language-specific version checks here in addition to the 'all' as above
        ('>1', '1-beta-1234', 'allbut:python,java', False),
        ('>1', '1.0.0.0-beta-1234', 'allbut:python,java', False),
        ('>0', '1-beta-1234', 'allbut:python,java', True),
        ('>0', '1.0.0.0-beta-1234', 'allbut:python,java', True),

        ('>1', '1-preview9.19421.4', 'allbut:python,java', False),
        ('>1', '1.0.0.0-preview9.19421.4', 'allbut:python,java', False),
        ('>0', '1-preview9.19421.4', 'allbut:python,java', True),
        ('>0', '1.0.0.0-preview9.19421.4', 'allbut:python,java', True),

        ('>1.0.0-rc1-100729', '1.0.0', 'allbut:python,java', True),
        ('>1.0.0-rc1-100729', '1', 'allbut:python,java', True),
        ('>1.0.0-rc1-100729', '1.0.0-rc1', 'allbut:python,java', False),
        ('>1.0.0-rc1-100729', '1-rc1', 'allbut:python,java', False),

    ]

    def test_version_comparison(self):
        alllangs = ['java', 'js', 'ruby', 'python', 'nuget']

        for lval, rval, lang, result in self.versions:
            if lang == 'all':
                testlangs = alllangs
            elif 'allbut' in lang:
                testlangs = list(alllangs)
                (ab, langlist) = lang.split(":")
                excludes = langlist.split(',')
                for exclude in excludes:
                    testlangs.remove(exclude)
            else:
                testlangs = [lang]
            for language in testlangs:
                print(('{} {} {}, Expected: {}'.format(lval, rval, language, result)))
                if type(result) == bool:
                    self.assertEqual(result, compare_versions(lval, rval, language=language))
                else:
                    did_exception=False
                    try:
                        compare_versions(lval, rval, language=language)
                        did_exception = False
                    except:
                        did_exception = True
                    self.assertEqual(True, did_exception)


all_languages = ['java', 'maven', 'js', 'npm', 'ruby', 'gem', 'nuget', 'python']
generic_languages = ['js', 'npm', 'ruby', 'gem', 'nuget']

lesser_versions = [
    '0', '0.0', '0.0.0', '0.0.0.0',
    '1', '1.0', '1.0.0', '1.0.0.0',
    '1.1', '1.0.1', '1.0.0.1',
    '1.1.1', '1.0.1.1',
    '1.1.1.1',
]

greater_versions = [
    '2', '2.0', '2.0.0', '2.0.0.0',
    '2.2', '2.0.2', '2.0.0.2',
    '2.2.2', '2.0.2.2',
    '2.2.2.2',
]

greater_versions_rc = [
    "%s-%s" % (ver, rc) for ver in greater_versions
    for rc in ['rc1', 'rc.1', 'rc1.10001.11']
]

lesser_versions_rc = [
    "%s-%s" % (ver, rc) for ver in lesser_versions
    for rc in ['rc1', 'rc.1', 'rc1.10001.11']
]


greater_than_operators = ['>', '>=']
lesser_than_operators = ['<', '<=']


@pytest.fixture(params=['%s %s' % (op, ver) for op in greater_than_operators for ver in lesser_versions])
def greater_than_versions(request):
    # > 0.0.1
    return request.param


@pytest.fixture(params=['%s %s' % (op, ver) for op in greater_than_operators for ver in greater_versions])
def greater_than_versions_high(request):
    # > 2.0.0
    return request.param


@pytest.fixture(params=['%s %s' % (op, ver) for op in greater_than_operators for ver in lesser_versions_rc])
def greater_than_rc_versions(request):
    # > 0.0.1-rc1
    return request.param


@pytest.fixture(params=['%s %s' % (op, ver) for op in lesser_than_operators for ver in greater_versions])
def lesser_than_versions(request):
    # < 2.0.0
    return request.param


@pytest.fixture(params=['%s %s' % (op, ver) for op in lesser_than_operators for ver in lesser_versions])
def lesser_than_versions_low(request):
    # < 2.0.0
    return request.param


@pytest.fixture(params=['%s %s' % (op, ver) for op in lesser_than_operators for ver in greater_versions_rc])
def lesser_than_rc_versions(request):
    # < 2.0.0-rc1
    return request.param


@pytest.mark.parametrize('right', greater_versions)
@pytest.mark.parametrize('lang', all_languages)
def test_greater_than(greater_than_versions, right, lang):
    assert compare_versions(greater_than_versions, right, lang) is True


@pytest.mark.parametrize('right', greater_versions)
@pytest.mark.parametrize('lang', all_languages)
def test_greater_than_rc(greater_than_rc_versions, right, lang):
    assert compare_versions(greater_than_rc_versions, right, lang) is True


@pytest.mark.parametrize('right', lesser_versions)
@pytest.mark.parametrize('lang', all_languages)
def test_lesser_than(lesser_than_versions, right, lang):
    assert compare_versions(lesser_than_versions, right, lang) is True


@pytest.mark.parametrize('right', lesser_versions)
@pytest.mark.parametrize('lang', all_languages)
def test_lesser_than_rc(lesser_than_rc_versions, right, lang):
    assert compare_versions(lesser_than_rc_versions, right, lang) is True



@pytest.mark.parametrize('right', lesser_versions)
@pytest.mark.parametrize('lang', all_languages)
def test_not_greater_than(greater_than_versions_high, right, lang):
    assert compare_versions(greater_than_versions_high, right, lang) is False


@pytest.mark.parametrize('right', greater_versions)
@pytest.mark.parametrize('lang', all_languages)
def test_not_lesser_than(lesser_than_versions_low, right, lang):
    assert compare_versions(lesser_than_versions_low, right, lang) is False
