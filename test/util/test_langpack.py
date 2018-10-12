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

        ('>0.0.1 <0.0.9 || >1.0.1 <1.0.9', '', 'all', 'exception'),
        ('>0.0.1 <0.0.9 || >1.0.1 <1.0.9', None, 'all', 'exception'),
        ('>0.0.1 <0.0.9 || >1.0.1 <1.0.9', [], 'all', 'exception'),
        ('', '1', 'all', 'exception'),
        (None, '1', 'all', 'exception'),
        ([], '1', 'all', 'exception'),
        ('>==1', '1', 'all', 'exception'),
        ('>>1', '1', 'all', 'exception'),
        ('blah', '1', 'all', 'exception'),
        
        #TODO need to add some language-specific version checks here in addition to the 'all' as above
    ]

    def test_version_comparison(self):
        alllangs = ['java', 'js', 'ruby', 'python']

        for lval, rval, lang, result in self.versions:
            if lang == 'all':
                testlangs = alllangs
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
#    @classmethod
#    def setUpClass(cls):
#        pass
