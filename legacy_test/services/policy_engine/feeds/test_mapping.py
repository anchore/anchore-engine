import unittest
import os
from anchore_engine.services.policy_engine.engine.feeds import Vulnerability, VulnerabilityFeedDataMapper, GemPackageDataMapper, NpmPackageDataMapper, GemMetadata, NpmMetadata, DataFeeds
from legacy_test.services.policy_engine.utils import init_db, LocalTestDataEnvironment

test_env = LocalTestDataEnvironment(data_dir=os.environ['ANCHORE_ENGINE_TEST_HOME'])
init_db(test_env.mk_db())


class TestVulnerabilityMapping(unittest.TestCase):
    """
    Tests Feed mapping objects
    """

    test_cve = {
        'Vulnerability': {
            'Description': 'Async Http Client (aka AHC or async-http-client) before 1.9.0 skips X.509 certificate verification unless both a keyStore location and a trustStore location are explicitly set, which allows man-in-the-middle attackers to spoof HTTPS servers by presenting an arbitrary certificate during use of a typical AHC configuration, as demonstrated by a configuration that does not send client certificates.',
            'FixedIn': [
                {
                    'Name': 'async-http-client',
                    'NamespaceName': 'debian:9',
                    'Version': '1.6.5-3',
                    'VersionFormat': 'dpkg',
                    'VendorAdvisory': {
                        'NoAdvisory': False,
                        'AdvisorySummary': [
                            {
                                'ID': 'DSA-0000-0',
                                'Link': 'https://security-tracker.debian.org/tracker/DSA-0000-0'
                            }
                        ]
                    }
                }
            ],
            'Link': 'https://security-tracker.debian.org/tracker/CVE-2013-7397',
            'Metadata': {
                'NVD': {
                    'CVSSv2': {
                        'Score': 4.3,
                        'Vectors': 'AV:N/AC:M/Au:N/C:N/I:P'
                    }
                }
            },
            'Name': 'CVE-2013-7397',
            'NamespaceName': 'debian:9',
            'Severity': 'Medium'
        }
    }

    test_cve2 = {
        'Vulnerability': {
            'Description': 'Async Http Client (aka AHC or async-http-client) before 1.9.0 skips X.509 certificate verification unless both a keyStore location and a trustStore location are explicitly set, which allows man-in-the-middle attackers to spoof HTTPS servers by presenting an arbitrary certificate during use of a typical AHC configuration, as demonstrated by a configuration that does not send client certificates.',
            'FixedIn': [
            ],
            'Link': 'https://security-tracker.debian.org/tracker/CVE-2013-7397',
            'Metadata': {},
            'Name': 'CVE-2013-7397',
            'NamespaceName': 'debian:9',
            'Severity': 'Medium'}
    }

    test_cve3 = {
        'Vulnerability': {
            'Description': 'Async Http Client (aka AHC or async-http-client) before 1.9.0 skips X.509 certificate verification unless both a keyStore location and a trustStore location are explicitly set, which allows man-in-the-middle attackers to spoof HTTPS servers by presenting an arbitrary certificate during use of a typical AHC configuration, as demonstrated by a configuration that does not send client certificates.',
            'FixedIn': [
            ],
            'VulnerableIn': [
                {
                    'Name': 'notasync-http-client',
                    'NamespaceName': 'debian:9',
                    'Version': '1.2.3.4',
                    'VersionFormat': 'dpkg'
                }
            ],
            'Link': 'https://security-tracker.debian.org/tracker/CVE-2013-7397',
            'Metadata': {},
            'Name': 'CVE-2013-7397',
            'NamespaceName': 'debian:9',
            'Severity': 'Medium'
        }
    }

    long_cve = {
        'Vulnerability': {
            'Description': '0'.join([str(i) for i in range(65000)]) + 'Async Http Client (aka AHC or async-http-client) before 1.9.0 skips X.509 certificate verification unless both a keyStore location and a trustStore location are explicitly set, which allows man-in-the-middle attackers to spoof HTTPS servers by presenting an arbitrary certificate during use of a typical AHC configuration, as demonstrated by a configuration that does not send client certificates.',
            'FixedIn': [
            ],
            'Link': 'https://security-tracker.debian.org/tracker/CVE-2013-7397',
            'Metadata': {},
            'Name': 'CVE-2013-7397',
            'NamespaceName': 'debian:9',
            'Severity': 'Medium'
        }
    }

    invalid_1 = {'NotAVulnerability': {}}
    invalid_2 = {'Vulnerability': {'Name': 'SomeCVE'}}

    mapper = VulnerabilityFeedDataMapper(feed_name='vulnerabilities', group_name='debian:9', keyname='Name')

    def test_valid(self):
        r = self.mapper.map(self.test_cve)
        self.assertEqual(r.id, self.test_cve['Vulnerability']['Name'])
        self.assertEqual(r.namespace_name, self.test_cve['Vulnerability']['NamespaceName'])
        self.assertEqual(len(r.fixed_in), 1)
        self.assertEqual(len(r.vulnerable_in), 0)
        self.assertEqual(r.severity, self.test_cve['Vulnerability']['Severity'])

    def test_invalid(self):
        with self.assertRaises(Exception) as f:

            self.mapper.map(self.invalid_1)

        with self.assertRaises(Exception) as f:
            self.mapper.map(self.invalid_2)

    def test_overflow(self):
        r = self.mapper.map(self.long_cve)
        print(('Truncated description length: {} from {}'.format(len(r.description),
                                                                len(self.long_cve['Vulnerability']['Description']))))
        self.assertEqual(r.id, self.test_cve['Vulnerability']['Name'])
        self.assertEqual(r.namespace_name, self.test_cve['Vulnerability']['NamespaceName'])
        self.assertEqual(len(r.fixed_in), 0)
        self.assertEqual(len(r.vulnerable_in), 0)
        self.assertLess(len(r.description), 1024*64)

    @unittest.skipIf(not test_env, 'No test_env found in env')
    def test_full_data(self):
        c = DataFeeds.instance().vulnerabilities.source
        for g in c.list_feed_groups('vulnerabilities'):
            print(('Group: {}'.format(g.name)))
            for v in c.get_feed_group_data('vulnerabilities', g.name):
                r = self.mapper.map(v)
                self.assertTrue(TestVulnerabilityMapping._vuln_validator(r), 'Failed validation on: {}'.format(v))


    @staticmethod
    def _vuln_validator(v):
        if not isinstance(v, Vulnerability):
            return False

        if v.id is None or \
           v.severity is None or \
            v.namespace_name is None:
            return False

        if v.severity not in ['Unknown', 'Negligible', 'Low', 'Medium', 'High', 'Critical']:
            return False

        return True


class TestNpmMapping(unittest.TestCase):
    mapper = NpmPackageDataMapper(feed_name='packages', group_name='npm', keyname='name')
    valid = [
        { 'testnpm': {
                'name': 'testnpm',
                'origins': ['origin1', 'origin2'],
                'versions': ['1.0.0', '1.0', '1.4'],
                'sourcepkg': 'testnpm-src',
                'lics': ['mit', 'bsd'],
                'latest': '1.4'
            }
        }, {'testnpm': {
                'name': 'testnpm',
                'origins': None,
                'versions': ['1.0.0', '1.0', '1.4'],
                'sourcepkg': 'testnpm-src',
                'lics': ['mit', 'bsd'],
                'latest': None
            }
        }, { 'testnpm': {
            'name': 'testnpm',
            'origins': ['origin1', 'origin2'],
            'versions': [],
            'sourcepkg': 'testnpm-src',
            'lics': None,
            'latest': '1.4'
            }
        }
    ]

    invalid = [
        { 'testnpm': {
            'origins': ['origin1', 'origin2'],
            'versions': [],
            'sourcepkg': 'testnpm-src',
            'lics': None,
            'latest': '1.4'
            }
        }, {'name': 'testnpm',
            'origins': ['origin1', 'origin2'],
            'versions': [],
            'sourcepkg': 'testnpm-src',
            'lics': None,
            'latest': '1.4'
        }
    ]

    overflow_1 = {
        'name': 'MyName',
        'versions': [str(i) for i in range(100000)]
    }

    def test_valid(self):
        for e in self.valid:
            self.assertTrue(TestNpmMapping._npm_validator(self.mapper.map(e)))

    def test_invalid(self):
        for e in self.invalid:
            self.assertFalse(TestNpmMapping._npm_validator(self.mapper.map(e)))

    def test_overflow(self):
        pass

    @unittest.skipIf(not test_env, 'No test_env found in env')
    def test_full_data(self):
        c = DataFeeds.instance().vulnerabilities.source
        count = 1
        for v in c.get_feed_group_data('packages', 'npm'):
            r = self.mapper.map(v)
            self.assertTrue(TestNpmMapping._npm_validator(r), 'Failed validation on #{} : {}'.format(count, v))
            count += 1

    @staticmethod
    def _npm_validator(n):
        if not isinstance(n, NpmMetadata):
            return False

        if not n.name:
            # TODO: make this a better check. Perhaps validating the content of the json as lists
            return False

        return True


class TestGemMapping(unittest.TestCase):
    mapper = GemPackageDataMapper(feed_name='packages', group_name='gem', keyname='name')

    def test_valid(self):
        pass

    def test_invalid(self):
        pass

    def test_overflow(self):
        pass

    @unittest.skipIf(not test_env, 'No test_env found in env')
    def test_full_data(self):
        count = 1
        c = DataFeeds.instance().vulnerabilities.source
        for v in c.get_feed_group_data('packages', 'gem'):
            r = self.mapper.map(v)
            self.assertTrue(TestGemMapping._gem_validator(r), 'Failed validation on #{}: {}'.format(count, v))
            count += 1

    @staticmethod
    def _gem_validator(n):
        if not isinstance(n, GemMetadata):
            return False

        if not n.name or not n.versions_json or not n.authors_json or not n.licenses_json or not n.id or not n.latest:
            return False

        return True


