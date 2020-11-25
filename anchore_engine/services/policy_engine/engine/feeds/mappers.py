import copy
import re

from anchore_engine.db import (
    GenericFeedDataRecord,
    GemMetadata,
    NpmMetadata,
    NvdV2Metadata,
    CpeV2Vulnerability,
    VulnDBMetadata,
    VulnDBCpe,
    Vulnerability,
    FixedArtifact,
)
from anchore_engine.subsys import logger
from anchore_engine.utils import CPE


class SingleTypeMapperFactory(object):
    def __init__(self, feed_name, mapper_clazz, common_key=None):
        """
        Create a single-type mapper factory that returns mappers of type <mapper_clazz>

        :param feed_name: name of the feed to configure into the mapper
        :param mapper_clazz: the class to instantiate when requested
        :param common_key: the data key to look for in items if all groups use the same key name for data items
        """

        self.feed = feed_name
        self.mapper_clazz = mapper_clazz
        self.common_key = common_key

    def __getitem__(self, item):
        return self.mapper_clazz(self.feed, item, self.common_key)

    def get(self, item):
        return self.__getitem__(item)


class FeedDataMapper(object):
    """
    Base interface for mapping feed records into the db
    """

    def __init__(self, feed_name, group_name, keyname):
        self.feed = feed_name
        self.group = group_name
        self.key_item_name = keyname

    def map(self, record_json):
        """
        Entrypoint to do the mapping, a wrapper for the inner map() function to pre-process the json.

        :param record_json: data record deserialized from json (dict) to map
        :return: a DB entity that can be added to a session/persisted
        """
        raise NotImplementedError()


class KeyIDFeedDataMapper(FeedDataMapper):
    """
    A mapper for handling the case where each data item is a single key that is the id itself, without a field identifier.

    E.g. { 'my_id1': { 'data1': 'value1'} } -> key='my_id1', data={'data1':'value1'}

    """

    def map(self, record_json):
        if len(list(record_json.keys())) == 1:
            key, value = list(record_json.items())[0]
            return self.map_inner(key, value)

    def map_inner(self, key, data):
        raise NotImplementedError()


class GenericFeedDataMapper(KeyIDFeedDataMapper):
    """
    A generic mapping class to consume feed json and return db objects
    """

    def map_inner(self, key, data):
        """
        Map a single data feed record from msg to db format
        :param record_json: data record deserialized from json (dict) to map
        :return: a DB entity that can be added to a session/persisted
        """

        db_rec = GenericFeedDataRecord()
        db_rec.feed = self.feed
        db_rec.group = self.group
        db_rec.id = key
        db_rec.data = data
        return db_rec


class GemPackageDataMapper(KeyIDFeedDataMapper):
    """
    Maps a Gem package feed record to a db record
    """

    def map_inner(self, key, data):
        db_rec = GemMetadata()
        db_rec.name = key[:255]
        db_rec.id = int(data.get("id")) if data.get("id") else -1
        db_rec.authors_json = data.get("authors")
        db_rec.versions_json = data.get("versions")
        db_rec.licenses_json = data.get("licenses")
        db_rec.latest = data.get("latest")[:255] if data.get("latest") else None
        return db_rec


class NpmPackageDataMapper(KeyIDFeedDataMapper):
    """
    Maps a NPM package record to the db record
    """

    def map_inner(self, key, data):
        db_rec = NpmMetadata()
        db_rec.name = key[:255]
        db_rec.versions_json = data.get("versions")
        db_rec.latest = data.get("latest")[:255] if data.get("latest") else None
        db_rec.sourcepkg = (
            data.get("sourcepkg")[:255] if data.get("sourcepkg") else None
        )
        db_rec.origins_json = data.get("origins")
        db_rec.lics_json = data.get("lics")
        return db_rec


class NvdV2FeedDataMapper(FeedDataMapper):
    """
    Maps an NVD record into an NvdMetadata ORM object
    """

    def map(self, record_json):
        # log.debug("V2 DBREC: {}".format(json.dumps(record_json)))

        # Copy it to ensure no lingering refs to source json doc
        record_json = copy.deepcopy(record_json)

        db_rec = NvdV2Metadata()
        db_rec.name = (
            record_json.get("cve", {}).get("CVE_data_meta", {}).get("ID", None)
        )
        db_rec.namespace_name = self.group
        db_rec.description = (
            record_json.get("cve", {})
            .get("description", {})
            .get("description_data", [{}])[0]
            .get("value", "")
        )
        db_rec.cvss_v2 = record_json.get("cvss_v2", None)
        db_rec.cvss_v3 = record_json.get("cvss_v3", None)
        db_rec.severity = (
            record_json.get("severity")
            if record_json.get("severity", None)
            else "Unknown"
        )
        db_rec.link = "https://nvd.nist.gov/vuln/detail/{}".format(db_rec.name)
        db_rec.references = record_json.get("external_references", [])

        db_rec.vulnerable_cpes = []
        for input_cpe in record_json.get("vulnerable_cpes", []):
            try:
                # "cpe:2.3:a:openssl:openssl:-:*:*:*:*:*:*:*",
                # TODO - handle cpe inputs with escaped characters
                # cpetoks = input_cpe.split(":")
                cpe_obj = CPE.from_cpe23_fs(input_cpe)
                newcpe = CpeV2Vulnerability()
                newcpe.feed_name = self.feed
                newcpe.part = cpe_obj.part
                newcpe.vendor = cpe_obj.vendor
                newcpe.product = cpe_obj.product
                newcpe.version = cpe_obj.version
                newcpe.update = cpe_obj.update
                newcpe.edition = cpe_obj.edition
                newcpe.language = cpe_obj.language
                newcpe.sw_edition = cpe_obj.sw_edition
                newcpe.target_sw = cpe_obj.target_sw
                newcpe.target_hw = cpe_obj.target_hw
                newcpe.other = cpe_obj.other
                db_rec.vulnerable_cpes.append(newcpe)
            except Exception as err:
                logger.warn(
                    "failed to convert vulnerable-software-list into database CPEV2 record - exception: "
                    + str(err)
                )

        return db_rec


class VulnDBFeedDataMapper(FeedDataMapper):
    """
    Maps an VulnDB record into an ORM object
    """

    def map(self, record_json):
        # log.debug("V2 DBREC: {}".format(json.dumps(record_json)))
        db_rec = VulnDBMetadata()
        db_rec.name = record_json.get("id")
        db_rec.namespace_name = self.group
        db_rec.title = record_json.get("title", None)
        db_rec.description = record_json.get("description", None)
        db_rec.solution = record_json.get("solution", None)
        db_rec.vendor_product_info = record_json.get("vendor_product_info", [])
        db_rec.references = record_json.get("external_references", [])
        db_rec.vulnerable_packages = record_json.get("vulnerable_packages", [])
        db_rec.vulnerable_libraries = record_json.get("vulnerable_libraries", [])
        db_rec.vendor_cvss_v2 = record_json.get("vendor_cvss_v2", [])
        db_rec.vendor_cvss_v3 = record_json.get("vendor_cvss_v3", [])
        db_rec.nvd = record_json.get("nvd", [])
        db_rec.vuln_metadata = record_json.get("metadata", {})
        db_rec.severity = (
            record_json.get("severity")
            if record_json.get("severity", None)
            else "Unknown"
        )

        db_rec.cpes = []
        for input_cpe in record_json.get("vulnerable_cpes", []):
            try:
                # "cpe:2.3:a:openssl:openssl:-:*:*:*:*:*:*:*",
                cpe_obj = CPE.from_cpe23_fs(input_cpe)
                newcpe = VulnDBCpe()
                newcpe.feed_name = self.feed
                # newcpe.severity = db_rec.severity  # todo ugh! get this from the parent!
                newcpe.part = cpe_obj.part
                newcpe.vendor = cpe_obj.vendor.replace("\\", "")
                newcpe.product = cpe_obj.product.replace("\\", "")
                newcpe.version = cpe_obj.version.replace("\\", "")
                newcpe.update = cpe_obj.update.replace("\\", "")
                newcpe.edition = cpe_obj.edition.replace("\\", "")
                newcpe.language = cpe_obj.language.replace("\\", "")
                newcpe.sw_edition = cpe_obj.sw_edition.replace("\\", "")
                newcpe.target_sw = cpe_obj.target_sw.replace("\\", "")
                newcpe.target_hw = cpe_obj.target_hw.replace("\\", "")
                newcpe.other = cpe_obj.other.replace("\\", "")
                newcpe.is_affected = True

                db_rec.cpes.append(newcpe)
            except Exception as err:
                logger.warn(
                    "failed to convert vendor_product_info into database VulnDBCpe record - exception: "
                    + str(err)
                )

        for input_cpe in record_json.get("unaffected_cpes", []):
            try:
                # "cpe:2.3:a:openssl:openssl:-:*:*:*:*:*:*:*",
                cpe_obj = CPE.from_cpe23_fs(input_cpe)
                newcpe = VulnDBCpe()
                newcpe.feed_name = self.feed
                # newcpe.severity = db_rec.severity  # todo ugh! get this from the parent!
                newcpe.part = cpe_obj.part
                newcpe.vendor = cpe_obj.vendor.replace("\\", "")
                newcpe.product = cpe_obj.product.replace("\\", "")
                newcpe.version = cpe_obj.version.replace("\\", "")
                newcpe.update = cpe_obj.update.replace("\\", "")
                newcpe.edition = cpe_obj.edition.replace("\\", "")
                newcpe.language = cpe_obj.language.replace("\\", "")
                newcpe.sw_edition = cpe_obj.sw_edition.replace("\\", "")
                newcpe.target_sw = cpe_obj.target_sw.replace("\\", "")
                newcpe.target_hw = cpe_obj.target_hw.replace("\\", "")
                newcpe.other = cpe_obj.other.replace("\\", "")
                newcpe.is_affected = False

                db_rec.cpes.append(newcpe)
            except Exception as err:
                logger.warn(
                    "failed to convert vendor_product_info into database VulnDBCpe record - exception: "
                    + str(err)
                )

        return db_rec


class VulnerabilityFeedDataMapper(FeedDataMapper):
    """
    Maps a Vulnerability record:

    Example:
    {
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
                        'Vectors': u'AV:N/AC:M/Au:N/C:N/I:P'
                    }
                }
            },
            'Name': 'CVE-2013-7397',
            'NamespaceName': 'debian:9',
            'Severity': 'Medium'}
    }
    """

    defaults = {"Severity": "Unknown", "Link": None, "Description": None}

    MAX_STR_LEN = 1024 * 64 - 4

    def map(self, record_json):
        if not record_json:
            return None

        # Handle a 'Vulnerability' wrapper around the specific record. If not present, assume a direct record
        if len(list(record_json.keys())) == 1 and record_json.get("Vulnerability"):
            vuln = record_json["Vulnerability"]
        else:
            vuln = record_json

        db_rec = Vulnerability()
        db_rec.id = vuln["Name"]
        db_rec.namespace_name = self.group
        db_rec.severity = vuln.get("Severity", "Unknown")
        db_rec.link = vuln.get("Link")
        description = vuln.get("Description", "")
        if description:
            db_rec.description = (
                vuln.get("Description", "")
                if len(vuln.get("Description", "")) < self.MAX_STR_LEN
                else (vuln.get("Description")[: self.MAX_STR_LEN - 8] + "...")
            )
        else:
            db_rec.description = ""
        db_rec.fixed_in = []
        # db_rec.vulnerable_in = []

        # db_rec.metadata_json = json.dumps(vuln.get('Metadata')) if 'Metadata' in vuln else None
        db_rec.additional_metadata = vuln.get("Metadata", {})
        cvss_data = vuln.get("Metadata", {}).get("NVD", {}).get("CVSSv2")
        if cvss_data:
            db_rec.cvss2_vectors = cvss_data.get("Vectors")
            db_rec.cvss2_score = cvss_data.get("Score")

        # Process Fixes
        if "FixedIn" in vuln:
            for f in vuln["FixedIn"]:
                fix = FixedArtifact()
                fix.name = f["Name"]
                fix.version = f["Version"]
                fix.version_format = f["VersionFormat"]
                fix.epochless_version = re.sub(r"^[0-9]*:", "", f["Version"])
                fix.vulnerability_id = db_rec.id
                fix.namespace_name = self.group
                fix.vendor_no_advisory = f.get("VendorAdvisory", {}).get(
                    "NoAdvisory", False
                )
                fix.fix_metadata = (
                    {"VendorAdvisorySummary": f["VendorAdvisory"]["AdvisorySummary"]}
                    if f.get("VendorAdvisory", {}).get("AdvisorySummary", [])
                    else None
                )

                db_rec.fixed_in.append(fix)

        #        if 'VulnerableIn' in vuln:
        #            for v in vuln['VulnerableIn']:
        #                v_in = VulnerableArtifact()
        #                v_in.name = v['Name']
        #                v_in.version = v['Version']
        #                v_in.version_format = v['VersionFormat']
        #                v_in.epochless_version = re.sub(r'^[0-9]*:', '', v['Version'])
        #                v_in.vulnerability_id = db_rec.id
        #                v_in.namespace_name = self.group
        #
        #                db_rec.vulnerable_in.append(v_in)

        return db_rec


class GithubFeedDataMapper(FeedDataMapper):
    """
    Maps a Github record into an GithubMetadata ORM object

    JSON Record is structured like::

        {'key': 'GHSA-73m2-3pwg-5fgc',
        'namespace': 'github:python',
        'payload': {'Vulnerability': {}, 'Advisory': advisory}

    And the Advisory itself::

        {'CVE': ['GHSA-73m2-3pwg-5fgc', 'CVE-2020-5236'],
         'FixedIn': [{'ecosystem': 'python',
                      'fixedin': None,
                      'identifier': '1.4.3',
                      'name': 'waitress'},
                     {'ecosystem': 'os',
                      'fixedin': None,
                      'identifier': None,
                      'name': 'waitress'}],
         'Metadata': {'CVE': ['GHSA-73m2-3pwg-5fgc', 'CVE-2020-5236']},
         'Severity': 'Critical',
         'Summary': 'Critical severity vulnerability that affects waitress',
         'url': 'https://github.com/advisories/GHSA-73m2-3pwg-5fgc',
         'withdrawn': None}

    """

    def map(self, record_json):
        advisory = record_json["Advisory"]

        db_rec = Vulnerability()
        db_rec.id = advisory["ghsaId"]
        db_rec.name = advisory["ghsaId"]
        db_rec.namespace_name = advisory["namespace"]
        db_rec.description = advisory["Summary"]
        db_rec.severity = advisory.get("Severity", "Unknown") or "Unknown"
        db_rec.link = advisory["url"]
        db_rec.metadata_json = advisory["Metadata"]
        references = [
            "https://nvd.nist.gov/vuln/detail/{}".format(i) for i in advisory["CVE"]
        ]
        db_rec.references = references

        # Set the `FixedArtifact` to an empty list so that a cascade deletion
        # gets rid of the associated fixes. If the advisory has been withdrawn,
        # this field will a string with a date.
        if advisory["withdrawn"] is not None:
            db_rec.fixed_in = []
            return db_rec

        for f in advisory["FixedIn"]:
            fix = FixedArtifact()
            fix.name = f["name"]
            # this is an unfortunate lie, 'version' has to be a range in order
            # to be processed correctly. If there is a real fix version, it
            # will be set in the `fix_metadata`.
            fix.version = f.get("range", "None")
            fix.version_format = "semver"
            fix.vulnerability_id = db_rec.id
            fix.namespace_name = f["namespace"]
            fix.vendor_no_advisory = False
            # the advisory summary is the same as db_rec.description, do we need to do this again?
            fix.fix_metadata = {"first_patched_version": f["identifier"]}

            db_rec.fixed_in.append(fix)

        return db_rec
