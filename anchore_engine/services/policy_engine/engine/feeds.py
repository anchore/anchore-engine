"""
Feeds manager system. Handles syncing and storing feed data locally for use by the policy engine.

Overall approach is to handle each feed individually with specific mapping code for the data types of each feed.
The reason for this is a more efficient (for query) data schema to support quick policy evaluations that require feed
data. Additionally, any new feed will require new code to be able to consume it in the policy eval system anyway, so
an update to the feed handling code is ok to be required as well.

"""
import json
import datetime
import re
import threading
import time
import traceback

from anchore_engine.db import get_thread_scoped_session as get_session
from anchore_engine.db import GenericFeedDataRecord, FeedMetadata, FeedGroupMetadata
from anchore_engine.db import FixedArtifact, Vulnerability, GemMetadata, NpmMetadata, NvdMetadata, CpeVulnerability
from anchore_engine.services.policy_engine.engine.logs import get_logger
from anchore_engine.clients.feeds.feed_service import get_client as get_feeds_client, InsufficientAccessTierError, InvalidCredentialsError
from anchore_engine.util.langpack import convert_langversionlist_to_semver

log = get_logger()

feed_list_cache = threading.local()


def get_feeds_config(full_config):
    """
    Returns the feeds-specifc portion of the global config. To centralized this logic.
    :param full_config:
    :return: dict that is the feeds configuration
    """
    return full_config.get('feeds',{})


def get_selected_feeds_to_sync(config):
    """
    Given a configuration dict, determine which feeds should be synced.

    :param config:
    :return: list of strings of feed names to sync, an empty least means no feeds. Response of None means selective sync is disabled and sync all feeds.
    """

    feed_config = get_feeds_config(config)
    if not feed_config:
        return []

    if feed_config.get('selective_sync', {}).get('enabled', False):
        return [x[0] for x in [x for x in list(feed_config.get('selective_sync', {}).get('feeds', {}).items()) if x[1]]]
    else:
        return None


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
        Map a single data feed record from msg to db format
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
        db_rec.id = int(data.get('id')) if data.get('id') else -1
        db_rec.authors_json = data.get('authors')
        db_rec.versions_json = data.get('versions')
        db_rec.licenses_json = data.get('licenses')
        db_rec.latest = data.get('latest')[:255] if data.get('latest') else None
        return db_rec


class NpmPackageDataMapper(KeyIDFeedDataMapper):
    """
    Maps a NPM package record to the db record
    """

    def map_inner(self, key, data):
        db_rec = NpmMetadata()
        db_rec.name = key[:255]
        db_rec.versions_json = data.get('versions')
        db_rec.latest = data.get('latest')[:255] if data.get('latest') else None
        db_rec.sourcepkg = data.get('sourcepkg')[:255] if data.get('sourcepkg') else None
        db_rec.origins_json = data.get('origins')
        db_rec.lics_json = data.get('lics')
        return db_rec


class NvdFeedDataMapper(FeedDataMapper):
    """
    Maps an NVD record into an NvdMetadata ORM object
    """
    def map(self, record_json):
        db_rec = NvdMetadata()
        db_rec.name = record_json['@id']
        db_rec.namespace_name = self.group
        db_rec.summary = record_json.get('summary', "")

        rawvc = record_json.get('vulnerable-configuration', {})
        db_rec.vulnerable_configuration = rawvc
        #db_rec.vulnerable_configuration = json.dumps(rawvc)

        rawvsw = record_json.get('vulnerable-software-list', {})
        db_rec.vulnerable_software = rawvsw
        #db_rec.vulnerable_software = json.dumps(rawvsw)

        rawcvss = record_json.get('cvss', {})
        db_rec.cvss = rawcvss
        #db_rec.cvss = json.dumps(rawcvss)

        sev = "Unknown"
        try:
            #cvss_json = json.loads(self.cvss)
            score = float(rawcvss['base_metrics']['score'])
            if score <= 3.9:
                sev = "Low"
            elif score <= 6.9:
                sev = "Medium"
            elif score <= 10.0:
                sev = "High"
            else:
                sev = "Unknown"
        except:
            sev = "Unknown"
        db_rec.severity = sev

        db_rec.vulnerable_cpes = []

        vswlist = []
        try:
            if isinstance(rawvsw['product'], list):
               vswlist = rawvsw['product']
            else:
                vswlist = [rawvsw['product']]
        except:
            pass

        # convert each vulnerable software list CPE into a DB record
        all_cpes = {}
        for vsw in vswlist:
            try:

                # tokenize the input CPE
                toks = vsw.split(":")
                final_cpe = ['cpe', '-', '-', '-', '-', '-', '-']
                for i in range(1, len(final_cpe)):
                    try:
                        if toks[i]:
                            final_cpe[i] = toks[i]
                        else:
                            final_cpe[i] = '-'
                    except:
                        final_cpe[i] = '-'

                if ':'.join(final_cpe) not in all_cpes:
                    all_cpes[':'.join(final_cpe)] = True
                    if final_cpe[1] == '/a':
                        newcpe = CpeVulnerability()
                        newcpe.feed_name = 'nvd'
                        newcpe.cpetype = final_cpe[1]
                        newcpe.vendor = final_cpe[2]
                        newcpe.name = final_cpe[3]
                        newcpe.version = final_cpe[4]
                        newcpe.update = final_cpe[5]
                        themeta = final_cpe[6]
                        if 'ruby' in final_cpe[6]:
                            themeta = '~~~ruby~~'
                        elif 'node.js' in final_cpe[6] or 'nodejs' in final_cpe[6]:
                            themeta = '~~~node.js~~'
                        elif 'python' in final_cpe[6]:
                            themeta = '~~~python~~'
                        newcpe.meta = themeta
                        newcpe.link = "https://nvd.nist.gov/vuln/detail/{}".format(db_rec.name)
                        db_rec.vulnerable_cpes.append(newcpe)

            except Exception as err:
                log.warn("failed to convert vulnerable-software-list into database CPE record - exception: " + str(err))

        return db_rec

class SnykFeedDataMapper(FeedDataMapper):
    """
    Maps a Snyk record into an Vulnerability ORM object
    """
    def map(self, record_json):
        if not record_json:
            return None

        # get the fundamental categories/ids
        id = list(record_json.keys()).pop()
        pkgvuln = record_json[id]
        (group_name, nslang) = self.group.split(":", 2)

        # create a new vulnerability record
        db_rec = Vulnerability()

        # primary keys
        db_rec.namespace_name = self.group
        db_rec.id = id

        # severity calculation
        db_rec.cvss2_score = pkgvuln.get('cvssScore')
        db_rec.cvss2_vectors = pkgvuln.get('cvssV3')
        db_rec.severity = db_rec.get_cvss_severity()

        # other metadata
        db_rec.link = pkgvuln.get('url')
        db_rec.description = ""
        db_rec.additional_metadata = pkgvuln

        # add fixed_in records
        semver_range = convert_langversionlist_to_semver(pkgvuln.get('vulnerableVersions', []), nslang)
        sem_versions = semver_range.split(' || ')
        for sem_version in sem_versions:
            v_in = FixedArtifact()
            v_in.name = pkgvuln.get("package")
            v_in.version = sem_version
            v_in.version_format = "semver" #"semver:{}".format(nslang)
            v_in.epochless_version = v_in.version
            v_in.vulnerability_id = db_rec.id
            v_in.namespace_name = db_rec.namespace_name
            v_in.fix_metadata = {'fix_exists': pkgvuln.get('upgradeable', False)}
            db_rec.fixed_in.append(v_in)

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
    defaults = {
        'Severity': 'Unknown',
        'Link': None,
        'Description': None
    }

    MAX_STR_LEN = 1024 * 64 - 4

    def map(self, record_json):
        if not record_json:
            return None

        # Handle a 'Vulnerability' wrapper around the specific record. If not present, assume a direct record
        if len(list(record_json.keys())) == 1 and record_json.get('Vulnerability'):
            vuln = record_json['Vulnerability']
        else:
            vuln = record_json

        db_rec = Vulnerability()
        db_rec.id = vuln['Name']
        db_rec.namespace_name = self.group
        db_rec.severity = vuln.get('Severity', 'Unknown')
        db_rec.link = vuln.get('Link')
        description = vuln.get("Description", "")
        if description:
            db_rec.description = vuln.get('Description','') if len(vuln.get('Description','')) < self.MAX_STR_LEN else (vuln.get('Description')[:self.MAX_STR_LEN - 8] + '...')
        else:
            db_rec.description = ""
        db_rec.fixed_in = []
        #db_rec.vulnerable_in = []

        #db_rec.metadata_json = json.dumps(vuln.get('Metadata')) if 'Metadata' in vuln else None
        db_rec.additional_metadata = vuln.get('Metadata', {})
        cvss_data = vuln.get('Metadata', {}).get('NVD', {}).get('CVSSv2')
        if cvss_data:
            db_rec.cvss2_vectors = cvss_data.get('Vectors')
            db_rec.cvss2_score = cvss_data.get('Score')

        # Process Fixes
        if 'FixedIn' in vuln:
            for f in vuln['FixedIn']:
                fix = FixedArtifact()
                fix.name = f['Name']
                fix.version = f['Version']
                fix.version_format = f['VersionFormat']
                fix.epochless_version = re.sub(r'^[0-9]*:', '', f['Version'])
                fix.vulnerability_id = db_rec.id
                fix.namespace_name = self.group
                fix.vendor_no_advisory = f.get('VendorAdvisory', {}).get('NoAdvisory', False)
                fix.fix_metadata = {'VendorAdvisorySummary': f['VendorAdvisory']['AdvisorySummary']} if f.get('VendorAdvisory', {}).get('AdvisorySummary', []) else None

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


class IFeedSource(object):
    """
    Base interface for a feed source
    """

    def list_feeds(self):
        raise NotImplementedError()

    def list_feed_groups(self, feed):
        raise NotImplementedError()

    def get_feed_group_data(self, feed, group, since=None):
        """
        Get data, optionally newer than a specific date. Returns *all* data, for a paged
        approach use the get_paged_feed_group_data function.

        :param feed: str feed name
        :param group: str group name
        :param since: datetime object indicating earliest date to fetch data from
        :return:
        """
        raise NotImplementedError()

    def get_paged_feed_group_data(self, feed, group, since=None, next_token=None):
        """
        Get a max_sized page of data using the continuation token.

        :param feed:
        :param group:
        :param since:
        :return:
        """
        raise NotImplementedError()


class AnchoreFeedServiceClient(IFeedSource):
    """
    Simple passthru to the Feeds client to consistently implement the interface
    
    """

    def __init__(self):
        """
        Initializes a default anchore.io service client, but can be overridden by the backing_client argument and will wrap that instead if provided
        :param backing_client:
        """
        self._client = None

    @property
    def client(self):
        if not self._client:
            self._client = get_feeds_client()
        return self._client

    def list_feed_groups(self, feed):
        resp = self.client.list_feed_groups(feed)
        groups = resp.groups
        return groups

    def list_feeds(self):
        feed_listing = self.client.list_feeds()
        return feed_listing.feeds

    def get_paged_feed_group_data(self, feed, group, since=None, next_token=None):
        # if type(since) == datetime.datetime:
        #     since = since.strftime(SINCE_DATE_FORMAT)

        if next_token:
            if since:
                resp = self.client.get_feed_group_data(feed, group, since=since, next_token=next_token)
            else:
                resp = self.client.get_feed_group_data(feed, group, next_token=next_token)
        else:
            if since:
                resp = self.client.get_feed_group_data(feed, group, since=since)
            else:
                resp = self.client.get_feed_group_data(feed, group)

        if next_token and resp.next_token and next_token == resp.next_token:
            raise Exception('Service returned same next token as requested, cannot proceed safely. Aborting fetch')

        log.debug('Got data len: {}, token: {}'.format(len(resp.data), resp.next_token))
        return resp.data, resp.next_token

    def get_feed_group_data(self, feed, group, since=None):
        # if type(since) == datetime.datetime:
        #     since = since.strftime(SINCE_DATE_FORMAT)

        next_token = None
        more_data = True
        data = []
        while more_data:
            log.debug('Fetching data, token = {}'.format(next_token))

            if next_token:
                if since:
                    resp = self.client.get_feed_group_data(feed, group, since=since, next_token=next_token)
                else:
                    resp = self.client.get_feed_group_data(feed, group, next_token=next_token)
            else:
                if since:
                    resp = self.client.get_feed_group_data(feed, group, since=since)
                else:
                    resp = self.client.get_feed_group_data(feed, group)

            data += resp.data
            if next_token and resp.next_token and next_token == resp.next_token:
                raise Exception('Service returned same next token as requested, cannot proceed safely. Aborting fetch')

            next_token = resp.next_token
            more_data = bool(next_token)
            log.debug('Got: {} records, token = {}'.format(len(resp.data), next_token))

        return data


class DataFeed(object):
    """
    Interface for a data feed. A DataFeed is a combination of a means to connect to the feed, metadata about the feed actions
    locally, and mapping data ingesting the feed data itself.
    
    """

    __source_cls__ = None #  A class definition that implements IFeedSource
    __feed_name__ = None
    __should_sync__ = None
    __group_data_mappers__ = None  # A dict/map of group names to mapper objects for translating group data into db types

    def __init__(self, metadata=None, src=None):
        """
        Instantiates any necessary clients and makes the feed ready to use
        :param metadata: an existing metadata record if available for bootstrapping
        :param src: an object to use as the feed source. if not provided then the class's __source_cls__ definition is used
        """

        self.source = self.__source_cls__() if not src else src
        self.metadata = metadata

    def sync(self, group=None, item_processing_fn=None, full_flush=False, flush_helper_fn=None):
        """
        Ensure the feed is synchronized. Performs checks per sync item and if item_processing_fn is provided.
        Transaction scope is the update for an entire group.

        item_processing_fn is exepected to be a function that can consume a db session but should *NOT* commit or rollback the session. The caller will handle that to properly maintain
        session scope to each item to be updated.

        :param group: the group name to update if only a single group update is required
        :param item_processign_fn: A function with first param the db session and second param the updated item, which is called on each updated item within the update transaction scope
        :param full_flush: Remove any old data from the feed and replace with new sync data
        :param flush_helper_fn: Function to invoke during each group's data flush process
        :return: list of updated records added to the database
        """
        raise NotImplementedError()

    def bulk_sync(self, group=None):
        """
        Similar to sync, but uses bulk operations and is therefore more prone to failure due to things like data conflicts.

        This is intended for large initial syncs or operations where conflicts and updates are less likely than a large
        volume of inserts.

        :param group: the group name to update if only one is desired. If not provided then all groups are updated
        :return: dict of group:record_count_inserted
        """
        raise NotImplementedError()


class AnchoreServiceFeed(DataFeed):
    """
    A data feed provided by the Anchore Feeds service.

    Metadata persisted in the backing db.
    Instance load will fire a load from the db to get the latest metadata in db, and sync
    operations will sync data and metadata from the upstream service.
    """

    __source_cls__ = AnchoreFeedServiceClient
    __group_data_mappers__ = GenericFeedDataMapper

    MAX_FEED_SYNC_PAGES = 4 # Number of pages of data (~5mb each) to process at a time during feed sync to keep memory usage reasonable

    def __init__(self, metadata=None, src=None):
        if not metadata:
            db = get_session()
            metadata = db.query(FeedMetadata).get(self.__feed_name__)

        super(AnchoreServiceFeed, self).__init__(metadata=metadata, src=src)

    def never_synced(self):
        """
        Returns true if this feed has never been successfully synced. Essentially checks the last_full_sync timestamp for existence.
        :return: boolean
        """
        is_not_synced = not self.metadata or not self.metadata.last_full_sync
        log.debug('Feed {} has never been synced? {}'.format(self.__feed_name__, is_not_synced))
        return is_not_synced

    def _sync_meta(self):
        """
        Ensure feed metadata is up-to-date in the db
        :return:
        """

        # Refresh data from the db if available
        session = get_session()

        if not self.metadata:
            meta_record = session.query(FeedMetadata).get(self.__feed_name__)
            if meta_record:
                self.metadata = meta_record

        my_feed = [x for x in self.source.list_feeds() if x.name == self.__feed_name__]
        if not my_feed:
            raise Exception('No feed with name {} found on feed source'.format(self.__feed_name__))
        else:
            my_feed = my_feed[0]

        if not self.metadata:
            self.metadata = FeedMetadata(name=my_feed.name, description=my_feed.description, access_tier=my_feed.access_tier)
            session.add(self.metadata)
        else:
            self.metadata.description = my_feed.description
            self.metadata.access_tier = my_feed.access_tier
            session.add(self.metadata)

    def record_count(self, group_name):
        raise NotImplementedError()

    def _get_data(self, group_name, since=None):
        """
        Returns a generator to iterate thru data returned by the source
        
        :param group_name: 
        :param since: 
        :return: 
        """

        if since:
            # if type(since) == datetime.datetime:
            #     since = since.strftime(SINCE_DATE_FORMAT)
            data = self.source.get_feed_group_data(self.__feed_name__, group_name, since=since)
        else:
            data = self.source.get_feed_group_data(self.__feed_name__, group_name)

        return data

    def _load_mapper(self, group_obj):
        """
        Find and instantiate the right mapper object for the given group.

        :param group_obj:
        :return:
        """
        if not hasattr(self.__class__.__group_data_mappers__, 'get'):
            mapper = self.__class__.__group_data_mappers__
        else:
            mapper = self.__class__.__group_data_mappers__.get(group_obj.name)

        if not mapper:
            raise Exception('No mapper class found for group: {}'.format(group_obj.name))

            # If it's a class, instantiate it
        if type(mapper) == type:
            mapper = mapper(self.__feed_name__, group_obj.name, keyname=None)

        return mapper


    # TODO: context manager for syncs to facilitate simple state management.
    # On enter, create record and state = 'running', on exit, set completion state and commit transaction
    # class SyncContext(object):
    #     def __init__(self, feed=None, group=None):
    #         log.debug('Beginning sync context')
    #         self.sync_record = None
    #         self.feed = feed
    #         self.group = group
    #         self.session = None
    #
    #     def __enter__(self):
    #         db = get_session()
    #         try:
    #             self.sync_record = SyncHistory(feed=self.feed, group=self.group)
    #             db.add(self.sync_record)
    #             db.commit()
    #         except:
    #             db.rollback()
    #             raise
    #
    #         self.session = get_session()
    #
    #     def __exit__(self, exc_type, exc_val, exc_tb):
    #         try:
    #             self.session.refresh(self.sync_record)
    #             if exc_val:
    #                 self.sync_record.state = 'failed'
    #             else:
    #                 self.sync_record.state = 'complete'
    #
    #             self.sync_record.terminated_at = datetime.datetime.utcnow()
    #             self.session.add(self.sync_record)
    #             self.session.commit()
    #         except:
    #             log.exception('Exception committing sync state, rolling back')
    #             self.session.rollback()
    #             raise
    #
    # def _dedup_data(self, new_data_items):
    #     return new_data_items

    def _dedup_data_key(self, item):
        """
        Return the key value to uniquely identify the item
        :param item:
        :return:
        """
        return item.__hash__()

    def _get_deduped_data(self, group_obj, since=None, next_token=None, max_pages=None):
        """
        Fetch data and deduplicate items in-line. Still requires buffering of entire data set in memory,
        but only the deduped data set, so usage is minimal.

        Returns mapped objects, not raw json dicts. Objects mapped using the class's defined mapper

        :param group_obj:
        :return:
        """
        mapper = self._load_mapper(group_obj)
        new_data = True
        pages = 0
        new_data_deduped = {}  # Dedup by item key
        while (new_data or next_token) and (max_pages is None or pages <= max_pages):
            new_data, next_token = self.source.get_paged_feed_group_data(self.__feed_name__, group_obj.name,
                                                                         since=since,
                                                                         next_token=next_token)
            pages += 1
            for x in new_data:
                mapped = mapper.map(x)
                if mapped:
                    new_data_deduped[self._dedup_data_key(mapped)] = mapped

            new_data = None
            log.debug('Page = {}, new_data = {}, next_token = {}'.format(pages, bool(new_data), bool(next_token), max_pages))

        data = list(new_data_deduped.values())
        new_data_deduped = None
        return data, next_token

    def _bulk_sync_group(self, group_obj):
        """
        Performs a bulk sync of a single group.

        :param group_obj:
        :return: number of records inserted
        """

        fetch_time = time.time()
        new_data_deduped, next_token = self._get_deduped_data(group_obj)
        fetch_time = time.time() - fetch_time
        log.info('Group data fetch took {} sec'.format(fetch_time))

        log.info('Adding {} records from group {}'.format(len(new_data_deduped), group_obj.name))
        db_time = time.time()
        db = get_session()
        try:
            for i in new_data_deduped:
                db.add(i)

            # Data complete, update the timestamp
            group_obj.last_sync = datetime.datetime.utcnow()
            db.add(group_obj)
            db.commit()
            return len(new_data_deduped)
        except Exception as e:
            log.exception('Error syncing group: {}'.format(group_obj))
            db.rollback()
            raise
        finally:
            db_time = time.time() - db_time
            log.info('Sync db time took {} sec'.format(db_time))

    def _sync_group(self, group_obj, full_flush=False):
        """
        Sync data from a single group and return the data. This operation is scoped to a transaction on the db.

        :param group_obj:
        :return:
        """
        sync_time = time.time()
        updated_images = set()
        db = get_session()
        if full_flush:
            last_sync = None
        else:
            last_sync = group_obj.last_sync

        try:
            next_token = ''
            while next_token is not None:
                if next_token == '':
                    next_token = None
                fetch_time = time.time()

                new_data_deduped, next_token = self._get_deduped_data(group_obj, since=last_sync, next_token=next_token, max_pages=self.MAX_FEED_SYNC_PAGES)
                fetch_time = time.time() - fetch_time
                log.info('Group data fetch took {} sec'.format(fetch_time))
                log.info('Merging {} records from group {}'.format(len(new_data_deduped), group_obj.name))
                db_time = time.time()
                for rec in new_data_deduped:
                    merged = db.merge(rec)
                    #db.add(merged)
                db.flush()
                log.info('Db merge took {} sec'.format(time.time() - db_time))

            group_obj.last_sync = datetime.datetime.utcnow()
            db.add(group_obj)
            db.commit()
        except Exception as e:
            log.exception('Error syncing group: {}'.format(group_obj))
            db.rollback()
            raise
        finally:
            sync_time = time.time() - sync_time
            log.info('Syncing group took {} sec'.format(sync_time))

        return updated_images

    def _flush_group(self, group_obj, flush_helper_fn=None):
        """
        Flush a specific data group. Do a db flush, but not a commit at the end to keep the transaction open.

        :param group_obj:
        :param flush_helper_fn:
        :return:
        """

        db = get_session()

        if flush_helper_fn:
            flush_helper_fn(db=db, feed_name=group_obj.feed_name, group_name=group_obj.name)

        db.query(GenericFeedDataRecord).delete()

    def bulk_sync(self, group=None):
        """
        Performs a bulk sync of one or all groups, which does not do any merges or assume any data is extant to conflict.
        Will also not perform any per-record updates to the rest of the system.

        This is intended as a function for use on the very first sync operation when no other data is yet in the system.

        :param group: str name of group to sync, if None then all groups are synced
        :return: map of group:record_count for insertions
        """

        self.init_feed_meta_and_groups()

        updated_records = {}

        # Each group update is a unique session and can roll itself back.
        for g in self.metadata.groups:
            log.info('Processing group for bulk sync: {}'.format(g.name))
            if not group or g.name == group:
                try:
                    inserted_count = self._bulk_sync_group(g)
                    updated_records[g.name] = inserted_count
                except Exception as e:
                    log.exception('Failed bulk syncing group data for {}/{}'.format(self.__feed_name__, g.name))
                    raise e
            else:
                log.info('Group not selected for bulk sync: {}. Skipping.'.format(g.name))

        self._update_last_sync_timestamp()
        return updated_records

    def _update_last_sync_timestamp(self, db=None, update_time=None):
        """
        Update the last sync timestamp with the current time or the time provided
        :return:
        """
        db_session = db if db else get_session()

        try:
            # Update timestamps
            self.metadata.last_update = update_time if update_time else datetime.datetime.utcnow()
            self.metadata.last_full_sync = self.metadata.last_update
            db_session.add(db_session.merge(self.metadata))

            # Only commit/rollback if no session was provided
            if not db:
                db_session.commit()
        except Exception as e:
            log.exception('Failed updating feed metadata timestamps.')
            # Don't modify session state if it was provided in call
            if not db:
                db_session.rollback()
            raise

    def init_feed_meta_and_groups(self):
        db = get_session()
        try:
            log.debug('Refreshing groups')
            self._sync_meta()
            self.refresh_groups()
            db.add(self.metadata)
            db.commit()
        except (InsufficientAccessTierError, InvalidCredentialsError):
            raise
        except Exception as e:
            db.rollback()
            raise

    def sync(self, group=None, item_processing_fn=None, full_flush=False, flush_helper_fn=None):
        """
        Sync data with the feed source. This may be *very* slow if there are lots of updates.

        Returns a dict with the following structure:
        {
        'group_name': [ record1, record2, ..., recordN],
        'group_name2': [ record1, record2, ...., recordM],
        ...
        }

        :param: group: The group to sync, optionally. If not specified, all groups are synced.
        :return: changed data updated in the sync as a list of records        
        """

        self.init_feed_meta_and_groups()

        updated_records = {}
        # Each group update is a unique session and can roll itself back.
        for g in self.metadata.groups:
            log.info('Processing group: {}'.format(g.name))
            if not group or g.name == group:
                if full_flush:
                    log.info('Performing group data flush prior to sync')
                    self._flush_group(g, flush_helper_fn)

                try:
                    new_data = self._sync_group(g, full_flush=full_flush)  # Each group sync is a transaction
                    updated_records[g.name] = new_data
                except Exception as e:
                    log.exception('Failed syncing group data for {}/{}'.format(self.__feed_name__, g.name))
            else:
                log.info('Skipping group {} since not selected'.format(g))

        db = get_session()
        try:
            # Update timestamps
            self.metadata.last_update = datetime.datetime.utcnow()
            self.metadata.last_full_sync = self.metadata.last_update
            db.add(db.merge(self.metadata))
            db.commit()
        except Exception as e:
            log.exception('Failed updating feed metadata timestamps.')
            db.rollback()
            raise

        return updated_records

    def group_by_name(self, group_name):
        return [x for x in self.metadata.groups if x.name == group_name] if self.metadata else []

    def refresh_groups(self):
        group_list = self.source.list_feed_groups(self.__feed_name__)

        for group in group_list:
            my_group = self.group_by_name(group.name)
            if not my_group:
                g = FeedGroupMetadata(name=group.name, description=group.description, access_tier=group.access_tier, feed=self.metadata)
                g.last_sync = None


class VulnerabilityFeed(AnchoreServiceFeed):
    """
    Vulnerabilities feed from anchore feed service backend. Unique in that the records are nested and have structure.
    Each vulnerability record maps to a set of records in the DB: one for the vulnerability and a set for each of the FixedIn and
    VulnerableIn collections that are optionally present for the vulnerability main record.

    """

    __feed_name__ = 'vulnerabilities'
    _cve_key = 'Name'
    __group_data_mappers__ = SingleTypeMapperFactory(__feed_name__, VulnerabilityFeedDataMapper, _cve_key)

    def query_by_key(self, key, group=None):
        if not group:
            raise ValueError('Group must be specified since it is part of the key for vulnerabilities')

        db = get_session()
        try:
            return db.query(Vulnerability).get((key, group))
        except Exception as e:
            log.exception('Could not retrieve vulnerability by key:')

    def query_data_since(self, since_datetime, group=None):
        db = get_session()
        try:
            if not group:
                return db.query(Vulnerability).filter(Vulnerability.updated_at >= since_datetime).all()
            else:
                return db.query(Vulnerability).filter(Vulnerability.updated_at >= since_datetime, Vulnerability.namespace_name == group).all()
        except Exception as e:
            log.exception('Could not retrieve vulnerability by key:')

    def _dedup_data_key(self, item):
        return item.id

    def _sync_group(self, group_obj, vulnerability_processing_fn=None, full_flush=False):
        """
        Sync data from a single group and return the data. The vulnerability_processing_fn callback is invoked for each item within the transaction scope.

        :param group_obj: the group object to sync
        :param bulk_load: should the load be done in bulk fashion, typically this is only for first run as it bypasses all per-item processing
        :return:
        """
        sync_time = time.time()
        updated_images = set() # A set
        db = get_session()

        if full_flush:
            last_sync = None
        else:
            last_sync = group_obj.last_sync

        try:
            next_token = ''
            while next_token is not None:
                if next_token == '':
                    next_token = None
                fetch_time = time.time()
                new_data_deduped, next_token = self._get_deduped_data(group_obj, since=last_sync, next_token=next_token, max_pages=self.MAX_FEED_SYNC_PAGES)
                fetch_time = time.time() - fetch_time
                log.debug('Group data fetch took {} sec'.format(fetch_time))
                log.debug('Merging {} records from group {}'.format(len(new_data_deduped), group_obj.name))
                db_time = time.time()
                for rec in new_data_deduped:
                    # Make any updates and changes within this single transaction scope
                    updated_image_ids = self.update_vulnerability(db, rec, vulnerability_processing_fn=vulnerability_processing_fn)
                    updated_images = updated_images.union(set(updated_image_ids))  # Record after commit to ensure in-sync.
                    db.flush()
                log.debug('Db merge took {} sec'.format(time.time() - db_time))

            group_obj.last_sync = datetime.datetime.utcnow()
            db.add(group_obj)
            db.commit()
        except Exception as e:
            log.exception('Error syncing group: {}'.format(group_obj))
            db.rollback()
            raise
        finally:
            sync_time = time.time() - sync_time
            log.info('Syncing group took {} sec'.format(sync_time))

        return updated_images

    @staticmethod
    def _are_match_equivalent(vulnerability_a, vulnerability_b):
        """
        Returns true if the two records (including child fixedin and/or vulnerablein records) are equivalent in terms of package matching.

        TODO: move this logic to an vuln-scan abstraction, but that abstraction needs more work before it's ready. Would like to keep the definition of what impacts matches centralized so as not to get out-of-sync.

        :param vulnerability_a:
        :param vulnerability_b:
        :return:
        """

        if not (vulnerability_a and vulnerability_b) or vulnerability_a.id != vulnerability_b.id or vulnerability_a.namespace_name != vulnerability_b.namespace_name:
            # They aren't the same item reference
            log.debug('Vuln id or namespaces are different: {} {} {} {}'.format(vulnerability_a.id, vulnerability_b.id, vulnerability_a.namespace_name, vulnerability_b.namespace_name))
            return False

        normalized_fixes_a = {(fix.name, fix.epochless_version, fix.version) for fix in vulnerability_a.fixed_in}
        normalized_fixes_b = {(fix.name, fix.epochless_version, fix.version) for fix in vulnerability_b.fixed_in}

        fix_diff = normalized_fixes_a.symmetric_difference(normalized_fixes_b)
        if fix_diff:
            log.debug('Fixed In records diff: {}'.format(fix_diff))
            return False

        #normalized_vulnin_a = {(vuln.name, vuln.epochless_version, vuln.version) for vuln in vulnerability_a.vulnerable_in}
        #normalized_vulnin_b = {(vuln.name, vuln.epochless_version, vuln.version) for vuln in vulnerability_b.vulnerable_in}

        #vulnin_diff = normalized_vulnin_a.symmetric_difference(normalized_vulnin_b)

        #if vulnin_diff:
        #    log.debug('VulnIn records diff: {}'.format(vulnin_diff))
        #    return False

        return True

    def update_vulnerability(self, db, vulnerability_record, vulnerability_processing_fn=None):
        """
        Processes a single vulnerability record. Specifically for vulnerabilities:
        Checks and updates any fixed-in or vulnerable-in records and given the final state of the vulneraability,
        calls the item_callback function which is expected to do things like: update image vulnerability lists based
        on the new item.

        :param vulnerability_record: the record from the feed source to process and load into the db.
        :param vulnerability_processing_fn: a callback function to execute with the new date, but before any transaction commit
        :return:
        """
        try:
            updates = []

            try:
                existing = db.query(Vulnerability).filter(Vulnerability.id == vulnerability_record.id, Vulnerability.namespace_name == vulnerability_record.namespace_name).one_or_none()
            except:
                log.debug('No current record found for {}'.format(vulnerability_record))
                existing = None

            if existing:
                needs_update = not VulnerabilityFeed._are_match_equivalent(existing, vulnerability_record)
                if needs_update:
                    log.debug('Found update that requires an image match update from {} to {}'.format(existing, vulnerability_record))
            else:
                needs_update = True

            merged = db.merge(vulnerability_record)

            if vulnerability_processing_fn and needs_update:
                updates = vulnerability_processing_fn(db, merged)
            else:
                log.debug('Skipping image processing due to no diff: {}'.format(merged))

            return updates
        except Exception as e:
            log.exception('Error in vulnerability processing')
            raise e

    def _flush_group(self, group_obj, flush_helper_fn=None):
        db = get_session()
        flush_helper_fn(db=db, feed_name=group_obj.feed_name, group_name=group_obj.name)

        count = db.query(FixedArtifact).filter(FixedArtifact.namespace_name == group_obj.name).delete()
        log.info('Flushed {} fix records'.format(count))
        #count = db.query(VulnerableArtifact).filter(VulnerableArtifact.namespace_name == group_obj.name).delete()
        #log.info('Flushed {} vuln_in records'.format(count))
        count = db.query(Vulnerability).filter(Vulnerability.namespace_name == group_obj.name).delete()
        log.info('Flushed {} vulnerability records'.format(count))

        db.flush()

    def sync(self, group=None, item_processing_fn=None, full_flush=False, flush_helper_fn=None):
        """
        Sync data with the feed source. This may be *very* slow if there are lots of updates.

        Returns a dict with the following structure:
        {
        'group_name': [ record1, record2, ..., recordN],
        'group_name2': [ record1, record2, ...., recordM],
        ...
        }

        :param: group: The group to sync, optionally. If not specified, all groups are synced.
        :return: changed data updated in the sync as a list of records
        """

        self.init_feed_meta_and_groups()

        updated_records = {}

        # Setup the group name cache
        feed_list_cache.vuln_group_list = [x.name for x in self.metadata.groups]
        try:
            # Each group update is a unique session and can roll itself back.
            for g in self.metadata.groups:
                log.info('Processing group: {}'.format(g.name))
                if not group or g.name == group:
                    if full_flush:
                        log.info('Performing group data flush prior to sync')
                        self._flush_group(g, flush_helper_fn)

                    try:
                        new_data = self._sync_group(g, vulnerability_processing_fn=item_processing_fn, full_flush=full_flush)
                        updated_records[g.name] = new_data
                    except Exception as e:
                        log.exception('Failed syncing group data for {}/{}'.format(self.__feed_name__, g.name))
                else:
                    log.info('Group not selected for sync: {}. Skipping.'.format(g.name))

            self._update_last_sync_timestamp()
            return updated_records
        finally:
            feed_list_cache.vuln_group_list = None


    @staticmethod
    def cached_group_name_lookup(name):
        return name in feed_list_cache.vuln_group_list if feed_list_cache and hasattr(feed_list_cache, 'vuln_group_list') else False

    def record_count(self, group_name):
        db = get_session()
        try:
            return db.query(Vulnerability).filter(Vulnerability.namespace_name == group_name).count()
        except Exception as e:
            log.exception('Error getting feed data group record count in package feed for group: {}'.format(group_name))
            raise
        finally:
            db.rollback()


class PackagesFeed(AnchoreServiceFeed):
    """
    Feed for package data, served from the anchore feed service backend
    """

    __feed_name__ = 'packages'

    __group_data_mappers__ = {
        'gem': GemPackageDataMapper,
        'npm': NpmPackageDataMapper
    }

    def query_by_key(self, key, group=None):
        if not group:
            raise ValueError('Group must be specified since it is part of the key for vulnerabilities')

        db = get_session()
        if group == 'gem':
            try:
                return db.query(GemMetadata).get(key)
            except Exception as e:
                log.exception('Could not retrieve vulnerability by key:')
                raise
        elif group == 'npm':
            try:
                return db.query(NpmMetadata).get(key)
            except Exception as e:
                log.exception('Could not retrieve vulnerability by key:')
                raise
        else:
            return None

    def _dedup_data_key(self, item):
        return item.name

    def record_count(self, group_name):
        db = get_session()
        try:
            if group_name == 'npm':
                return db.query(NpmMetadata).count()
            elif group_name == 'gem':
                return db.query(GemMetadata).count()
            else:
                return 0
        except Exception as e:
            log.exception('Error getting feed data group record count in package feed for group: {}'.format(group_name))
            raise
        finally:
            db.rollback()


class NvdFeed(AnchoreServiceFeed):
    """
    Feed for package data, served from the anchore feed service backend
    """

    __feed_name__ = 'nvd'
    _cve_key = '@id'
    __group_data_mappers__ = SingleTypeMapperFactory(__feed_name__, NvdFeedDataMapper, _cve_key)

    def query_by_key(self, key, group=None):
        if not group:
            raise ValueError('Group must be specified since it is part of the key for vulnerabilities')

        db = get_session()
        try:
            return db.query(NvdMetadata).get((key, group))
        except Exception as e:
            log.exception('Could not retrieve nvd vulnerability by key:')

    def _dedup_data_key(self, item):
        return item.name

    def record_count(self, group_name):
        db = get_session()
        try:
            if 'nvddb' in group_name:
                return db.query(NvdMetadata).filter(NvdMetadata.namespace_name == group_name).count()
            else:
                return 0
        except Exception as e:
            log.exception('Error getting feed data group record count in package feed for group: {}'.format(group_name))
            raise
        finally:
            db.rollback()

#class SnykFeed(AnchoreServiceFeed):
class SnykFeed(VulnerabilityFeed):
    """
    Feed for package data, served from the anchore feed service backend
    """

    __feed_name__ = 'snyk'
    _cve_key = 'id'
    __group_data_mappers__ = SingleTypeMapperFactory(__feed_name__, SnykFeedDataMapper, _cve_key)

#    def query_by_key(self, key, group=None):
#        if not group:
#            raise ValueError('Group must be specified since it is part of the key for vulnerabilities')
#        db = get_session()
#        try:
#            return db.query(Vulnerability).get((key, group))
#        except Exception as e:
#            log.exception('Could not retrieve snyk vulnerability by key:')

#    def _dedup_data_key(self, item):
#        return item.id

    def record_count(self, group_name):
        db = get_session()
        try:
            if 'snyk' in group_name:
                return db.query(Vulnerability).filter(Vulnerability.namespace_name == group_name).count()
            else:
                return 0
        except Exception as e:
            log.exception('Error getting feed data group record count in package feed for group: {}'.format(group_name))
            raise
        finally:
            db.rollback()


class FeedFactory(object):
    """
    Factory class for creating feed objects. Not necessary yet because we don't have any dynamically updated feeds such that we
    don't exactly know the set of feeds nor do the group types change unexpectedly.

    """
    override_mapping = {
        'vulnerabilities': VulnerabilityFeed,
        'packages': PackagesFeed,
        'nvd': NvdFeed,
        'snyk': SnykFeed,
    }

    default_mapping = AnchoreServiceFeed

    @classmethod
    def create(cls, feed_msg, src):
        """
        Creates a new feed record and object from the received json
        :param feed_json:
        :return: DataFeed object
        """
        record = FeedMetadata(name=feed_msg.name, description=feed_msg.description, access_tier=feed_msg.access_tier)
        obj = cls.get(record.name, record, src)
        return obj

    @classmethod
    def get(cls, name, record, src):
        """
        Returns a feed instance for the given feed name based on mappings. If a specific mapping is found,
        it is used, else the generic feed object is used.

        :param name: name of the feed, should be unique across sources
        :return:
        """
        try:
            clazz = cls.override_mapping.get(name)
            if clazz:
                return clazz(record, src=src)
            else:
                return cls.default_mapping(record, src=src)

        except KeyError:
            feed_obj = AnchoreServiceFeed(record, src=src)


class DataFeeds(object):
    _proxy = None
    _vulnerabilitiesFeed_cls = VulnerabilityFeed
    _packagesFeed_cls = PackagesFeed
    _nvdsFeed_cls = NvdFeed
    _snyksFeed_cls = SnykFeed

    def __init__(self):
        self.vuln_fn = None
        self.vuln_flush_fn = None

    @classmethod
    def instance(cls):
        if not cls._proxy:
            cls._proxy = DataFeeds()
        return cls._proxy

    def list_metadata(self):
        """
        Returns a list of FeedMetadata objects populated with FeedGroupMetadata objects as returned by the db, but detached from the session.

        :return: list of FeedMetadata objects
        """
        db = get_session()
        try:
            feeds = db.query(FeedMetadata).all()
            response = []
            for f in feeds:
                t = f.to_detached()
                t.groups = [g.to_detached() for g in f.groups]
                response.append(t)

            return response
        except Exception as e:
            log.exception('Could not get feed metadata')
            raise e
        finally:
            db.rollback()

    def records_for(self, feed_name, group_name):
        if feed_name == 'vulnerabilities':
            return self.vulnerabilities.record_count(group_name)
        elif feed_name == 'packages':
            return self.packages.record_count(group_name)
        elif feed_name == 'nvd':
            return self.nvd.record_count(group_name)
        elif feed_name == 'snyk':
            return self.snyk.record_count(group_name)
        else:
            return 0

    def refresh(self):
        """
        Refresh listing of feeds. This is basically a no-op for now until we have dynamic feed schema detection since by
        design we only want to sync feeds we know about and have a data format for and those are enumerated.

        This function does verify that the expected feeds are available for a sync.
        :return: True on success, raise exception on failure to find a feed
        """

        try:
            self.vulnerabilities.refresh_groups()
        except (InsufficientAccessTierError, InvalidCredentialsError) as e:
            log.error('Cannot update group metadata for vulnerabilities feed due to insufficient access or invalid credentials: {}'.format(e.message))

        try:
            self.packages.refresh_groups()
        except (InsufficientAccessTierError, InvalidCredentialsError) as e:
            log.error('Cannot update group metadata for packages feed due to insufficient access or invalid credentials: {}'.format(e.message))

        try:
            self.nvd.refresh_groups()
        except (InsufficientAccessTierError, InvalidCredentialsError) as e:
            log.error('Cannot update group metadata for Nvd feed due to insufficient access or invalid credentials: {}'.format(e.message))

        try:
            self.snyk.refresh_groups()
        except (InsufficientAccessTierError, InvalidCredentialsError) as e:
            log.error('Cannot update group metadata for snyk feed due to insufficient access or invalid credentials: {}'.format(e.message))


    def sync(self, to_sync=None, full_flush=False):
        """
        Sync all feeds.
        :return:
        """

        all_success = True

        updated_records = {}
        log.info('Performing feed sync of feeds: {}'.format('all' if to_sync is None else to_sync))

        # Initialize the feed metadata and groups first

        vuln_feed = None
        if to_sync is None or 'vulnerabilities' in to_sync:
            try:
                log.info('Syncing group metadata for vulnerabilities feed')
                vuln_feed = self.vulnerabilities
                vuln_feed.init_feed_meta_and_groups()
            except:
                log.exception('Cannot sync group metadata for vulnerabilities feed')
                vuln_feed = None

        pkgs_feed = None
        if to_sync is None or 'packages' in to_sync:
            try:
                log.info('Syncing group metadata for packages feed')
                pkgs_feed = self.packages
                pkgs_feed.init_feed_meta_and_groups()
            except:
                log.exception('Cannot sync group metadata for packages feed')
                pkgs_feed = None

        nvd_feed = None
        if to_sync is None or 'nvd' in to_sync:
            try:
                log.info('Syncing group metadata for nvd feed')
                nvd_feed = self.nvd
                nvd_feed.init_feed_meta_and_groups()
            except:
                log.exception('Cannot sync group metadata for nvd feed')
                nvd_feed = None

        snyk_feed = None
        if to_sync is None or 'snyk' in to_sync:
            try:
                log.info('Syncing group metadata for snyk feed')
                snyk_feed = self.snyk
                snyk_feed.init_feed_meta_and_groups()
            except:
                log.warn('Cannot sync group metadata for snyk feed, may not be available in the feed source')
                log.debug(traceback.format_exc())
                snyk_feed = None

        # Perform the feed sync next

        if vuln_feed:
            try:
                log.info('Syncing vulnerability feed')
                updated_records['vulnerabilities'] = vuln_feed.sync(item_processing_fn=self.vuln_fn, full_flush=full_flush, flush_helper_fn=self.vuln_flush_fn)
            except:
                log.exception('Failure updating the vulnerabilities feed')
                all_success = False

        if pkgs_feed:
            try:
                log.info('Syncing packages feed')
                updated_records['packages'] = pkgs_feed.sync()
            except:
                log.exception('Failure updating the packages feed')
                all_success = False

        if nvd_feed:
            try:
                log.info('Syncing nvd feed')
                updated_records['nvd'] = nvd_feed.sync()
            except:
                log.exception('Failure updating the nvd feed')
                all_success = False

        if snyk_feed:
            try:
                log.info('Syncing snyk feed')
                updated_records['snyk'] = snyk_feed.sync(item_processing_fn=self.vuln_fn, full_flush=full_flush, flush_helper_fn=self.vuln_flush_fn)
            except:
                log.exception('Failure updating the snyk feed')
                all_success = False

        if not all_success:
            raise Exception("one or more feeds failed to sync")

        return updated_records

    def bulk_sync(self, to_sync=None, only_if_unsynced=True):
        """
        Sync all feeds using a bulk sync for each for performance, particularly on initial sync.
        :param to_sync: list of feed names to sync, if None all feeds are synced
        :return:
        """

        all_success = True

        updated_records = {}

        if to_sync is None or 'vulnerabilities' in to_sync:
            if not only_if_unsynced or self.vulnerabilities.never_synced():
                log.info('Bulk syncing vulnerability feed')
                try:
                    updated_records['vulnerabilities'] = self.vulnerabilities.bulk_sync()
                except Exception as err:
                    log.exception('Failure updating the vulnerabilities feed. Continuing with next feed')
                    all_success = False

            else:
                log.info('Skipping bulk sync since feed already initialized')

        if to_sync is None or 'packages' in to_sync:
            if not only_if_unsynced or self.packages.never_synced():
                try:
                    log.info('Syncing packages feed')
                    updated_records['packages'] = self.packages.bulk_sync()
                except Exception as err:
                    log.exception('Failure updating the packages feed. Continuing with next feed')
                    all_success = False

            else:
                log.info('Skipping bulk sync since feed already initialized')

        if to_sync is None or 'nvd' in to_sync:
            if not only_if_unsynced or self.nvd.never_synced():
                try:
                    log.info('Syncing nvd feed')
                    updated_records['nvd'] = self.nvd.bulk_sync()
                except Exception as err:
                    log.exception('Failure updating the nvd feed. Continuing with next feed')
                    all_success = False

            else:
                log.info('Skipping bulk sync since feed already initialized')

        if to_sync is None or 'snyk' in to_sync:
            if not only_if_unsynced or self.snyk.never_synced():
                try:
                    log.info('Syncing snyk feed')
                    updated_records['snyk'] = self.snyk.bulk_sync()
                except Exception as err:
                    log.exception('Failure updating the snyk feed. Continuing with next feed')
                    all_success = False

            else:
                log.info('Skipping bulk sync since feed already initialized')


        if not all_success:
            raise Exception("one or more feeds failed to sync")

        return updated_records

    @property
    def vulnerabilities(self):
        return self._vulnerabilitiesFeed_cls()

    @property
    def packages(self):
        return self._packagesFeed_cls()

    @property
    def nvd(self):
        return self._nvdsFeed_cls()

    @property
    def snyk(self):
        return self._snyksFeed_cls()
