"""
Utilities for running tests for db, logging, etc.

"""
import datetime
import json
import os


from anchore_engine.services.policy_engine.engine.feeds import DataFeeds
from legacy_test.services.policy_engine.feeds import TimeWindowedLocalFilesytemFeedClient, LocalPackagesFeed, \
    LocalVulnerabilityFeed


class LocalFileExport(object):
    def __init__(self, img_id, json_path):
        self.img_id = img_id
        self.json_path = json_path


def setup_engine_config(db_connect_str):
    """
    Sets the config for the service to bootstrap a specific db.
    :param db_connect_str:
    :return:
    """
    from anchore_engine.configuration import localconfig
    localconfig.load_defaults()
    localconfig.localconfig['credentials'] = {
        'database': {
            'db_connect': db_connect_str
        }
    }
    return localconfig.localconfig


def get_policy_tables():
    """
    Get a list of table names for the policy service to allow db bootstrap of only those tables.
    :return: list of string table names
    """
    import inspect
    from anchore_engine.db.entities import policy_engine
    from anchore_engine.db.entities.common import Base

    entity_names = [x[1].__tablename__ for x in [x for x in inspect.getmembers(policy_engine) if inspect.isclass(x[1]) and issubclass(x[1], Base) and x[1] != Base]]
    tables = [x for x in Base.metadata.sorted_tables if x.name in entity_names]

    return tables


def init_distro_mappings():
    """
    Initializes the distro mappings, needed for lots of operation tests.
    :return:
    """

    from anchore_engine.db import session_scope, DistroMapping

    initial_mappings = [
        DistroMapping(from_distro='alpine', to_distro='alpine', flavor='ALPINE'),
        DistroMapping(from_distro='busybox', to_distro='busybox', flavor='BUSYB'),
        DistroMapping(from_distro='centos', to_distro='centos', flavor='RHEL'),
        DistroMapping(from_distro='debian', to_distro='debian', flavor='DEB'),
        DistroMapping(from_distro='fedora', to_distro='centos', flavor='RHEL'),
        DistroMapping(from_distro='ol', to_distro='ol', flavor='RHEL'),
        DistroMapping(from_distro='rhel', to_distro='centos', flavor='RHEL'),
        DistroMapping(from_distro='ubuntu', to_distro='ubuntu', flavor='DEB')
    ]

    # set up any data necessary at system init
    try:
        with session_scope() as dbsession:
            distro_mappings = dbsession.query(DistroMapping).all()

            for i in initial_mappings:
                if not [x for x in distro_mappings if x.from_distro == i.from_distro]:
                    dbsession.add(i)
    except Exception as err:
        raise Exception("unable to initialize default distro mappings - exception: " + str(err))


def init_db(connect_str='sqlite:///:memory:', do_bootstrap=False):
    """
    Policy-Engine specific db initialization and setup for testing.

    :param connect_str: connection string, defaults to sqllite in-memory if none provided
    :return:
    """
    conf = setup_engine_config(connect_str)
    from anchore_engine.db import initialize
    from anchore_engine.db.entities.common import do_create
    pol_tables = get_policy_tables()
    initialize(localconfig=conf)
    if do_bootstrap:
        do_create(pol_tables)

    init_distro_mappings()


class LocalTestDataEnvironment(object):
    """
    A local environment for testing data.
    Includes image exports, feeds data, and temp dir for sqlite db.

    The environment is a filesystem location with data in specific paths. Expected to be organized like:
    {data_dir}/images - directory containing image analysis json files as output by the anchore tool export functionality
    {data_dir}/feeds - directory containing a local copy of the feeds data in a hierarchical structure
    {data_dir}/feeds/<feed>/<group>/ - a group data directory containing ISO-8601 timestamp format-named json files that are feed data.
    e.g. {data_dir}/feeds/vulnerabilities/centos:6/2017-05-03T17:37:08.959123.json

    {data_dir}/db - directory containing sqlite database(s). Default is to look for sqlite.db file.
    {data_dir}/bundles - directory containg json files that are bundles to use for testing


    """
    IMAGES_DIR = 'images'
    FEEDS_DIR = 'feeds'
    DB_DIR = 'db'
    BUNDLES_DIR = 'bundles'

    IMAGE_METADATA_FILENAME = 'image_export_metadata.json'
    # Metadata file that contains a single object with image_id as key and each value an object with:
    # name - str, file - str
    # Exampe:
    # {
    #     '123': {'name': 'node', 'file': 'nodejs.export.json'},
    #     '456': {'name': 'nginx', 'file': 'nginx.export.json'}
    # }


    def __init__(self, data_dir=None, load_from_file=None):
        self.root_dir = data_dir if data_dir else os.curdir
        self.src = load_from_file

        if self.src:
            raise NotImplementedError('Load from tarball not yet implemented')

        self.images_dir = os.path.join(self.root_dir, self.IMAGES_DIR)
        self.feeds_dir = os.path.join(self.root_dir, self.FEEDS_DIR)
        self.db_dir = os.path.join(self.root_dir, self.DB_DIR)
        self.bundle_dir = os.path.join(self.root_dir, self.BUNDLES_DIR)
        self.img_meta_path = os.path.join(self.images_dir, self.IMAGE_METADATA_FILENAME)

        with open(self.img_meta_path) as f:
            self.image_map = json.load(f)

        self.bundles = {}
        for f in os.listdir(self.bundle_dir):
            with open(os.path.join(self.bundle_dir, f)) as fd:
                b = json.load(fd ,parse_int=str, parse_float=str)
            self.bundles[b['id']] = b


    def image_exports(self):
        """
        Returns a list of id, filepath tuples
        :return:
        """
        return [(x, os.path.join(self.images_dir, self.image_map[x]['path'])) for x in list(self.image_map.keys())]

    def init_feeds(self, up_to=None):
        LocalPackagesFeed.__source_cls__ = TimeWindowedLocalFilesytemFeedClient
        LocalPackagesFeed.__data_path__ = self.feeds_dir
        LocalVulnerabilityFeed.__source_cls__ = TimeWindowedLocalFilesytemFeedClient
        LocalVulnerabilityFeed.__data_path__ = self.feeds_dir

        if up_to:
            LocalPackagesFeed.__source_cls__.limit_to_older_than(up_to)
            LocalVulnerabilityFeed.__source_cls__.limit_to_older_than(up_to)

        DataFeeds._vulnerabilitiesFeed_cls = LocalVulnerabilityFeed
        DataFeeds._packagesFeed_cls = LocalPackagesFeed

    def get_image_meta(self, img_id):
        return self.image_map.get(img_id)

    def get_images_named(self, name):
        return [x for x in list(self.image_map.items()) if x[1]['name'] == name]

    def set_max_feed_time(self, max_datetime):
        LocalPackagesFeed.__source_cls__.limit_to_older_than(max_datetime)
        LocalVulnerabilityFeed.__source_cls__.limit_to_older_than(max_datetime)

    def mk_db(self, generate=False):
        if generate:
            return 'sqlite:///' + os.path.join(self.db_dir, datetime.datetime.utcnow().isoformat() + '.sqlite.db')
        else:
            return 'sqlite:///' + os.path.join(self.db_dir, 'sqlite.db')

    def list_available_bundles(self):
        raise NotImplementedError()

    def get_bundle(self, bundle_id):
        return self.bundles.get(bundle_id)

    def get_bundle_by_name(self, bundle_name):
        return [x for x in list(self.bundles.keys()) if self.bundles[x]['name'] == bundle_name]