"""
Utilities for running tests for db, logging, etc.

"""
import datetime
import json
import os

from anchore_engine.services.policy_engine.engine.feeds import (
    IFeedSource,
    FeedGroupList,
    FeedList,
    GroupData,
)
from anchore_engine.db.entities.policy_engine import FeedMetadata
import logging as logger
from anchore_engine.common.schemas import FeedAPIGroupRecord, FeedAPIRecord
from anchore_engine.utils import ensure_bytes


class LocalFileExport(object):
    def __init__(self, img_id, json_path):
        self.img_id = img_id
        self.json_path = json_path


def init_distro_mappings():
    """
    Initializes the distro mappings, needed for lots of operation tests.
    :return:
    """

    from anchore_engine.db import session_scope, DistroMapping

    initial_mappings = [
        DistroMapping(from_distro="alpine", to_distro="alpine", flavor="ALPINE"),
        DistroMapping(from_distro="busybox", to_distro="busybox", flavor="BUSYB"),
        DistroMapping(from_distro="centos", to_distro="centos", flavor="RHEL"),
        DistroMapping(from_distro="debian", to_distro="debian", flavor="DEB"),
        DistroMapping(from_distro="fedora", to_distro="centos", flavor="RHEL"),
        DistroMapping(from_distro="ol", to_distro="ol", flavor="RHEL"),
        DistroMapping(from_distro="rhel", to_distro="centos", flavor="RHEL"),
        DistroMapping(from_distro="ubuntu", to_distro="ubuntu", flavor="DEB"),
    ]

    # set up any data necessary at system init
    try:
        with session_scope() as dbsession:
            distro_mappings = dbsession.query(DistroMapping).all()

            for i in initial_mappings:
                if not [x for x in distro_mappings if x.from_distro == i.from_distro]:
                    dbsession.add(i)
    except Exception as err:
        raise Exception(
            "unable to initialize default distro mappings - exception: " + str(err)
        )


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

    IMAGES_DIR = "images"
    FEEDS_DIR = "feeds"
    DB_DIR = "db"
    BUNDLES_DIR = "bundles"

    IMAGE_METADATA_FILENAME = "image_export_metadata.json"

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

        logger.info("Using local test data dir: {}".format(self.root_dir))

        if self.src:
            raise NotImplementedError("Load from tarball not yet implemented")

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
                b = json.load(fd, parse_int=str, parse_float=str)
            self.bundles[b["id"]] = b

    def image_exports(self):
        """
        Returns a list of id, filepath tuples
        :return:
        """
        return [
            (x, os.path.join(self.images_dir, self.image_map[x]["path"]))
            for x in list(self.image_map.keys())
        ]

    def init_feeds(self, up_to=None):
        if up_to:
            TimeWindowedLocalFilesytemFeedClient.limit_to_older_than(up_to)

    @property
    def feed_client(self):
        return TimeWindowedLocalFilesytemFeedClient(self.feeds_dir)

    def get_image_meta(self, img_id):
        return self.image_map.get(img_id)

    def get_images_named(self, name):
        return [x for x in list(self.image_map.items()) if x[1]["name"] == name]

    def set_max_feed_time(self, max_datetime):
        TimeWindowedLocalFilesytemFeedClient.limit_to_older_than(max_datetime)

    def list_available_bundles(self):
        raise NotImplementedError()

    def get_bundle(self, bundle_id):
        return self.bundles.get(bundle_id)

    def get_bundle_by_name(self, bundle_name):
        return [
            x
            for x in list(self.bundles.keys())
            if self.bundles[x]["name"] == bundle_name
        ]


class LocalFilesystemFeedClient(IFeedSource):
    """
    Client for a local fs of feeds with a base path where data is structured hierarchically and with ISO8601 formatted
    timestamps as filenames

    """

    def __init__(self, base_path):
        self.src_path = base_path
        self.feed_url = "file://" + self.src_path

    def list_feeds(self):
        feeds = []
        for d_name in os.listdir(self.src_path):
            feeds.append(
                FeedAPIRecord(
                    name=d_name,
                    access_tier=0,
                    description="A local feed found on local FS at: {}".format(
                        os.path.join(self.src_path, d_name)
                    ),
                )
            )
        logger.info("Returning local fs feeds: {}".format(feeds))
        return FeedList(feeds=feeds)

    def list_feed_groups(self, feed_name):
        assert feed_name
        groups = []
        feed_path = os.path.join(self.src_path, feed_name)
        for d_name in os.listdir(feed_path):
            groups.append(
                FeedAPIGroupRecord(
                    name=d_name,
                    access_tier=0,
                    description="A local feed group found on local FS at: {}".format(
                        os.path.join(feed_path, d_name)
                    ),
                )
            )
        logger.info(
            "Returning local fs feed groups for feed {}: {}".format(feed_name, groups)
        )
        return FeedGroupList(groups=groups)

    def get_feed_group_data(self, feed, group, since=None, next_token=None):
        assert feed and group

        if type(since) == datetime.datetime:
            since = since.isoformat()

        files = []
        group_path = os.path.join(self.src_path, feed, group)
        data = []

        for datafile_name in sorted(os.listdir(group_path)):
            if (since and datafile_name >= since) or not since:
                fpath = os.path.join(group_path, datafile_name)
                with open(fpath) as f:
                    content = json.load(f)
                    data += content
            else:
                continue

        return GroupData(
            data=data, next_token=None, since=since, record_count=len(data)
        )


class TimeWindowedLocalFilesytemFeedClient(LocalFilesystemFeedClient):
    """
    A local client that can limit the freshness of the data to allow incremental sync testing by
    explicitly moving the time boundary forward.

    """

    newest_allowed = None
    max_content_size = 5 * 1024 * 1024

    @classmethod
    def limit_to_older_than(cls, limit_datetime):
        cls.newest_allowed = limit_datetime

    def get_feed_group_data(self, feed, group, since=None, next_token=None):
        """
        Extended implementation of parent type function that includes a limit to how fresh of data is allowed. Will
        return all records between 'since' date and 'newest_allowed' date unless newest_allowed is None in which case there
        is no forward limit.

        :param feed:
        :param group:
        :param since:
        :param next_token:
        :return:
        """
        if type(since) == datetime.datetime:
            since = since.isoformat()

        group_path = os.path.join(self.src_path, feed, group)
        data = []

        back_boundary = since
        forward_boundary = (
            self.newest_allowed.isoformat() if self.newest_allowed else None
        )
        logger.debug(
            "Getting data for {}/{} with back boundary {} and forward boundary {}".format(
                feed, group, back_boundary, forward_boundary
            )
        )
        for datafile_name in sorted(os.listdir(group_path)):
            if (not back_boundary or (datafile_name >= back_boundary)) and (
                not forward_boundary
                or (forward_boundary and datafile_name <= forward_boundary)
            ):
                logger.debug("Using data file {}".format(datafile_name))
                fpath = os.path.join(group_path, datafile_name)
                with open(fpath) as f:
                    content = json.load(f)
                    if isinstance(content, dict):
                        data.extend(content["data"])
                    else:
                        data.extend(content)
            else:
                logger.debug(
                    "Data file {} outside of bounds, skipping".format(datafile_name)
                )
                continue

        # Make it look like a single chunk of data from the API (e.g. next_token and data keys
        data = {"data": data, "next_token": ""}
        outdata = ensure_bytes(json.dumps(data))

        return GroupData(
            data=outdata, next_token=None, since=since, record_count=len(data["data"])
        )


def reset_feed_sync_time(db, update_time, feed_name, feed_groups=None):
    """
    Given a db session, queries the feed metadata and sets the timestamps for last_sync on relevant groups and feed. Will only update the object, the
    caller is expected to handle merge/commit of the db session as needed.

    :param db:
    :param update_time:
    :param feed_name:
    :param feed_groups:
    :return:
    """
    feed = db.query(FeedMetadata).get(feed_name)
    feed.last_full_sync = update_time
    for g in feed.groups:
        if not feed_groups or g.name in feed_groups:
            g.last_sync = update_time
    return feed
