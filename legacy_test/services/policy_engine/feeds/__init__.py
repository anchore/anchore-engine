import os
import datetime
import json
import logging
from collections import namedtuple

from anchore_engine.services.policy_engine.engine.feeds import PackagesFeed, VulnerabilityFeed, IFeedSource, FeedMetadata, FeedGroupMetadata

log = logging.getLogger()
log.setLevel(logging.DEBUG)


class LocalFilesystemFeedClient(IFeedSource):
    """
    Client for a local fs of feeds with a base path where data is layed out heirarchicaly and with ISO8601 formatted
    timestamps as filenames

    """
    Feed = namedtuple('LocalFeed', ['name', 'access_tier', 'description'])
    FeedGroup = namedtuple('LocalFeedGroup', ['name', 'access_tier', 'description'])

    def __init__(self, base_path):
        self.src_path = base_path

    def list_feeds(self):
        feeds = []
        for d_name in os.listdir(self.src_path):
            feeds.append(LocalFilesystemFeedClient.Feed(name=d_name, access_tier=0,
                                                        description='A local feed found on local FS at: {}'.format(
                                                            os.path.join(self.src_path, d_name))))
        return feeds

    def list_feed_groups(self, feed_name):
        groups = []
        feed_path = os.path.join(self.src_path, feed_name)
        for d_name in os.listdir(feed_path):
            groups.append(LocalFilesystemFeedClient.FeedGroup(name=d_name, access_tier=0,
                                                              description='A local feed group found on local FS at: {}'.format(
                                                                  os.path.join(feed_path, d_name))))

        return groups

    def get_feed_group_data(self, feed, group, since=None):
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

        return data


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

    def get_paged_feed_group_data(self, feed, group, since=None, next_token=None):
        if type(since) == datetime.datetime:
            since = since.isoformat()

        files = []
        group_path = os.path.join(self.src_path, feed, group)
        if next_token:
            next_token = next_token.decode('base64')
        data = []
        size = 0
        token = None

        back_boundary = since
        forward_boundary = self.newest_allowed.isoformat() if self.newest_allowed else None
        log.debug(
            'Getting data for {}/{} with back boundary {} and forward boundary {}'.format(feed, group, back_boundary,
                                                                                          forward_boundary))
        for datafile_name in sorted(os.listdir(group_path)):
            if (not back_boundary or (datafile_name >= back_boundary)) and (
                not forward_boundary or (forward_boundary and datafile_name <= forward_boundary)) and (datafile_name >= next_token or not next_token):
                log.debug('Using data file {}'.format(datafile_name))
                fpath = os.path.join(group_path, datafile_name)
                s = os.stat(fpath)
                if size + s.st_size > self.max_content_size:
                    token = datafile_name
                    break
                else:
                    size += s.st_size
                    with open(fpath) as f:
                            content = json.load(f)
                            data += content
            else:
                log.debug('Data file {} outside of bounds, skipping'.format(datafile_name))
                continue

        return data, token.encode('base64') if token else None

    def get_feed_group_data(self, feed, group, since=None):
        """
        Extended implementation of parent type function that includes a limit to how fresh of data is allowed. Will
        return all records between 'since' date and 'newest_allowed' date unless newest_allowed is None in which case there
        is no forward limit.

        :param feed:
        :param group:
        :param since:
        :return:
        """
        if type(since) == datetime.datetime:
            since = since.isoformat()

        files = []
        group_path = os.path.join(self.src_path, feed, group)
        data = []

        back_boundary = since
        forward_boundary = self.newest_allowed.isoformat() if self.newest_allowed else None
        log.debug('Getting data for {}/{} with back boundary {} and forward boundary {}'.format(feed, group, back_boundary, forward_boundary))
        for datafile_name in sorted(os.listdir(group_path)):
            if (not back_boundary or (datafile_name >= back_boundary)) and (not forward_boundary or (forward_boundary and datafile_name <= forward_boundary)):
                log.debug('Using data file {}'.format(datafile_name))
                fpath = os.path.join(group_path, datafile_name)
                with open(fpath) as f:
                    content = json.load(f)
                    data += content
            else:
                log.debug('Data file {} outside of bounds, skipping'.format(datafile_name))
                continue

        return data


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


# Examples for how to extend for local FS testing
class LocalPackagesFeed(PackagesFeed):
    __source_cls__ = LocalFilesystemFeedClient
    __data_path__ = None

    def __init__(self, metadata=None, src=None):
        if not src:
            src = self.__source_cls__(self.__data_path__)
        super(PackagesFeed, self).__init__(metadata=metadata, src=src)


class LocalVulnerabilityFeed(VulnerabilityFeed):
    __source_cls__ = LocalFilesystemFeedClient
    __data_path__ = None

    def __init__(self, metadata=None, src=None):
        if not src:
            src = self.__source_cls__(self.__data_path__)
        super(LocalVulnerabilityFeed, self).__init__(metadata=metadata, src=src)

