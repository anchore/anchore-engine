from collections import namedtuple

# Named tuples for responses
FeedGroup = namedtuple('FeedGroup', ['feed', 'name', 'access_tier', 'description'])
FeedGroupList = namedtuple('FeedList', ['next_token', 'groups'])
Feed = namedtuple('Feed', ['name', 'description', 'access_tier'])
FeedList = namedtuple('FeedList', ['next_token', 'feeds'])
GroupData = namedtuple('GroupData', ['data', 'next_token', 'since'])


class IFeedClient(object):
    """
    Base interface for a feed source
    """

    def list_feeds(self):
        """
        Get feed listing
        :return: FeedList
        """
        raise NotImplementedError()

    def list_feed_groups(self, feed):
        """
        Get groups for the feed
        :param feed: str name of feed to list
        :return: FeedGroupList
        """
        raise NotImplementedError()

    def get_feed_group_data(self, feed, group, since=None, next_token=None):
        """
        Get group data for the feed group that is newer than the since str. lexicographically
        Data is a list of dictionaries/json objects provided by the feed with no guarantees for uniqueness or ordering.

        :param feed: str name of feed to query
        :param group: str name of group within feed
        :param since: data str prefix, in iso-8601 format. e.g '2017-01-30' or '2017-01-30T12:00'
        :param next_token: token to fetch next chunk of data
        :return: GroupData
        """
        raise NotImplementedError()
