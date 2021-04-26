import datetime
from collections import namedtuple

FeedGroupList = namedtuple("FeedGroupList", ["groups"])
FeedList = namedtuple("FeedList", ["feeds"])
GroupData = namedtuple(
    "GroupData", ["data", "next_token", "since", "record_count", "response_metadata"]
)


class IFeedSource(object):
    """
    Base interface for a feed source
    """

    def list_feeds(self) -> FeedList:
        raise NotImplementedError()

    def list_feed_groups(self, feed: str) -> FeedGroupList:
        raise NotImplementedError()

    def get_feed_group_data(
        self,
        feed: str,
        group: str,
        since: datetime.datetime = None,
        next_token: str = None,
    ) -> GroupData:
        """
        Get a max_sized page of data using the continuation token.

        :param next_token:
        :param feed:
        :param group:
        :param since:
        :return:
        """
        raise NotImplementedError()
