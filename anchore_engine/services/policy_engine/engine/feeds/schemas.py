"""
JSON schemas for the feed Download and sync processes

"""

import datetime
import uuid

from anchore_engine.apis.serialization import (
    JsonMappedMixin,
    JitSchema,
    fields,
    post_load,
)
from anchore_engine.db import FeedGroupMetadata


class FeedAPIGroupRecord(JsonMappedMixin):
    class FeedAPIGroupV1Schema(JitSchema):
        name = fields.Str()
        access_tier = fields.Int()
        description = fields.Str()

        @post_load
        def make(self, data):
            return FeedAPIGroupRecord(**data)

    __schema__ = FeedAPIGroupV1Schema()

    def __init__(self, name="", access_tier=0, description=""):
        self.name = name
        self.access_tier = access_tier
        self.description = description


class FeedAPIRecord(JsonMappedMixin):
    class FeedAPIV1Schema(JitSchema):
        name = fields.Str()
        access_tier = fields.Int()
        description = fields.Str()

        @post_load
        def make(self, data):
            return FeedAPIRecord(**data)

    __schema__ = FeedAPIV1Schema()

    def __init__(self, name="", access_tier=0, description=""):
        self.name = name
        self.access_tier = access_tier
        self.description = description


class GroupDownloadOperationParams(JsonMappedMixin):
    class GroupDownloadOperationParamsV1Schema(JitSchema):
        since = fields.DateTime(allow_none=True)

        @post_load
        def make(self, data):
            return GroupDownloadOperationParams(**data)

    __schema__ = GroupDownloadOperationParamsV1Schema()

    def __init__(self, since: datetime.datetime = None):
        self.since = since


class GroupDownloadOperationConfiguration(JsonMappedMixin):
    class GroupDownloadOperationV1Schema(JitSchema):
        feed = fields.Str()
        group = fields.Str()
        parameters = fields.Nested(
            GroupDownloadOperationParams.GroupDownloadOperationParamsV1Schema
        )

        @post_load
        def make(self, data):
            return GroupDownloadOperationConfiguration(**data)

    __schema__ = GroupDownloadOperationV1Schema()

    def __init__(
        self,
        feed: str = None,
        group: str = None,
        parameters: GroupDownloadOperationParams = None,
    ):
        self.feed = feed
        self.group = group
        self.parameters = parameters


class DownloadOperationConfiguration(JsonMappedMixin):
    """
    A configuration for a Download operation
    """

    class DownloadOperationV1Schema(JitSchema):
        groups = fields.List(
            fields.Nested(
                GroupDownloadOperationConfiguration.GroupDownloadOperationV1Schema
            )
        )
        source_uri = fields.Str()
        uuid = fields.UUID()

        @post_load
        def make(self, data):
            return DownloadOperationConfiguration(**data)

    __schema__ = DownloadOperationV1Schema()

    def __init__(self, uuid: str = None, groups: list = None, source_uri: str = None):
        self.groups = groups
        self.source_uri = source_uri
        self.uuid = uuid

    @classmethod
    def generate_new(cls, source_uri, db_groups_to_sync, is_full_download=False):
        conf = DownloadOperationConfiguration(
            uuid=uuid.uuid4().hex, source_uri=source_uri, groups=[]
        )

        for g in db_groups_to_sync:
            if not isinstance(g, FeedGroupMetadata):
                raise TypeError(
                    "db_groups_to_sync must be list of FeedGroupMetadata objects"
                )

            group_download_conf = GroupDownloadOperationConfiguration()
            group_download_conf.feed = g.feed_name
            group_download_conf.group = g.name
            group_since = g.last_sync if not is_full_download else None
            group_download_conf.parameters = GroupDownloadOperationParams(
                since=group_since
            )
            conf.groups.append(group_download_conf)

        return conf


class GroupDownloadResult(JsonMappedMixin):
    class GroupDownloadResultV1Schema(JitSchema):
        started = fields.DateTime()
        ended = fields.DateTime()
        feed = fields.Str()
        group = fields.Str()
        status = fields.Str()
        total_records = fields.Int()

        @post_load
        def make(self, data):
            return GroupDownloadResult(**data)

    __schema__ = GroupDownloadResultV1Schema()

    def __init__(
        self,
        started: datetime = None,
        ended: datetime = None,
        feed: str = None,
        group: str = None,
        status: str = None,
        total_records: int = None,
    ):
        self.started = started
        self.ended = ended
        self.status = status
        self.feed = feed
        self.group = group
        self.total_records = total_records


class DownloadOperationResult(JsonMappedMixin):
    class DownloadOperationResultV1Schema(JitSchema):
        started = fields.DateTime(allow_none=True)
        ended = fields.DateTime(allow_none=True)
        status = fields.Str(allow_none=True)
        results = fields.List(
            fields.Nested(GroupDownloadResult.GroupDownloadResultV1Schema)
        )

        @post_load
        def make(self, data):
            return DownloadOperationResult(**data)

    __schema__ = DownloadOperationResultV1Schema()

    def __init__(
        self,
        started: datetime = None,
        ended: datetime = None,
        status: str = None,
        results: list = None,
    ):
        """
        Make sure these are UTC dates

        :param started:
        :param ended:
        :param status:
        :param results:
        """
        self.started = started
        self.ended = ended
        self.status = status
        self.results = results


class LocalFeedDataRepoMetadata(JsonMappedMixin):
    class LocalFeedDataRepoMetadataV1Schema(JitSchema):
        download_configuration = fields.Nested(
            DownloadOperationConfiguration.DownloadOperationV1Schema, allow_none=True
        )
        download_result = fields.Nested(
            DownloadOperationResult.DownloadOperationResultV1Schema, allow_none=True
        )
        data_write_dir = fields.Str()

        @post_load
        def make(self, data):
            return LocalFeedDataRepoMetadata(**data)

    __schema__ = LocalFeedDataRepoMetadataV1Schema()

    def __init__(
        self,
        download_configuration: DownloadOperationConfiguration = None,
        download_result: DownloadOperationResult = None,
        data_write_dir: str = None,
    ):
        self.download_configuration = download_configuration
        self.download_result = download_result
        self.data_write_dir = data_write_dir
