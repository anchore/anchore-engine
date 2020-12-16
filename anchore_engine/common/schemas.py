"""
Shared global location for all JSON serialization schemas. They should only reference each-other in this module so it
can import cleanly into any service or module.
"""
import datetime

import marshmallow
from marshmallow import Schema, post_load, fields
from anchore_engine.utils import datetime_to_rfc3339, rfc3339str_to_datetime

# For other modules to import from this one instead of having to know/use marshmallow directly
ValidationError = marshmallow.ValidationError

# Add the rfc3339 format handlers
# fields.DateTime.SERIALIZATION_FUNCS["rfc3339"] = datetime_to_rfc3339
# fields.DateTime.DESERIALIZATION_FUNCS["rfc3339"] = rfc3339str_to_datetime
# fields.DateTime.DEFAULT_FORMAT = "rfc3339"


datetime_deserializations = fields.DateTime.DESERIALIZATION_FUNCS
datetime_deserializations["rfc3339"] = rfc3339str_to_datetime

datetime_serializations = fields.DateTime.SERIALIZATION_FUNCS
datetime_serializations["rfc3339"] = datetime_to_rfc3339


class RFC3339DateTime(fields.DateTime):
    DESERIALIZATION_FUNCS = datetime_deserializations
    SERIALIZATION_FUNCS = datetime_serializations

    DEFAULT_FORMAT = "rfc3339"


# TODO: This is not enforced in the interface yet, but should be the input and return type for queue operations in this API
class JsonSerializable:
    """
    Simple type wrapper mixin for json serialize/deserialize of objects to reduce boilerplate.

    To use: add as a parent type and set __schema__ at the class level to the JitSchema-subclassed object that is the json schema to use.
    Then call <class>.from_json(dict) and <obj>.to_json()

    Example:
        {'bucket': 'xx', 'key': 'blah'} -> obj
        obj = ObjectStoreLocation.from_json(json.loads(input_string))
        obj.to_json() # Gives a dict
        obj.to_json_str() # Gives a string serialized json output

        class ObjectStoreLocation(JsonSerializable):
          class ObjectStoreLocationV1Schema(Schema):
            bucket = fields.Str()
            key = fields.Str()

            # This tells the system to return the actual object type rather than a serialization result
            @post_load
            def make(self, data, **kwargs):
              return ObjectStoreLocation(**data)


          # Set the schema ref. This doesn't strictly have to be a child-class, could be outside the parent type. Done here for clarity
          __schema__ = ObjectStoreLocationV1Schema()

          # Needs a kwargs-style constructor for the @post_load/make() call to work
          def __init__(self, bucket=None, key=None):
            self.bucket = bucket
            self.key = key


    """

    __schema__: Schema = None

    @classmethod
    def from_json(cls, data):
        return cls.__schema__.load(data)

    def to_json(self):
        return self.__schema__.dump(self)

    def to_json_str(self):
        return self.__schema__.dumps(self)


class QueueMessage(JsonSerializable):
    """
    The generic queue message object
    """

    class QueueMessageV1Schema(Schema):
        """
        Example for an image analysis message:
            { 'created_at': 1604474221,
                'data': {
                    'imageDigest': 'sha256:0325f4ff0aa8c89a27d1dbe10b29a71a8d4c1a42719a4170e0552a312e22fe88',
                    'manifest': '{"schemaVersion": 2, "mediaType": "application/vnd.docker.distribution.manifest.v2+json", "config": {"mediaType": "application/vnd.docker.container.image.v1+json", "size": 1512, "digest": "sha256:b7c5ffe56db790f91296bcebc5158280933712ee2fc8e6dc7d6c96dbb1632431"}, "layers": [{"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip", "size": 2387850, "digest": "sha256:c1e54eec4b5786500c19795d1fc604aa7302aee307edfe0554a5c07108b77d48"}]}',
                    'parent_manifest': '{"schemaVersion": 2, "mediaType": "application/vnd.docker.distribution.manifest.list.v2+json", "manifests": [{"mediaType": "application/vnd.docker.distribution.manifest.v2+json", "size": 528, "digest": "sha256:0325f4ff0aa8c89a27d1dbe10b29a71a8d4c1a42719a4170e0552a312e22fe88", "platform": {"architecture": "amd64", "os": "linux"}}]}',
                    'userId': 'admin'},
                'dataId': 'e05953b79c0f8653ae0650e461db4c90',
                'last_updated': 1604474221,
                'max_tries': 0,
                'popped': True,
                'priority': False,
                'queueId': 32013,
                'queueName': 'images_to_analyze',
                'receipt_handle': None,
                'record_state_key': 'active',
                'record_state_val': None,
                'tries': 0,
                'userId': 'system',
                'visible_at': None
            }

        """

        account = fields.String(data_key="userId")
        created_at = fields.Int(required=True)  # Epoch timestamp
        last_updated = fields.Int(required=True)  # Epoch timestamp
        queue_id = fields.Int(required=True, data_key="queueId")
        queue_name = fields.String(required=True, data_key="queueName")
        data = fields.Dict(required=True)
        data_id = fields.String(data_key="dataId", required=True)
        receipt_handle = fields.String(allow_none=True)
        record_state_key = fields.String(allow_none=True)
        record_state_val = fields.String(allow_none=True)
        tries = fields.Int(allow_none=True)
        max_tries = fields.Int(allow_none=True)
        popped = fields.Bool(allow_none=True)
        priority = fields.Bool(allow_none=True)
        visible_at = fields.Int(allow_none=True)
        version = fields.String(
            default="1", missing="1", allow_none=True
        )  # New version field to support future message schema updates

        @post_load
        def make(self, data, **kwargs):
            return QueueMessage(**data)

    __schema__ = QueueMessageV1Schema(unknown="EXCLUDE")

    def __init__(
        self,
        account=None,
        queue_id=None,
        queue_name=None,
        data=None,
        data_id=None,
        receipt_handle=None,
        record_state_key=None,
        record_state_val=None,
        tries=None,
        max_tries=None,
        popped=None,
        visible_at=None,
        priority=None,
        created_at=None,
        last_updated=None,
        version=None,
    ):
        self.account = account
        self.queue_id = queue_id
        self.queue_name = queue_name
        self.data = data
        self.data_id = data_id
        self.receipt_handle = receipt_handle
        self.record_state_key = record_state_key
        self.record_state_val = record_state_val
        self.tries = tries
        self.max_tries = max_tries
        self.popped = popped
        self.created_at = created_at
        self.last_updated = last_updated
        self.visible_at = visible_at
        self.priority = priority
        self.version = None


class AnalysisQueueMessage(JsonSerializable):
    """
    A queue message payload requesting analysis of an image, for consumption by the worker service.
    """

    class AnalysisQueueMessageV1Schema(Schema):
        """
        Example for an image analysis message:
        {
            'imageDigest': 'sha256:0325f4ff0aa8c89a27d1dbe10b29a71a8d4c1a42719a4170e0552a312e22fe88',
            'manifest': '{"schemaVersion": 2, "mediaType": "application/vnd.docker.distribution.manifest.v2+json", "config": {"mediaType": "application/vnd.docker.container.image.v1+json", "size": 1512, "digest": "sha256:b7c5ffe56db790f91296bcebc5158280933712ee2fc8e6dc7d6c96dbb1632431"}, "layers": [{"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip", "size": 2387850, "digest": "sha256:c1e54eec4b5786500c19795d1fc604aa7302aee307edfe0554a5c07108b77d48"}]}',
            'parent_manifest': '{"schemaVersion": 2, "mediaType": "application/vnd.docker.distribution.manifest.list.v2+json", "manifests": [{"mediaType": "application/vnd.docker.distribution.manifest.v2+json", "size": 528, "digest": "sha256:0325f4ff0aa8c89a27d1dbe10b29a71a8d4c1a42719a4170e0552a312e22fe88", "platform": {"architecture": "amd64", "os": "linux"}}]}',
            'userId': 'admin'},
        }

        """

        account = fields.String(data_key="userId")
        image_digest = fields.String(data_key="imageDigest")
        manifest = fields.String(required=True)
        parent_manifest = fields.String()
        type = fields.String(default="analysis")

        @post_load
        def make(self, data, **kwargs):
            return AnalysisQueueMessage(**data)

    __schema__ = AnalysisQueueMessageV1Schema()

    def __init__(
        self, account=None, image_digest=None, manifest=None, parent_manifest=None
    ):
        self.account = account
        self.image_digest = image_digest
        self.manifest = manifest
        self.parent_manifest = parent_manifest


class ImageLayerMetadata(JsonSerializable):
    class ImageLayerMetadataV1Schema(Schema):
        digest = fields.String()
        size = fields.Int()
        location = fields.String(
            allow_none=True
        )  # To allow capturing foreign url references

        @post_load
        def make(self, data, **kwarg):
            return ImageLayerMetadata(**data)

    __schema__ = ImageLayerMetadataV1Schema()

    def __init__(self, digest=None, size=None, location=None):
        self.digest = digest
        self.size = size
        self.location = location


class ImagePlatform(JsonSerializable):
    class ImagePlatformV1Schema(Schema):
        os = fields.String()
        architecture = fields.String()

        @post_load
        def make(self, data, **kwargs):
            return ImagePlatform(**data)

    __schema__ = ImagePlatformV1Schema(unknown="EXCLUDE")

    def __init__(self, os=None, architecture=None):
        self.os = os
        self.architecture = architecture


class ImportContentReference(JsonSerializable):
    """
    An import content reference for the internal object store. This is primarily used for internal messaging
    """

    class ImportContentReferenceV1Schema(Schema):
        content_type = fields.String(required=True)
        digest = fields.String(required=True)
        bucket = fields.String(required=True)
        key = fields.String(required=True)

        @post_load
        def make(self, data, **kwargs):
            return ImportContentReference(**data)

    __schema__ = ImportContentReferenceV1Schema()

    def __init__(self, content_type=None, digest=None, bucket=None, key=None):
        self.content_type = content_type
        self.digest = digest
        self.bucket = bucket
        self.key = key


class ContentTypeDigests(JsonSerializable):
    class ContentTypeDigestsV1Schema(Schema):
        packages = fields.String(required=True)
        image_config = fields.String(required=True)
        manifest = fields.String(required=True)
        dockerfile = fields.String(allow_none=True)
        parent_manifest = fields.String(allow_none=True)

        @post_load
        def make(self, data, **kwargs):
            return ContentTypeDigests(**data)

    __schema__ = ContentTypeDigestsV1Schema()

    def __init__(
        self,
        packages=None,
        image_config=None,
        dockerfile=None,
        manifest=None,
        parent_manifest=None,
    ):
        self.packages = packages
        self.dockerfile = dockerfile
        self.manifest = manifest
        self.parent_manifest = parent_manifest
        self.image_config = image_config


class ImportManifest(JsonSerializable):
    class ImportManifestV1Schema(Schema):
        tags = fields.List(fields.String(), allow_none=True)
        contents = fields.Nested(ContentTypeDigests.ContentTypeDigestsV1Schema)
        digest = fields.String(required=True)
        parent_digest = fields.String(
            allow_none=True
        )  # The digest of the manifest-list parent object if this was a pulled image in a multi-arch tag and that data is available
        local_image_id = fields.String(allow_none=True)
        operation_uuid = fields.String(required=True)

        @post_load
        def make(self, data, **kwargs):
            return ImportManifest(**data)

    __schema__ = ImportManifestV1Schema()

    def __init__(
        self,
        digest=None,
        parent_digest=None,
        local_image_id=None,
        metadata=None,
        tags=None,
        contents=None,
        operation_uuid=None,
    ):
        self.metadata = metadata
        self.tags = tags
        self.contents = contents
        self.digest = digest
        self.local_image_id = local_image_id
        self.parent_digest = parent_digest
        self.operation_uuid = operation_uuid


class InternalImportManifest(JsonSerializable):
    """
    The materialized internal manifest for an import. Differs from the external ImportManifest in that it carries information
    between services such as the object storage location of the content to avoid re-computing it in each service.
    """

    class InternalImportManifestV1Schema(Schema):
        tags = fields.List(fields.String(), allow_none=True)
        contents = fields.List(
            fields.Nested(ImportContentReference.ImportContentReferenceV1Schema)
        )
        digest = fields.String(required=True)
        parent_digest = fields.String(
            allow_none=True
        )  # The digest of the manifest-list parent object if this was a pulled image in a multi-arch tag and that data is available
        local_image_id = fields.String(allow_none=True)
        operation_uuid = fields.String(required=True)

        @post_load
        def make(self, data, **kwargs):
            return InternalImportManifest(**data)

    __schema__ = InternalImportManifestV1Schema()

    def __init__(
        self,
        digest=None,
        parent_digest=None,
        local_image_id=None,
        tags=None,
        contents=None,
        operation_uuid=None,
    ):
        self.tags = tags
        self.contents = contents
        self.digest = digest
        self.local_image_id = local_image_id
        self.parent_digest = parent_digest
        self.operation_uuid = operation_uuid


class ImportQueueMessage(JsonSerializable):
    """
    This message has the same keys as the Analysis message due to implementation details in the queue rebalancer/handler in the catalog.
    That should be fixed and then allow this to be a more bespoke message format
    """

    class ImportQueueMessageV1Schema(Schema):
        account = fields.String(data_key="userId")
        image_digest = fields.String(data_key="imageDigest")
        manifest = fields.Nested(
            InternalImportManifest.InternalImportManifestV1Schema, allow_none=True
        )
        parent_manifest = fields.String(allow_none=True)
        type = fields.String(default="analysis", allow_none=True)

        @post_load
        def make(self, data, **kwargs):
            return ImportQueueMessage(**data)

    __schema__ = ImportQueueMessageV1Schema()

    def __init__(
        self,
        account=None,
        image_digest=None,
        manifest=None,
        parent_manifest=None,
        type=None,
    ):
        self.account = account
        self.image_digest = image_digest
        self.manifest = manifest
        self.parent_manifest = parent_manifest
        self.type = type


class FeedAPIGroupRecord(JsonSerializable):
    class FeedAPIGroupV1Schema(Schema):
        name = fields.Str()
        access_tier = fields.Int()
        description = fields.Str()

        @post_load
        def make(self, data, **kwargs):
            return FeedAPIGroupRecord(**data)

    __schema__ = FeedAPIGroupV1Schema()

    def __init__(self, name="", access_tier=0, description=""):
        self.name = name
        self.access_tier = access_tier
        self.description = description


class FeedAPIRecord(JsonSerializable):
    class FeedAPIV1Schema(Schema):
        name = fields.Str()
        access_tier = fields.Int()
        description = fields.Str()

        @post_load
        def make(self, data, **kwargs):
            return FeedAPIRecord(**data)

    __schema__ = FeedAPIV1Schema()

    def __init__(self, name="", access_tier=0, description=""):
        self.name = name
        self.access_tier = access_tier
        self.description = description


class GroupDownloadOperationParams(JsonSerializable):
    class GroupDownloadOperationParamsV1Schema(Schema):
        since = fields.DateTime(allow_none=True)

        @post_load
        def make(self, data, **kwargs):
            return GroupDownloadOperationParams(**data)

    __schema__ = GroupDownloadOperationParamsV1Schema()

    def __init__(self, since: datetime.datetime = None):
        self.since = since


class GroupDownloadOperationConfiguration(JsonSerializable):
    class GroupDownloadOperationV1Schema(Schema):
        feed = fields.Str()
        group = fields.Str()
        parameters = fields.Nested(
            GroupDownloadOperationParams.GroupDownloadOperationParamsV1Schema
        )

        @post_load
        def make(self, data, **kwargs):
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


class DownloadOperationConfiguration(JsonSerializable):
    """
    A configuration for a Download operation
    """

    class DownloadOperationV1Schema(Schema):
        groups = fields.List(
            fields.Nested(
                GroupDownloadOperationConfiguration.GroupDownloadOperationV1Schema
            )
        )
        source_uri = fields.Str()
        uuid = fields.UUID()

        @post_load
        def make(self, data, **kwargs):
            return DownloadOperationConfiguration(**data)

    __schema__ = DownloadOperationV1Schema()

    def __init__(self, uuid: str = None, groups: list = None, source_uri: str = None):
        self.groups = groups
        self.source_uri = source_uri
        self.uuid = uuid


class GroupDownloadResult(JsonSerializable):
    class GroupDownloadResultV1Schema(Schema):
        started = fields.DateTime()
        ended = fields.DateTime()
        feed = fields.Str()
        group = fields.Str()
        status = fields.Str()
        total_records = fields.Int()

        @post_load
        def make(self, data, **kwargs):
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


class DownloadOperationResult(JsonSerializable):
    class DownloadOperationResultV1Schema(Schema):
        started = fields.DateTime(allow_none=True)
        ended = fields.DateTime(allow_none=True)
        status = fields.Str(allow_none=True)
        results = fields.List(
            fields.Nested(GroupDownloadResult.GroupDownloadResultV1Schema)
        )

        @post_load
        def make(self, data, **kwargs):
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


class LocalFeedDataRepoMetadata(JsonSerializable):
    class LocalFeedDataRepoMetadataV1Schema(Schema):
        download_configuration = fields.Nested(
            DownloadOperationConfiguration.DownloadOperationV1Schema, allow_none=True
        )
        download_result = fields.Nested(
            DownloadOperationResult.DownloadOperationResultV1Schema, allow_none=True
        )
        data_write_dir = fields.Str()

        @post_load
        def make(self, data, **kwargs):
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
