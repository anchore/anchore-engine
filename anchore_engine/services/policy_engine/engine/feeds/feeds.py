import datetime
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Optional, Sequence, Tuple

from sqlalchemy.orm.session import Session

from anchore_engine.clients.grype_wrapper import (
    GrypeDBEngineMetadata,
    GrypeDBMetadata,
    GrypeWrapperSingleton,
    RecordSource,
)
from anchore_engine.clients.services import internal_client_for
from anchore_engine.clients.services.catalog import CatalogClient
from anchore_engine.clients.services.simplequeue import SimpleQueueClient
from anchore_engine.common.models.policy_engine import (
    FeedGroupMetadata as APIFeedGroupMetadata,
)
from anchore_engine.common.models.schemas import (
    BatchImageVulnerabilitiesQueueMessage,
    GroupDownloadResult,
    ImageVulnerabilitiesQueueMessage,
)
from anchore_engine.db import (
    CpeV2Vulnerability,
    CpeVulnerability,
    FeedGroupMetadata,
    FeedMetadata,
    FixedArtifact,
    GemMetadata,
    GenericFeedDataRecord,
    GrypeDBFeedMetadata,
    Image,
    NpmMetadata,
    NvdMetadata,
    NvdV2Metadata,
    VulnDBCpe,
    VulnDBMetadata,
    Vulnerability,
    VulnerableArtifact,
)
from anchore_engine.db import get_thread_scoped_session as get_session
from anchore_engine.services.policy_engine.engine.feeds.db import (
    get_feed_json,
    lookup_feed,
)
from anchore_engine.services.policy_engine.engine.feeds.download import (
    FileData,
    LocalFeedDataRepo,
)
from anchore_engine.services.policy_engine.engine.feeds.grypedb_sync import (
    GrypeDBSyncError,
    GrypeDBSyncManager,
)
from anchore_engine.services.policy_engine.engine.feeds.mappers import (
    FeedDataMapper,
    GemPackageDataMapper,
    GithubFeedDataMapper,
    MapperFactory,
    MultiTypeMapperFactory,
    NpmPackageDataMapper,
    NvdV2FeedDataMapper,
    SingleTypeMapperFactory,
    VulnDBFeedDataMapper,
    VulnerabilityFeedDataMapper,
)
from anchore_engine.services.policy_engine.engine.feeds.storage import (
    GrypeDBFile,
    GrypeDBStorage,
)
from anchore_engine.services.policy_engine.engine.vulnerabilities import (
    ThreadLocalFeedGroupNameCache,
    flush_vulnerability_matches,
    process_updated_vulnerability,
)
from anchore_engine.subsys import logger
from anchore_engine.utils import rfc3339str_to_datetime

IMAGE_VULNERABILITIES_QUEUE = "image_vulnerabilities"
MESSAGE_BATCH_SIZE = 10


@dataclass
class GroupSyncResult:
    group: Optional[str] = None
    status: str = "failure"
    total_time_seconds: int = 0
    updated_record_count: int = 0
    updated_image_count: int = 0


@dataclass
class FeedSyncResult:
    feed: Optional[str] = None
    status: str = "failure"
    total_time_seconds: int = 0
    groups: List[GroupSyncResult] = field(default_factory=list)


class LogContext:
    def __init__(
        self,
        operation_id: Optional[str] = None,
        feed: Optional[str] = None,
        group: Optional[str] = None,
    ):
        self.operation_id: Optional[str] = operation_id
        self.feed: Optional[str] = feed
        self.group: Optional[str] = group

    def format_msg(self, msg: str):
        return "{} (operation_id={}, feed={}, group={})".format(
            msg, self.operation_id, self.feed, self.group
        )


class LogContextMixin:
    def __init__(self, metadata: Optional[FeedMetadata] = None):
        self._log_ctx: LogContext = LogContext(None, None, None)
        super().__init__(metadata)

    @property
    def _log_context(self):
        """
        Getter for log context.
        """
        return self._log_ctx

    @_log_context.setter
    def _log_context(self, log_context: LogContext) -> None:
        """
        Setter for log context.

        :param log_context: log context object to replace what's currently stored
        :type log_context: LogContext
        """
        self._log_ctx = log_context


class DataFeed(ABC):
    """
    Base class for a data feed. A DataFeed is a combination of a means to connect to the feed, metadata about the feed actions
    locally, and mapping data ingesting the feed data itself.

    :param metadata: existing FeedMetadata instance to use to store stateful information about this feed (if available for bootstrapping)
    :type metadata: Optional[FeedMetadata], defaults to None
    """

    __feed_name__ = None
    __group_data_mappers__: Optional[
        MapperFactory
    ] = None  # A dict/map of group names to mapper objects for translating group data into db types

    def __init__(self, metadata: Optional[FeedMetadata] = None):
        if not metadata:
            db = get_session()
            metadata = lookup_feed(db, self.__feed_name__)
            if not metadata:
                raise Exception(
                    "Must have feed metadata in db already, should sync metadata before invoking instance operations"
                )
        self.metadata: FeedMetadata = metadata

    def _update_last_full_sync_timestamp(self) -> None:
        """
        Update the last sync timestamp of the FeedMetadata record for this feed
        """
        db = get_session()
        try:
            if self.metadata:
                db.refresh(self.metadata)
            else:
                raise ValueError("metadata object not found")

            # Update timestamps
            self.metadata.last_update = datetime.datetime.utcnow()
            self.metadata.last_full_sync = self.metadata.last_update
            db.commit()
        except Exception as e:
            logger.exception("Failed updating feed metadata timestamps.")
            db.rollback()
            raise e

    @abstractmethod
    def sync(
        self,
        fetched_data: LocalFeedDataRepo,
        full_flush: bool = False,
        event_client: CatalogClient = None,
        operation_id=None,
        group=None,
    ) -> FeedSyncResult:
        """
        Ensure the feed is synchronized. Performs checks per sync item and if item_processing_fn is provided.
        Transaction scope is the update for an entire group.

        item_processing_fn is exepected to be a function that can consume a db session but should *NOT* commit or rollback the session. The caller will handle that to properly maintain
        session scope to each item to be updated.

        :param fetched_data: disk cache for downloaded data to sync
        :type fetched_data: LocalFeedDataRepo
        :param full_flush: whether or not to flush all records before syncing new ones
        :type full_flush: bool, defaults to False
        :param event_client: catalog client
        :type event_client: Optional[CatalogClient], defaults to None
        :param operation_id: UUID4 hexadeicmal string
        :type operation_id: Optional[str], defaults to None
        :param group: filter for which groups to update
        :type group: Optional[str], defaults to None
        :return: changed data updated in the sync as a list of records
        :rtype: FeedSyncResult
        """
        ...

    @abstractmethod
    def record_count(self, group_name, db) -> int:
        """
        Returns number of records present in the database for a given group

        :param group_name: name of the group
        :type group_name: str
        :param db: sqlaclhemy database session
        :type db: Session
        :return: number of records
        :rtype: int
        """
        ...

    @abstractmethod
    def update_counts(self) -> None:
        """
        Self-contained unit of work to update the row counts for each feed group in the feed group metadata
        """
        ...

    @abstractmethod
    def group_by_name(self, group_name: str) -> Optional[FeedGroupMetadata]:
        """
        Gets the metadata record for the group with the given name.

        :param group_name: the name of the group for which to retreive the metadata record
        :type group_name: str
        :return: the metadata record if it exists
        :rtype: Optional[FeedGroupMetadata]
        """
        ...

    @abstractmethod
    def flush_group(self, group_name: str) -> FeedGroupMetadata:
        """
        Flush a specific data group. Do a db flush, but not a commit at the end to keep the transaction open.

        :param group_name: name of group to flush
        :type group_name: str
        :return: db record containing metadata of group flushed
        :rtype: FeedGroupMetadata
        """
        ...

    @abstractmethod
    def flush_all(self) -> FeedMetadata:
        """
        Flush all groups for the feed, unset the last full sync timestamp, but leave metadata records for feed.

        :return: db record containing feed metadata
        :rtype: FeedMetadata
        """
        ...


class AnchoreServiceFeed(LogContextMixin, DataFeed, ABC):
    """
    A data feed provided by the Anchore Feeds service.

    Metadata persisted in the backing db.
    Instance load will fire a load from the db to get the latest metadata in db, and sync
    operations will sync data and metadata from the upstream service.
    """

    __feed_name__ = "base"
    __group_data_mappers__ = MultiTypeMapperFactory(__feed_name__, {}, None)
    __flush_helper_fn__ = None

    RECORDS_PER_CHUNK = 500

    def update_counts(self) -> None:
        """
        Self-contained unit of work to update the row counts for each feed group in the feed group metadata
        """

        db = get_session()
        try:
            logger.debug("Updating group counts for feed {}".format(self.__feed_name__))
            my_meta = lookup_feed(db, self.__feed_name__)
            for group in my_meta.groups:
                group.count = self.record_count(group.name, db)
                logger.info(
                    "Updating feed group {} record count = {}".format(
                        group.name, group.count
                    )
                )
            db.commit()
        except Exception:
            db.rollback()
            logger.error("Could not update group counts")
            raise

    def _load_mapper(self, group_obj) -> FeedDataMapper:
        """
        Find and instantiate the right mapper object for the given group.

        :param group_obj:
        :return: feed data mapper for this group
        :rtype: FeedDataMapper
        """
        mapper = self.__class__.__group_data_mappers__.get(group_obj.name)

        if not mapper:
            raise Exception(
                "No mapper class found for group: {}".format(group_obj.name)
            )

        return mapper

    def _process_group_file_records(
        self,
        db: Session,
        group_download_result: GroupDownloadResult,
        group_obj: FeedGroupMetadata,
        local_repo: Optional[LocalFeedDataRepo],
    ) -> int:
        """
        Convert the download results for a feed group into database records and write to the database session.
        Transactions are batched by the integer specified in AnchoreServiceFeed.RECORDS_PER_CHUNK, so a commit only
        occurs once for every chunk. The transaction can be rolled back in _sync_group() for a specific chunk if an
        exception is encountered.
        :param db: sqlalchemy database session
        :type db: Session
        :param group_download_result: group download result record to update
        :type group_download_result: GroupDownloadResult
        :param group_obj: metadata record for this feed group
        :type group_obj: FeedGroupMetadata
        :param local_repo: LocalFeedDataRepo (disk cache for download results)
        :type local_repo: Optional[LocalFeedDataRepo], defaults to None
        :return: int
        :rtype: total number of records updated
        """

        #  load the mapper for this record type
        mapper = self._load_mapper(group_obj)
        count = 0
        total_records_updated = 0

        #  iterate over the downloaded json rows in the local storage
        for record in local_repo.read(
            group_download_result.feed, group_download_result.group, 0
        ):

            # convert the json record to the corresponding database record structure and update or add
            mapped = mapper.map(record)
            db.merge(mapped)
            total_records_updated += 1
            count += 1

            # every time we process RECORDS_PER_CHUNK records, flush the changes and commit the txn
            if count >= self.RECORDS_PER_CHUNK:
                # Commit
                group_obj.count = self.record_count(group_obj.name, db)
                db.commit()
                db = get_session()
                logger.info(
                    self._log_context.format_msg(
                        "DB Update Progress: {}/{}".format(
                            total_records_updated,
                            group_download_result.total_records,
                        ),
                    )
                )
                count = 0

        # Once we run out of records, flush the changes and commit the txn
        else:
            group_obj.count = self.record_count(group_obj.name, db)
            db.commit()
            logger.info(
                self._log_context.format_msg(
                    "DB Update Progress: {}/{}".format(
                        total_records_updated,
                        group_download_result.total_records,
                    ),
                )
            )
        return total_records_updated

    def _sync_group(
        self,
        group_download_result: GroupDownloadResult,
        full_flush=False,
        local_repo=None,
    ) -> GroupSyncResult:
        """
        Sync data from a single group and return the data. Transactions are batched.

        :param group_download_result: group download result record to update
        :type group_download_result: GroupDownloadResult
        :param full_flush: whether or not to flush out old records before syncing
        :type full_flush: bool, defaults to False
        :param local_repo: LocalFeedDataRepo (disk cache for download results)
        :type local_repo: Optional[LocalFeedDataRepo], defaults to None
        :return: GroupSyncResult as a dict
        :rtype: dict
        """
        result = GroupSyncResult(group=group_download_result.group)

        db = get_session()
        group_db_obj = None
        if self.metadata:
            db.refresh(self.metadata)
            group_db_obj = self.group_by_name(group_download_result.group)

        if not group_db_obj:
            logger.error(
                self._log_context.format_msg(
                    "Skipping sync for feed group {}, not found in db, record should have been synced already".format(
                        group_download_result.group
                    ),
                )
            )
            return result

        download_started = group_download_result.started.replace(
            tzinfo=datetime.timezone.utc
        )
        sync_started = time.time()

        try:
            if full_flush:
                logger.info(
                    self._log_context.format_msg(
                        "Performing data flush prior to sync as requested",
                    )
                )
                self._flush_group(group_db_obj)

            # Iterate thru the records and commit

            logger.info(
                self._log_context.format_msg(
                    "Syncing {} total update records into db in sets of {}".format(
                        group_download_result.total_records, self.RECORDS_PER_CHUNK
                    ),
                )
            )
            result.updated_record_count = self._process_group_file_records(
                db, group_download_result, group_db_obj, local_repo
            )
            db = get_session()

            logger.debug(
                self._log_context.format_msg(
                    "Updating last sync timestamp to {}".format(download_started),
                )
            )
            group_db_obj = self.group_by_name(group_download_result.group)
            # There is potential failures that could happen when downloading,
            # skipping updating the `last_sync` allows the system to retry
            if group_download_result.status == "complete":
                group_db_obj.last_sync = download_started
            group_db_obj.count = self.record_count(group_db_obj.name, db)
            db.add(group_db_obj)
            db.commit()
        except Exception as e:
            logger.exception(
                self._log_context.format_msg(
                    "Error syncing",
                )
            )
            db.rollback()
            raise e
        finally:
            sync_time = time.time() - sync_started
            result.total_time_seconds = time.time() - download_started.timestamp()
            logger.info(
                self._log_context.format_msg(
                    "Sync to db duration: {} sec".format(sync_time),
                )
            )
            logger.info(
                self._log_context.format_msg(
                    "Total sync, including download, duration: {} sec".format(
                        result.total_time_seconds
                    ),
                )
            )

        result.status = "success"
        return result

    def _flush_group(self, group_obj: FeedGroupMetadata) -> None:
        """
        Flush a specific data group. Do a db flush, but not a commit at the end to keep the transaction open.

        :param group_obj: feed group metadata record
        :type group_obj: FeedGroupMetadata
        """
        db = get_session()

        logger.info(
            self._log_context.format_msg(
                "Flushing group records",
            )
        )

        if self.__flush_helper_fn__:
            self.__flush_helper_fn__(
                db=db, feed_name=group_obj.feed_name, group_name=group_obj.name
            )

        db.query(GenericFeedDataRecord).delete()
        group_obj.last_sync = None  # Null the update timestamp to reflect the flush
        group_obj.count = 0
        db.flush()

    def flush_group(self, group_name: str) -> FeedGroupMetadata:
        """
        Flush a specific data group. Do a db flush, but not a commit at the end to keep the transaction open.

        :param group_name: name of group to flush
        :type group_name: str
        :return: db record containing metadata of group flushed
        :rtype: FeedGroupMetadata
        """
        db = get_session()
        try:
            g = self.group_by_name(group_name)
            if not g:
                raise KeyError(group_name)

            self._flush_group(g)
            db.commit()
            return g
        except Exception:
            db.rollback()
            raise

    def flush_all(self) -> FeedMetadata:
        """
        Flush all groups for the feed, unset the last full sync timestamp, but leave metadata records for feed.

        :return: db record containing feed metadata
        :rtype: FeedMetadata
        """
        db = get_session()
        try:
            db.refresh(self.metadata)
            for g in self.metadata.groups:
                self._flush_group(group_obj=g)

            db.refresh(self.metadata)

            # Remove all groups
            self.metadata.groups = []
            self.metadata.last_full_sync = None
            db.commit()
            return self.metadata
        except Exception:
            db.rollback()
            raise

    def sync(
        self,
        fetched_data: LocalFeedDataRepo,
        full_flush: bool = False,
        event_client: CatalogClient = None,
        operation_id=None,
        group=None,
    ) -> FeedSyncResult:
        """
        Sync data with the feed source. This may be *very* slow if there are lots of updates.

        Returns a dict with the following structure:
        {
        'group_name': [ record1, record2, ..., recordN],
        'group_name2': [ record1, record2, ...., recordM],
        ...
        }

        :param fetched_data: disk cache for downloaded data to sync
        :type fetched_data: LocalFeedDataRepo
        :param full_flush: whether or not to flush all records before syncing new ones
        :type full_flush: bool, defaults to False
        :param event_client: catalog client
        :type event_client: Optional[CatalogClient], defaults to None
        :param operation_id: UUID4 hexadeicmal string
        :type operation_id: Optional[str], defaults to None
        :param group: filter for which groups to update
        :type group: Optional[str], defaults to None
        :return: FeedSyncResult, containing sync results for each group
        :rtype: FeedSyncResult
        """
        result = FeedSyncResult(feed=self.__feed_name__)
        failed_count = 0

        # Each group update is a unique session and can roll itself back.
        sync_start_time = time.time()

        logger.info(
            LogContext(operation_id, self.__feed_name__, None).format_msg(
                "Starting feed sync"
            )
        )

        # Only iterate thru what was fetched
        for group_download_result in filter(
            # if `group` is none or empty string OR if `group` matches the name attribute in group download result
            lambda x: x.feed == self.__feed_name__ and (not group or group == x.name),
            fetched_data.metadata.download_result.results,
        ):
            self._log_context = LogContext(
                operation_id, group_download_result.feed, group_download_result.group
            )
            logger.info(
                self._log_context.format_msg(
                    "Processing group for db update",
                )
            )

            try:
                new_data = self._sync_group(
                    group_download_result,
                    full_flush=full_flush,
                    local_repo=fetched_data,
                )  # Each group sync is a transaction
                result.groups.append(new_data)
            except Exception:
                logger.exception(
                    self._log_context.format_msg(
                        "Failed syncing group data",
                    )
                )
                failed_count += 1
                fail_result = GroupSyncResult(group=group_download_result.group)
                result.groups.append(fail_result)

        result.total_time_seconds = time.time() - sync_start_time
        self._update_last_full_sync_timestamp()

        # This is the merge/update only time, not including download time. Caller can compute total from this return value

        if failed_count == 0:
            result.status = "success"

        return result

    def group_by_name(self, group_name: str) -> Optional[FeedGroupMetadata]:
        """
        Gets the metadata record for the group with the given name.

        :param group_name: the name of the group for which to retreive the metadata record
        :type group_name: str
        :return: the metadata record if it exists
        :rtype: Optional[FeedGroupMetadata]
        """
        found = (
            [x for x in self.metadata.groups if x.name == group_name]
            if self.metadata
            else []
        )
        if len(found) > 1:
            logger.warn(
                "Found more than one group with name {} for feed {} in metadata db, not expected. Groups = {}".format(
                    group_name,
                    self.__feed_name__,
                    [g.to_json() for g in self.metadata.groups],
                )
            )
        if found:
            return found[0]
        else:
            return None


class GrypeDBFeedSyncError(Exception):
    pass


class UnexpectedRawGrypeDBFile(GrypeDBFeedSyncError):
    def __init__(self):
        super().__init__(
            "Unexpected Condition: More than one GrypeDB file downloaded during feed sync."
        )


class RefreshTaskCreationError(GrypeDBFeedSyncError):
    def __init__(self, errors: Sequence[Tuple[str, Exception]]):
        self.errors = errors
        super().__init__(
            f"Failed to create {len(self.errors)} RefreshTasks in simple queue."
        )


class GrypeDBStagingFailure(GrypeDBFeedSyncError):
    def __init__(
        self, engine_metadata: GrypeDBEngineMetadata, db_metadata: GrypeDBMetadata
    ):
        super().__init__(
            f"Staging new Grype DB file was unsuccessful. (engine_metadata: {engine_metadata}, db_metadata: {engine_metadata})"
        )


class GrypeDBFeed(LogContextMixin, DataFeed):
    """
    AnchoreServiceFeed used to sync Grype DB data.

    :param metadata: FeedMetadata instance to use to store stateful information about this feed
    :type metadata: Optional[FeedMetadata], defaults to None
    """

    __feed_name__ = "grypedb"
    _cve_key = None

    def __init__(self, metadata: Optional[FeedMetadata] = None):
        """
        Constructor method.
        """
        # The catalog_client is stored with the instance here to to avoid breaking Liskov Substitution Principle.
        # Signatures for overridden methods from superclass should not change in subclass.
        self._catalog_svc_client: Optional[CatalogClient] = None
        super().__init__(metadata=metadata)

    @property
    def _catalog_client(self) -> CatalogClient:
        """
        Getter for catalog client

        :return: catalog client instance
        :rtype: CatalogClient
        """
        if not isinstance(self._catalog_svc_client, CatalogClient):
            logger.debug(
                "Catalog Client not initialized in GrypeDBFeed. Initializing..."
            )
            self._catalog_svc_client = internal_client_for(CatalogClient, userId=None)
        return self._catalog_svc_client

    @staticmethod
    def _get_db_metadata_records(
        db: Session, checksum: Optional[str] = None, active: Optional[bool] = None
    ) -> List[GrypeDBFeedMetadata]:
        """
        Utility Method, queries GrypeDBFeedMetadata and optionally filters on checksum or active attribute.

        :param db: sqlalchemy database session
        :type db: Session
        :param checksum: checksum of the grype db file
        :type checksum: Optional[str], defaults to None
        :param active: whether or not to filter on the active record
        :type active: Optional[bool], defaults to None
        :return: list of GrypeDBFeedMetadata
        :rtype: List[GrypeDBFeedMetadata]
        """
        # sort by created at so the first index would be the correct active one if more than one returned
        results = db.query(GrypeDBFeedMetadata).order_by(
            GrypeDBFeedMetadata.created_at.desc()
        )
        if checksum:
            results = results.filter(GrypeDBFeedMetadata.archive_checksum == checksum)
        if isinstance(active, bool):
            results = results.filter(GrypeDBFeedMetadata.active.is_(active))
        return results.all()

    def record_count(self, group_name: str, db: Session) -> int:
        """
        Returns number of records present in the database for a given group (GrypeDBFeedMetadata records)

        :param group_name: name of the group
        :type group_name: str
        :param db: sqlaclhemy database session
        :type db: Session
        :return: number of records
        :rtype: int
        """
        return len(self._get_db_metadata_records(db))

    def flush_group(self, group_name: str) -> FeedGroupMetadata:
        """
        Flush a specific data group. Do a db flush, but not a commit at the end to keep the transaction open.

        :param group_name: name of group to flush
        :type group_name: str
        :return: db record containing metadata of group flushed
        :rtype: FeedGroupMetadata
        """
        raise NotImplementedError

    def group_by_name(self, group_name: str) -> Optional[FeedGroupMetadata]:
        """
        Gets the metadata record for the group with the given name.

        :param group_name: the name of the group for which to retreive the metadata record
        :type group_name: str
        :return: the metadata record if it exists
        :rtype: Optional[FeedGroupMetadata]
        """
        return None

    def update_counts(self) -> None:
        """
        Self-contained unit of work to update the row counts for each feed group in the feed group metadata
        """
        return

    def flush_all(self) -> FeedMetadata:
        """
        Flush all groups for the feed, unset the last full sync timestamp, but leave metadata records for feed.

        :return: db record containing feed metadata
        :rtype: FeedMetadata
        """
        db = get_session()
        deleted_records = []
        try:
            records = self._get_db_metadata_records(db)
            for record in records:
                deleted_records.append(record.archive_checksum)
                db.delete(record)
            db.refresh(self.metadata)

            # Remove all groups
            self.metadata.groups = []
            self.metadata.last_full_sync = None
            db.commit()
        except Exception:
            db.rollback()
            raise
        catalog_client = self._catalog_client
        for archive_checksum in deleted_records:
            catalog_client.delete_document(self.__feed_name__, archive_checksum)
        return self.metadata

    @staticmethod
    def _enqueue_refresh_tasks(db: Session) -> None:
        """
        Queues a task for refreshing image vulnerabilities report for each image in policy-engine persistence context

        :param db: sqlalchemy database session
        :type db: Session
        """
        logger.debug("Enqueuing image vulnerabilities refresh tasks")
        all_images = db.query(Image.user_id, Image.id, Image.digest).all()

        if not all_images:
            logger.debug("No images in the system to refresh")
            return

        queue_messages = GrypeDBFeed._create_refresh_tasks(
            all_images, MESSAGE_BATCH_SIZE
        )
        q_client = internal_client_for(SimpleQueueClient, None)
        errors = []
        for task in queue_messages:
            try:
                q_client.enqueue(name=IMAGE_VULNERABILITIES_QUEUE, inobj=task.to_json())
            except Exception as err:
                errors.append((task.to_json_str(), err))

        if len(errors) > 0:
            logger.error(
                f"Failed to create/enqueue %d/%d refresh tasks.",
                len(errors),
                len(queue_messages),
            )
            raise RefreshTaskCreationError(errors)

        logger.debug(
            "Queued %d task(s) for %d image(s)", len(queue_messages), len(all_images)
        )

    @staticmethod
    def _create_refresh_tasks(
        all_images: List[Tuple[str, str, str]], batch_size: int = MESSAGE_BATCH_SIZE
    ) -> List[BatchImageVulnerabilitiesQueueMessage]:
        """
        Creates a list of queue messages to be added to the queue. Each queue message is a list of images to be refreshed.
        This is to avoid queue overheads for message per image in a system with a large number of images

        :param all_images: List of tuples where each tuple is (account_id, image_id, image_digest)
        :param batch_size: Number of messages in a batch
        """
        tasks = []

        if not all_images or not isinstance(batch_size, int) or batch_size < 1:
            return tasks

        for start in range(0, len(all_images), batch_size):
            tasks.append(
                BatchImageVulnerabilitiesQueueMessage(
                    messages=[
                        ImageVulnerabilitiesQueueMessage(
                            account_id=account_id,
                            image_id=image_id,
                            image_digest=image_digest,
                        )
                        for account_id, image_id, image_digest in all_images[
                            start : start + batch_size
                        ]
                    ]
                )
            )

        return tasks

    def _switch_active_grypedb(
        self,
        db: Session,
        record: FileData,
        engine_metadata: GrypeDBEngineMetadata,
        db_metadata: GrypeDBMetadata,
    ) -> None:
        """
        Inserts a new active GrypeDBFeedMetadata record. Before doing so, it deletes all inactive records and then
        marks the currently active record as inactive. No more than two GrypeDBFeedMetadata records are persisted at once.

        :param db: sqlalchemy database session
        :type db: Session
        :param record: FileData record retrieved from download.FileListIterator
        :type record: FileData
        :param engine_metadata: metadata from staged Grype DB file
        :type engine_metadata: GrypeDBEngineMetadata
        :param db_metadata: metadata from staged Grype DB file
        :type db_metadata: GrypeDBMetadata
        """
        catalog_client = self._catalog_client

        # delete all records not active
        inactive_records = self._get_db_metadata_records(db, active=False)
        for inactive_record in inactive_records:
            catalog_client.delete_document(
                self.__feed_name__, inactive_record.archive_checksum
            )
            db.delete(inactive_record)

        # search for active and mark inactive
        active_records = self._get_db_metadata_records(db, active=True)
        for active_record in active_records:
            active_record.active = False

        # insert new as active
        object_url = catalog_client.create_raw_object(
            self.__feed_name__, engine_metadata.archive_checksum, record.data
        )
        built_at = rfc3339str_to_datetime(db_metadata.built)
        self.grypedb_meta = GrypeDBFeedMetadata(
            archive_checksum=engine_metadata.archive_checksum,
            db_checksum=engine_metadata.db_checksum,
            schema_version=engine_metadata.grype_db_version,
            object_url=object_url,
            active=True,
            built_at=built_at,
        )
        db.add(self.grypedb_meta)

    @staticmethod
    def _run_grypedb_sync_task(
        db: Session, checksum: str, grype_db_data: bytes
    ) -> None:
        """
        Write the Grype DB to a tar.gz in a temporary directory and pass to GrypeDBSyncManager.
        The GrypeDBSyncManager updates the working copy of GrypeDB on this instance of policy engine.

        :param checksum: grype DB file checksum
        :type checksum: str
        :param grype_db_data: raw tar.gz file data
        :type grype_db_data: bytes
        """
        with GrypeDBStorage() as grypedb_file:
            with grypedb_file.create_file(checksum) as f:
                f.write(grype_db_data)
            GrypeDBSyncManager.run_grypedb_sync(db, grypedb_file.path)

    def _set_group_counts(self, db, source_counts: List[RecordSource]) -> None:
        """
        Uses grype wrapper to query the source counts in the grypedb
        casts these source counts to FeedGroupMetadata and saves it to GrypeDBFeedMetadata groups column
        certain timestamps like the last_sync are not set in this process the first time around because it has not yet
        been set on the GrypeDBFeedMetadata object
        """
        if source_counts and isinstance(source_counts, list):
            groups = []

            for source in source_counts:
                logger.debug(
                    "Adding group %s consisting of %d vulns to GrypeDBFeedMetadata record",
                    source.group,
                    source.count,
                )
                groups.append(
                    APIFeedGroupMetadata(
                        name=source.group,
                        last_sync=self.grypedb_meta.synced_at,
                        created_at=self.grypedb_meta.created_at,
                        updated_at=self.grypedb_meta.last_updated,
                        enabled=True,
                        record_count=source.count,
                    ).to_json()
                )

            self.grypedb_meta.groups = groups
            db.flush()
        else:
            raise ValueError(
                "GrypeDBFeedMetadata type is non iterable and incorrectly set"
            )

    def _update_group_timestamps(self, db):
        """
        Updates the tiemstamps
        """

        if self.grypedb_meta.groups and isinstance(self.grypedb_meta.groups, List):
            # Set last_sync and updated_at on dict so from_json can be used
            groups = []
            for group in self.grypedb_meta.groups:
                groups.append(
                    APIFeedGroupMetadata(
                        name=group["name"],
                        last_sync=self.grypedb_meta.synced_at,
                        created_at=self.grypedb_meta.created_at,
                        updated_at=self.grypedb_meta.last_updated,
                        enabled=True,
                        record_count=group["record_count"],
                    ).to_json()
                )

            self.grypedb_meta.groups = groups

            db.flush()
        else:
            raise ValueError(
                "GrypeDBFeedMetadata type is non iterable and incorrectly set"
            )

    def _process_grype_file_records(
        self,
        db: Session,
        group_download_result: GroupDownloadResult,
        local_repo: Optional[LocalFeedDataRepo],
    ) -> bool:
        """
        Convert the download results for Grype DB into database records and write to the database session.
        Returns true or false based upon whether downloaded db is new or not
        :param db: sqlalchemy database session
        :type db: Session
        :param group_download_result: group download result record to update
        :type group_download_result: GroupDownloadResult
        :param local_repo: LocalFeedDataRepo (disk cache for download results)
        :type local_repo: Optional[LocalFeedDataRepo], defaults to None
        :return: True if new grypedb, false if existing one
        """
        is_new = False
        total_records_updated = 0
        for record in local_repo.read_files(
            group_download_result.feed, group_download_result.group
        ):
            # If we go through two files, then that means the feed service provided two GrypeDB files.
            # This is an unexpected condition.
            if total_records_updated >= 1:
                raise UnexpectedRawGrypeDBFile()
            # Check that the data that we downloaded matches the checksum provided
            checksum = record.metadata["checksum"]
            GrypeDBFile.verify_integrity(record.data, checksum)
            # If there aren't any other database files with the same checksum, then this is a new database file.
            matches = self._get_db_metadata_records(db, checksum)
            if len(matches) == 0:
                # Cache the file to temporary storage
                with GrypeDBStorage() as grypedb_file:
                    with grypedb_file.create_file(checksum) as f:
                        f.write(record.data)
                    logger.info("Staging new Grype DB file for update.")

                    # Call grype-wrapper to stage a db update. Wrapper responds with object containing archive and db checksums.
                    engine_metadata = (
                        GrypeWrapperSingleton.get_instance().stage_grype_db_update(
                            grypedb_file.path,
                            checksum,
                            str(record.metadata["version"]),
                        )
                    )
                    db_metadata = (
                        GrypeWrapperSingleton.get_instance().get_grype_db_metadata(
                            use_staging=True
                        )
                    )

                    # get source counts on grypedb syncing for use upstream. Raise error if it fails
                    self.source_counts = (
                        GrypeWrapperSingleton.get_instance().query_record_source_counts(
                            use_staging=True
                        )
                    )
                    if not self.source_counts:
                        raise GrypeDBStagingFailure(engine_metadata, db_metadata)

                    GrypeWrapperSingleton.get_instance().unstage_grype_db()

                    if engine_metadata and db_metadata:
                        logger.info(
                            "Staging Grype DB was successful. Switching active Grype DB file to new DB."
                        )
                        # Based on the response policy-engine creates an active grypedbfeed record and marks the rest inactive.
                        # Update the database and the catalog with the new Grype DB file.
                        self._switch_active_grypedb(
                            db, record, engine_metadata, db_metadata
                        )
                        is_new = True
                        # Changes are unstaged to allow GrypeDBSyncTask to control swapping of working copy.
                        # GrypeDBSyncTask swaps out working Grype DB on this instance of policy engine
                        # Even if the GrypeDBSyncTask fails, we still want the FeedSync to succeed.
                        # The GrypeDBSyncTask is also registered to a watcher, so it will try to sync again later.
                        try:
                            GrypeDBSyncManager.run_grypedb_sync(db, grypedb_file.path)
                        except GrypeDBSyncError:
                            logger.exception(
                                self._log_context.format_msg(
                                    "Error running GrypeDBSyncTask. Working copy of GrypeDB could not be updated.",
                                )
                            )

                        # best effort at queuing refresh tasks, DO NOT bail on errors
                        try:
                            self._enqueue_refresh_tasks(db)
                        except RefreshTaskCreationError:
                            logger.exception(
                                "Logging and ignoring error queuing report refresh tasks post GrypeDB sync"
                            )
                    else:
                        raise GrypeDBStagingFailure(engine_metadata, db_metadata)
                # Update number of records processed
                total_records_updated += 1
                logger.info(
                    self._log_context.format_msg(
                        "DB Update Progress: %d/%d"
                        % (total_records_updated, group_download_result.total_records)
                    ),
                )
            else:
                # If checksum already exists and  updating, assign to instance variable so timestamps can be updated
                self.grypedb_meta = matches[0]
        else:
            db.commit()
            logger.info(
                self._log_context.format_msg(
                    "DB Update Complete, Progress: %d/%d"
                    % (
                        total_records_updated,
                        group_download_result.total_records,
                    ),
                )
            )

        return is_new

    def _sync_grype_groups(
        self,
        group_download_result: GroupDownloadResult,
        full_flush=False,
        local_repo=None,
    ) -> List[GroupSyncResult]:
        """
        Sync data from download file and update group data

        :param group_download_result: group download result record to update
        :type group_download_result: GroupDownloadResult
        :param full_flush: whether or not to flush out old records before syncing
        :type full_flush: bool, defaults to False
        :param local_repo: LocalFeedDataRepo (disk cache for download results)
        :type local_repo: Optional[LocalFeedDataRepo], defaults to None
        :return: GroupSyncResult as a dict
        :rtype: dict
        """
        results = []

        db = get_session()

        download_started = group_download_result.started.replace(
            tzinfo=datetime.timezone.utc
        )
        sync_started = time.time()

        try:
            if full_flush:
                logger.info(
                    self._log_context.format_msg(
                        "Performing data flush prior to sync as requested",
                    )
                )
                self.flush_all()

            # Iterate thru the records and commit

            logger.info(
                self._log_context.format_msg(
                    "Syncing %d total update records into db"
                    % group_download_result.total_records,
                )
            )
            is_new = self._process_grype_file_records(
                db, group_download_result, local_repo
            )

            logger.debug(
                self._log_context.format_msg(
                    "Updating last sync timestamp to %s" % download_started,
                )
            )

            # process group logic for grype db if it is a new record. Set on metadata record if it is a new record
            # If not new, use grype wrapper to get source counts for existing db
            if is_new:
                source_counts = self.source_counts
                self._set_group_counts(db, source_counts)
            else:
                source_counts = (
                    GrypeWrapperSingleton.get_instance().query_record_source_counts()
                )

            db.commit()
            # There is potential failure-s that could happen when downloading,
            # skipping updating the `last_sync` allows the system to retry
            # if group_download_result.status == "complete":
            #     group_db_obj.last_sync = download_started
            #       TODO update group info here
            # group_db_obj.count = self.record_count(group_db_obj.name, db)
            # db.add(group_db_obj)
            # db.commit()
        except Exception as e:
            logger.exception(
                self._log_context.format_msg(
                    "Error syncing",
                )
            )
            db.rollback()
            raise e
        finally:
            sync_time = time.time() - sync_started
            total_time_seconds = time.time() - download_started.timestamp()
            logger.info(
                self._log_context.format_msg(
                    "Sync to db duration: %d sec" % sync_time,
                )
            )
            logger.info(
                self._log_context.format_msg(
                    "Total sync, including download, duration: {} sec".format(
                        total_time_seconds
                    ),
                )
            )

        for source in source_counts:
            if is_new:
                updated_count = source.count
            else:
                updated_count = 0

            results.append(
                GroupSyncResult(
                    group=source.group,
                    updated_record_count=updated_count,
                    total_time_seconds=total_time_seconds,
                    status="success",
                )
            )

        return results

    def _update_last_full_sync_timestamp(self) -> None:
        """
        Overrides the base class update function to update both the feed last sync, the grype db metadata record, and its groups
        """
        super()._update_last_full_sync_timestamp()
        last_sync = self.metadata.last_full_sync

        db = get_session()

        try:
            if self.grypedb_meta:
                db.refresh(self.grypedb_meta)
            else:
                logger.error("No grypedb meta found to update last sync timestamp")
                raise ValueError("Grype DB Meta not found")

            self.grypedb_meta.synced_at = last_sync
            self._update_group_timestamps(db)
            db.commit()
        finally:
            db.rollback()

    def sync(
        self,
        fetched_data: LocalFeedDataRepo,
        full_flush: bool = False,
        event_client: Optional[CatalogClient] = None,
        operation_id: Optional[str] = None,
        group: Optional[str] = None,
    ) -> FeedSyncResult:
        """
        Sync data with the feed source. This may be *very* slow if there are lots of updates.
        Returns a dict with the following structure:
        {
        'group_name': [ record1, record2, ..., recordN],
        'group_name2': [ record1, record2, ...., recordM],
        ...
        }

        :param fetched_data: disk cache for downloaded data to sync
        :type fetched_data: LocalFeedDataRepo
        :param full_flush: whether or not to flush all records before syncing new ones
        :type full_flush: bool, defaults to False
        :param event_client: catalog client
        :type event_client: Optional[CatalogClient], defaults to None
        :param operation_id: UUID4 hexadeicmal string
        :type operation_id: Optional[str], defaults to None
        :param group: filter for which groups to update
        :type group: Optional[str], defaults to None
        :return: changed data updated in the sync as a list of records
        :rtype: FeedSyncResult
        """
        self._catalog_svc_client = event_client
        result = FeedSyncResult(feed=self.__feed_name__)
        failed_count = 0

        # Each group update is a unique session and can roll itself back.
        sync_start_time = time.time()

        logger.info(
            LogContext(operation_id, self.__feed_name__, None).format_msg(
                "Starting feed sync"
            )
        )

        # Only iterate thru what was fetched
        for group_download_result in filter(
            # if `group` is none or empty string OR if `group` matches the name attribute in group download result
            lambda x: x.feed == self.__feed_name__ and (not group or group == x.name),
            fetched_data.metadata.download_result.results,
        ):
            self._log_context = LogContext(
                operation_id, group_download_result.feed, group_download_result.group
            )
            logger.info(
                self._log_context.format_msg(
                    "Processing group for db update",
                )
            )

            try:
                new_data = self._sync_grype_groups(
                    group_download_result,
                    full_flush=full_flush,
                    local_repo=fetched_data,
                )  # Each group sync is a transaction
                result.groups.extend(new_data)
            except Exception:
                logger.exception(
                    self._log_context.format_msg(
                        "Failed syncing group data",
                    )
                )
                failed_count += 1
                fail_result = GroupSyncResult(group=group_download_result.group)
                result.groups.append(fail_result)

        result.total_time_seconds = time.time() - sync_start_time
        self._update_last_full_sync_timestamp()

        # This is the merge/update only time, not including download time. Caller can compute total from this return value

        if failed_count == 0:
            result.status = "success"

        return result


class VulnerabilityFeed(AnchoreServiceFeed):
    """
    Vulnerabilities feed from anchore feed service backend. Unique in that the records are nested and have structure.
    Each vulnerability record maps to a set of records in the DB: one for the vulnerability and a set for each of the FixedIn and
    VulnerableIn collections that are optionally present for the vulnerability main record.

    """

    __feed_name__ = "vulnerabilities"
    _cve_key = "Name"
    __group_data_mappers__ = SingleTypeMapperFactory(
        __feed_name__, VulnerabilityFeedDataMapper, _cve_key
    )
    __vuln_processing_fn__ = process_updated_vulnerability
    __flush_helper_fn__ = flush_vulnerability_matches

    def _process_group_file_records(
        self,
        db: Session,
        group_download_result: GroupDownloadResult,
        group_obj: FeedGroupMetadata,
        local_repo: Optional[LocalFeedDataRepo],
    ) -> int:
        """
        Convert the download results for a feed group into database records and write to the database session.
        Transactions are batched by the integer specified in AnchoreServiceFeed.RECORDS_PER_CHUNK, so a commit only
        occurs once for every chunk. The transaction can be rolled back in _sync_group() for a specific chunk if an
        exception is encountered.
        :param db: sqlalchemy database session
        :type db: Session
        :param group_download_result: group download result record to update
        :type group_download_result: GroupDownloadResult
        :param group_obj: metadata record for this feed group
        :type group_obj: FeedGroupMetadata
        :param local_repo: LocalFeedDataRepo (disk cache for download results)
        :type local_repo: Optional[LocalFeedDataRepo], defaults to None
        :return: int
        :rtype: total number of records updated
        """
        total_records_updated = 0
        mapper = self._load_mapper(group_obj)
        # Iterate thru the records and commit
        count = 0
        for record in local_repo.read(
            group_download_result.feed, group_download_result.group, 0
        ):
            mapped = mapper.map(record)
            updated_image_ids = self.update_vulnerability(
                db,
                mapped,
                vulnerability_processing_fn=VulnerabilityFeed.__vuln_processing_fn__,
            )
            db.merge(mapped)
            total_records_updated += 1
            count += 1

            if len(updated_image_ids) > 0:
                db.flush()  # Flush after every one so that mem footprint stays small if lots of images are updated

            if count >= self.RECORDS_PER_CHUNK:
                # Commit
                group_obj.count = self.record_count(group_obj.name, db)
                db.commit()
                logger.info(
                    self._log_context.format_msg(
                        "DB Update Progress: {}/{}".format(
                            total_records_updated,
                            group_download_result.total_records,
                        ),
                    )
                )
                db = get_session()
                count = 0

        else:
            group_obj.count = self.record_count(group_obj.name, db)
            db.commit()
            logger.info(
                self._log_context.format_msg(
                    "DB Update Progress: {}/{}".format(
                        total_records_updated,
                        group_download_result.total_records,
                    ),
                )
            )
        return total_records_updated

    @staticmethod
    def _are_match_equivalent(vulnerability_a, vulnerability_b):
        """
        Returns true if the two records (including child fixedin and/or vulnerablein records) are equivalent in terms of package matching.

        TODO: move this logic to an vuln-scan abstraction, but that abstraction needs more work before it's ready. Would like to keep the definition of what impacts matches centralized so as not to get out-of-sync.

        :param vulnerability_a:
        :param vulnerability_b:
        :return:
        """

        if (
            not (vulnerability_a and vulnerability_b)
            or vulnerability_a.id != vulnerability_b.id
            or vulnerability_a.namespace_name != vulnerability_b.namespace_name
        ):
            # They aren't the same item reference
            logger.debug(
                "Vuln id or namespaces are different: {} {} {} {}".format(
                    vulnerability_a.id,
                    vulnerability_b.id,
                    vulnerability_a.namespace_name,
                    vulnerability_b.namespace_name,
                )
            )
            return False

        normalized_fixes_a = {
            (fix.name, fix.epochless_version, fix.version)
            for fix in vulnerability_a.fixed_in
        }
        normalized_fixes_b = {
            (fix.name, fix.epochless_version, fix.version)
            for fix in vulnerability_b.fixed_in
        }

        fix_diff = normalized_fixes_a.symmetric_difference(normalized_fixes_b)
        if fix_diff:
            logger.debug("Fixed In records diff: {}".format(fix_diff))
            return False

        return True

    @staticmethod
    def update_vulnerability(
        db, vulnerability_record, vulnerability_processing_fn=None
    ):
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
                existing = (
                    db.query(Vulnerability)
                    .filter(
                        Vulnerability.id == vulnerability_record.id,
                        Vulnerability.namespace_name
                        == vulnerability_record.namespace_name,
                    )
                    .one_or_none()
                )
            except Exception:
                logger.debug(
                    "No current record found for {}".format(vulnerability_record)
                )
                existing = None

            if existing:
                needs_update = not VulnerabilityFeed._are_match_equivalent(
                    existing, vulnerability_record
                )
                if needs_update:
                    logger.debug(
                        "Found update that requires an image match update from {} to {}".format(
                            existing, vulnerability_record
                        )
                    )
            else:
                needs_update = True

            merged = db.merge(vulnerability_record)

            if vulnerability_processing_fn and needs_update:
                updates = vulnerability_processing_fn(db, merged)
            else:
                logger.debug(
                    "Skipping image processing due to no diff: {}".format(merged)
                )

            return updates
        except Exception as e:
            logger.exception("Error in vulnerability processing")
            raise e

    def _flush_group(self, group_obj):
        logger.info(
            self._log_context.format_msg(
                "Flushing group records",
            )
        )

        db = get_session()

        VulnerabilityFeed.__flush_helper_fn__(
            db=db, feed_name=group_obj.feed_name, group_name=group_obj.name
        )

        count = (
            db.query(FixedArtifact)
            .filter(FixedArtifact.namespace_name == group_obj.name)
            .delete()
        )
        logger.info(
            self._log_context.format_msg(
                "Flushed {} fix records".format(count),
            )
        )
        count = (
            db.query(VulnerableArtifact)
            .filter(VulnerableArtifact.namespace_name == group_obj.name)
            .delete()
        )
        logger.info("Flushed %s vuln artifact records", count)
        count = (
            db.query(Vulnerability)
            .filter(Vulnerability.namespace_name == group_obj.name)
            .delete()
        )
        logger.info(
            self._log_context.format_msg(
                "Flushed {} vulnerability records".format(count),
            )
        )
        group_obj.last_sync = None  # Null the update timestamp to reflect the flush
        group_obj.count = 0

        db.flush()

    def sync(
        self,
        fetched_data: LocalFeedDataRepo,
        full_flush: bool = False,
        event_client: CatalogClient = None,
        operation_id=None,
        group=None,
    ) -> FeedSyncResult:
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

        if self.metadata and self.metadata.groups:
            # Setup the group name cache
            ThreadLocalFeedGroupNameCache.add(
                [(x.name, x.enabled) for x in self.metadata.groups]
            )
        else:
            ThreadLocalFeedGroupNameCache.flush()

        try:
            return super().sync(
                fetched_data,
                full_flush,
                event_client,
                operation_id=operation_id,
                group=group,
            )
        finally:
            ThreadLocalFeedGroupNameCache.flush()

    def record_count(self, group_name, db):
        try:
            return (
                db.query(Vulnerability)
                .filter(Vulnerability.namespace_name == group_name)
                .count()
            )
        except Exception:
            logger.exception(
                "Error getting feed data group record count in package feed for group: {}".format(
                    group_name
                )
            )
            raise


class PackagesFeed(AnchoreServiceFeed):
    """
    Feed for package data, served from the anchore feed service backend
    """

    __feed_name__ = "packages"

    __group_data_mappers__ = MultiTypeMapperFactory(
        __feed_name__, {"gem": GemPackageDataMapper, "npm": NpmPackageDataMapper}, None
    )

    @staticmethod
    def _dedup_data_key(item):
        return item.name

    def record_count(self, group_name, db):
        try:
            if group_name == "npm":
                return db.query(NpmMetadata).count()
            elif group_name == "gem":
                return db.query(GemMetadata).count()
            else:
                return 0
        except Exception:
            logger.exception(
                "Error getting feed data group record count in package feed for group: {}".format(
                    group_name
                )
            )
            raise

    def _flush_group(self, group_obj):
        db = get_session()

        if self.__flush_helper_fn__:
            self.__flush_helper_fn__(
                db=db, feed_name=group_obj.feed_name, group_name=group_obj.name
            )

        if group_obj.name == "npm":
            ent_cls = NpmMetadata
        elif group_obj.name == "gem":
            ent_cls = GemMetadata
        else:
            logger.info(
                self._log_context.format_msg(
                    "Unknown group name {}. Nothing to flush".format(group_obj.name),
                )
            )
            return

        count = db.query(ent_cls).delete()
        logger.info(
            self._log_context.format_msg(
                "Flushed {} records".format(count, group_obj.name),
            )
        )

        group_obj.last_sync = None
        group_obj.count = 0
        db.flush()


class NvdV2Feed(AnchoreServiceFeed):
    """
    Feed for package data, served from the anchore feed service backend
    """

    __feed_name__ = "nvdv2"
    _cve_key = "id"
    __group_data_mappers__ = SingleTypeMapperFactory(
        __feed_name__, NvdV2FeedDataMapper, _cve_key
    )

    def _flush_group(self, group_obj):
        db = get_session()

        if self.__flush_helper_fn__:
            self.__flush_helper_fn__(
                db=db, feed_name=group_obj.feed_name, group_name=group_obj.name
            )

        count = (
            db.query(CpeV2Vulnerability)
            .filter(CpeV2Vulnerability.namespace_name == group_obj.name)
            .delete()
        )
        logger.info(
            self._log_context.format_msg(
                "Flushed {} CpeV2Vuln records".format(count),
            )
        )
        count = (
            db.query(NvdV2Metadata)
            .filter(NvdV2Metadata.namespace_name == group_obj.name)
            .delete()
        )
        logger.info(
            self._log_context.format_msg(
                "Flushed {} NvdV2 records".format(count),
            )
        )

        group_obj.last_sync = None
        group_obj.count = 0
        db.flush()

    def record_count(self, group_name, db):
        try:
            return (
                db.query(NvdV2Metadata)
                .filter(NvdV2Metadata.namespace_name == group_name)
                .count()
            )
        except Exception:
            logger.exception(
                "Error getting feed data group record count in package feed for group: {}".format(
                    group_name
                )
            )
            raise


class NvdFeed(AnchoreServiceFeed):
    """
    Legacy NVD feed, no longer used. Replaced by NVDv2. This is added back in to support clean removal of those records.

    Feed for package data, served from the anchore feed service backend
    """

    __feed_name__ = "nvd"
    _cve_key = "@id"
    __group_data_mappers__ = MultiTypeMapperFactory(__feed_name__, {}, None)

    def sync(
        self,
        fetched_data: LocalFeedDataRepo,
        full_flush: bool = False,
        event_client: CatalogClient = None,
        operation_id=None,
        group=None,
    ) -> FeedSyncResult:
        logger.warn("Sync not supported for legacy nvd feed")
        result = FeedSyncResult(feed="nvd")
        return result

    def _flush_group(self, group_obj):
        db = get_session()

        if self.__flush_helper_fn__:
            self.__flush_helper_fn__(
                db=db, feed_name=group_obj.feed_name, group_name=group_obj.name
            )

        count = (
            db.query(CpeVulnerability)
            .filter(CpeVulnerability.namespace_name == group_obj.name)
            .delete()
        )
        logger.info(
            self._log_context.format_msg(
                "Flushed {} CpeVulnerability records".format(count),
            )
        )
        count = (
            db.query(NvdMetadata)
            .filter(NvdMetadata.namespace_name == group_obj.name)
            .delete()
        )
        logger.info(
            self._log_context.format_msg(
                "Flushed {} Nvddb records".format(count),
            )
        )

        db.flush()

    def record_count(self, group_name, db):
        try:
            if "nvddb" in group_name:
                return (
                    db.query(NvdMetadata)
                    .filter(NvdMetadata.namespace_name == group_name)
                    .count()
                )
            else:
                return 0
        except Exception:
            logger.exception(
                "Error getting feed data group record count in package feed for group: {}".format(
                    group_name
                )
            )
            raise


class VulnDBFeed(AnchoreServiceFeed):
    """
    Feed for VulnDB data served from on-prem enterprise feed service
    """

    __feed_name__ = "vulndb"
    _cve_key = "id"
    __group_data_mappers__ = SingleTypeMapperFactory(
        __feed_name__, VulnDBFeedDataMapper, _cve_key
    )

    def _flush_group(self, group_obj):
        db = get_session()

        if self.__flush_helper_fn__:
            self.__flush_helper_fn__(
                db=db, feed_name=group_obj.feed_name, group_name=group_obj.name
            )

        count = (
            db.query(VulnDBCpe)
            .filter(VulnDBCpe.namespace_name == group_obj.name)
            .delete()
        )
        logger.info(
            self._log_context.format_msg(
                "Flushed {} VulnDBCpe records".format(count),
            )
        )
        count = (
            db.query(VulnDBMetadata)
            .filter(VulnDBMetadata.namespace_name == group_obj.name)
            .delete()
        )
        logger.info(
            self._log_context.format_msg(
                "Flushed {} VulnDBMetadata records".format(count),
            )
        )

        group_obj.last_sync = None
        group_obj.count = 0
        db.flush()

    def record_count(self, group_name, db):
        try:
            return (
                db.query(VulnDBMetadata)
                .filter(VulnDBMetadata.namespace_name == group_name)
                .count()
            )
        except Exception:
            logger.exception(
                "Error getting feed data group record count in vulndb feed for group: {}".format(
                    group_name
                )
            )
            raise


class GithubFeed(VulnerabilityFeed):
    """
    Feed for the Github Advisories data
    """

    __feed_name__ = "github"
    _cve_key = "id"
    __group_data_mappers__ = SingleTypeMapperFactory(
        __feed_name__, GithubFeedDataMapper, _cve_key
    )


def feed_instance_by_name(name: str) -> DataFeed:
    """
    Returns an instance of the feed using the given name, raises KeyError if name not found

    :param name:
    :return:
    """
    return feed_registry.get(name)()


class FeedRegistry(object):
    """
    Registry for feed classes to facilitate lookups etc. Adapted from the metaclass approach but more explicit
    """

    def __init__(self):
        self.registry = {}

    def register(self, feed_cls, is_vulnerability_feed=False):
        """
        Register the class. The class must have a __feed_name__ class attribute for the lookup

        :param feed_cls:
        :param is_vulnerability_feed: indicates this feed provides distro-level vulnerability info, necessary for determining which feeds to check for vuln info
        :return:
        """

        feed = feed_cls.__feed_name__.lower()
        self.registry[feed] = (feed_cls, is_vulnerability_feed)

    def get(self, name: str):
        """
        Lookup a feed class by the feed's name, matched against the __feed_name__ attribute of the feed class.

        Match is done case-insensitive

        :param name:
        :return:
        """
        # Try direct name
        return self.registry[name.lower()][0]

    def registered_feed_names(self):
        return list(self.registry.keys())

    def registered_vulnerability_feed_names(self):
        return [x[0] for x in self.registry.items() if x[1][1] is True]


# The global registry
feed_registry = FeedRegistry()


def have_vulnerabilities_for(distro_namespace_obj):
    """
    Does the system have any vulnerabilities for the given distro.

    :param distro_namespace_obj:
    :return: boolean
    """

    # All options are the same, no need to loop
    # Check all options for distro/flavor mappings
    db = get_session()
    for namespace_name in distro_namespace_obj.like_namespace_names:
        for vuln_feed in feed_registry.registered_vulnerability_feed_names():
            feed = get_feed_json(db_session=db, feed_name=vuln_feed)
            if feed and namespace_name in [x["name"] for x in feed.get("groups", [])]:
                # No records yet, but we have the feed, so may just not have any data yet
                return True
    else:
        return False
