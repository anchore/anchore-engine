import datetime
import time

from anchore_engine.clients.services.catalog import CatalogClient
from anchore_engine.db import (
    get_thread_scoped_session as get_session,
    FeedMetadata,
    GenericFeedDataRecord,
    FeedGroupMetadata,
    ImagePackageVulnerability,
    Vulnerability,
    FixedArtifact,
    GemMetadata,
    NpmMetadata,
    NvdV2Metadata,
    CpeV2Vulnerability,
    VulnDBMetadata,
    VulnDBCpe,
    VulnerableArtifact,
    get_thread_scoped_session,
    NvdMetadata,
    CpeVulnerability,
)

from anchore_engine.common.schemas import (
    DownloadOperationConfiguration,
    GroupDownloadResult,
    GroupDownloadOperationParams,
)
from anchore_engine.services.policy_engine.engine.feeds.download import (
    LocalFeedDataRepo,
)
from anchore_engine.services.policy_engine.engine.feeds.mappers import (
    GenericFeedDataMapper,
    SingleTypeMapperFactory,
    VulnerabilityFeedDataMapper,
    GemPackageDataMapper,
    NpmPackageDataMapper,
    NvdV2FeedDataMapper,
    VulnDBFeedDataMapper,
    GithubFeedDataMapper,
)
from anchore_engine.services.policy_engine.engine.feeds import mappers
from anchore_engine.services.policy_engine.engine.vulnerabilities import (
    process_updated_vulnerability,
    flush_vulnerability_matches,
    ThreadLocalFeedGroupNameCache,
)
from anchore_engine.subsys.events import (
    FeedGroupSyncStarted,
    FeedGroupSyncCompleted,
    FeedGroupSyncFailed,
    EventBase,
)
from anchore_engine.services.policy_engine.engine.feeds.db import (
    lookup_feed,
    get_feed_json,
)
from anchore_engine.subsys import logger


def build_group_sync_result(group=None, status="failure"):
    return {
        "group": group,
        "status": status,
        "total_time_seconds": 0,
        "updated_record_count": 0,
        "updated_image_count": 0,
    }


def build_feed_sync_results(feed=None, status="failure"):
    return {"feed": feed, "status": status, "total_time_seconds": 0, "groups": []}


class DataFeed(object):
    """
    Interface for a data feed. A DataFeed is a combination of a means to connect to the feed, metadata about the feed actions
    locally, and mapping data ingesting the feed data itself.

    """

    __feed_name__ = None
    __group_data_mappers__ = None  # A dict/map of group names to mapper objects for translating group data into db types

    def __init__(self, metadata: FeedMetadata):
        """
        Instantiates any necessary clients and makes the feed ready to use
        :param metadata: an existing metadata record if available for bootstrapping
        :param src: an object to use as the feed source. if not provided then the class's __source_cls__ definition is used
        """
        self.metadata = metadata

    def sync(
        self,
        fetched_data: LocalFeedDataRepo,
        full_flush: bool = False,
        event_client: CatalogClient = None,
        operation_id=None,
        group=None,
    ) -> dict:
        """
        Ensure the feed is synchronized. Performs checks per sync item and if item_processing_fn is provided.
        Transaction scope is the update for an entire group.

        item_processing_fn is exepected to be a function that can consume a db session but should *NOT* commit or rollback the session. The caller will handle that to properly maintain
        session scope to each item to be updated.

        :param fetched_data: the local data repo
        :param full_flush: Remove any old data from the feed and replace with new sync data
        :param operation_id: uuid of the sync operation, mostly for logging usage
        :return: list of updated records added to the database
        """
        raise NotImplementedError()

    def record_count(self, group_name, db):
        """
        :param group_name: Name of group to get count for
        :param db: db session to use
        :return:
        """
        raise NotImplementedError()

    def update_counts(self):
        raise NotImplementedError()

    def flush_group(self, group_name):
        """
        Flushes data out of a specific group. Does not remove the group metadata record, but will set the count to zero.
        This is a db unit-of-work. Will create transaction and commit result

        :param group_name:
        :return: True on success
        """
        raise NotImplementedError()

    def flush_all(self):
        """
        Flush all groups for the feed, unset the last full sync timestamp, but leave metadata records for feed.

        :return:
        """
        raise NotImplementedError()


class AnchoreServiceFeed(DataFeed):
    """
    A data feed provided by the Anchore Feeds service.

    Metadata persisted in the backing db.
    Instance load will fire a load from the db to get the latest metadata in db, and sync
    operations will sync data and metadata from the upstream service.
    """

    __group_data_mappers__ = GenericFeedDataMapper
    __flush_helper_fn__ = None

    RECORDS_PER_CHUNK = 500

    def __init__(self, metadata=None):
        if not metadata:
            db = get_session()
            metadata = lookup_feed(db, self.__feed_name__)
            if not metadata:
                raise Exception(
                    "Must have feed metadata in db already, should sync metadata before invoking instance operations"
                )

        super(AnchoreServiceFeed, self).__init__(metadata=metadata)

    def record_count(self, group_name, db):
        # Implement in subclasses
        raise NotImplementedError()

    def update_counts(self):
        """
        Self-contained unit of work to update the row counts for each feed group in the feed group metadata
        :return:
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

    def _load_mapper(self, group_obj):
        """
        Find and instantiate the right mapper object for the given group.

        :param group_obj:
        :return:
        """
        if not hasattr(self.__class__.__group_data_mappers__, "get"):
            mapper = self.__class__.__group_data_mappers__
        else:
            mapper = self.__class__.__group_data_mappers__.get(group_obj.name)

        if not mapper:
            raise Exception(
                "No mapper class found for group: {}".format(group_obj.name)
            )

            # If it's a class, instantiate it
        if type(mapper) == type:
            mapper = mapper(self.__feed_name__, group_obj.name, keyname=None)

        return mapper

    def _sync_group(
        self,
        group_download_result: GroupDownloadResult,
        full_flush=False,
        local_repo=None,
        operation_id=None,
    ):
        """
        Sync data from a single group and return the data. This operation is scoped to a transaction on the db.

        :param group_obj:
        :return:
        """
        total_updated_count = 0
        result = build_group_sync_result()
        result["group"] = group_download_result.group
        sync_started = None

        db = get_session()
        group_db_obj = None
        if self.metadata:
            db.refresh(self.metadata)
            group_db_obj = self.group_by_name(group_download_result.group)

        if not group_db_obj:
            logger.error(
                log_msg_ctx(
                    operation_id,
                    group_download_result.feed,
                    group_download_result.group,
                    "Skipping sync for feed group {}, not found in db, record should have been synced already",
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
                    log_msg_ctx(
                        operation_id,
                        group_download_result.feed,
                        group_download_result.group,
                        "Performing data flush prior to sync as requested",
                    )
                )
                self._flush_group(group_db_obj, operation_id=operation_id)

            mapper = self._load_mapper(group_db_obj)

            # Iterate thru the records and commit

            logger.info(
                log_msg_ctx(
                    operation_id,
                    group_download_result.feed,
                    group_download_result.group,
                    "Syncing {} total update records into db in sets of {}".format(
                        group_download_result.total_records, self.RECORDS_PER_CHUNK
                    ),
                )
            )
            count = 0
            for record in local_repo.read(
                group_download_result.feed, group_download_result.group, 0
            ):
                mapped = mapper.map(record)
                merged = db.merge(mapped)
                total_updated_count += 1
                count += 1

                if count >= self.RECORDS_PER_CHUNK:
                    # Commit
                    group_db_obj.count = self.record_count(group_db_obj.name, db)
                    db.commit()
                    db = get_session()
                    logger.info(
                        log_msg_ctx(
                            operation_id,
                            group_download_result.feed,
                            group_download_result.group,
                            "DB Update Progress: {}/{}".format(
                                total_updated_count, group_download_result.total_records
                            ),
                        )
                    )
                    count = 0

            else:
                group_db_obj.count = self.record_count(group_db_obj.name, db)
                db.commit()
                db = get_session()
                logger.info(
                    log_msg_ctx(
                        operation_id,
                        group_download_result.feed,
                        group_download_result.group,
                        "DB Update Progress: {}/{}".format(
                            total_updated_count, group_download_result.total_records
                        ),
                    )
                )

            logger.debug(
                log_msg_ctx(
                    operation_id,
                    group_download_result.feed,
                    group_download_result.group,
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
                log_msg_ctx(
                    operation_id,
                    group_download_result.feed,
                    group_download_result.group,
                    "Error syncing",
                )
            )
            db.rollback()
            raise e
        finally:
            sync_time = time.time() - sync_started
            total_group_time = time.time() - download_started.timestamp()
            logger.info(
                log_msg_ctx(
                    operation_id,
                    group_download_result.feed,
                    group_download_result.group,
                    "Sync to db duration: {} sec".format(sync_time),
                )
            )
            logger.info(
                log_msg_ctx(
                    operation_id,
                    group_download_result.feed,
                    group_download_result.group,
                    "Total sync, including download, duration: {} sec".format(
                        total_group_time
                    ),
                )
            )

        result["updated_record_count"] = total_updated_count
        result["status"] = "success"
        result["total_time_seconds"] = total_group_time
        result["updated_image_count"] = 0
        return result

    def _flush_group(self, group_obj, operation_id=None):
        """
        Flush a specific data group. Do a db flush, but not a commit at the end to keep the transaction open.

        :param group_obj:
        :return:
        """
        db = get_session()

        logger.info(
            log_msg_ctx(
                operation_id,
                group_obj.name,
                group_obj.feed_name,
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

    def flush_group(self, group_name):
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

    def flush_all(self):
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
    ) -> dict:
        """
        Sync data with the feed source. This may be *very* slow if there are lots of updates.

        Returns a dict with the following structure:
        {
        'group_name': [ record1, record2, ..., recordN],
        'group_name2': [ record1, record2, ...., recordM],
        ...
        }

        :param: fetched_data
        :param: full_flush
        :param: event_client
        :param: operation_id
        :return: changed data updated in the sync as a list of records
        """
        result = build_feed_sync_results()
        result["feed"] = self.__feed_name__
        failed_count = 0

        # Each group update is a unique session and can roll itself back.
        t = time.time()

        logger.info(
            log_msg_ctx(operation_id, self.__feed_name__, None, "Starting feed sync")
        )

        # Only iterate thru what was fetched
        for group_download_result in filter(
            lambda x: x.feed == self.__feed_name__ and (not group or group == x.name),
            fetched_data.metadata.download_result.results,
        ):
            logger.info(
                log_msg_ctx(
                    operation_id,
                    group_download_result.feed,
                    group_download_result.group,
                    "Processing group for db update",
                )
            )

            try:
                new_data = self._sync_group(
                    group_download_result,
                    full_flush=full_flush,
                    local_repo=fetched_data,
                    operation_id=operation_id,
                )  # Each group sync is a transaction
                result["groups"].append(new_data)
            except Exception as e:
                logger.exception(
                    log_msg_ctx(
                        operation_id,
                        group_download_result.feed,
                        group_download_result.group,
                        "Failed syncing group data",
                    )
                )
                failed_count += 1
                fail_result = build_group_sync_result()
                fail_result["group"] = group_download_result.group
                result["groups"].append(fail_result)

        sync_time = time.time() - t
        self._update_last_full_sync_timestamp()

        # This is the merge/update only time, not including download time. Caller can compute total from this return value
        result["total_time_seconds"] = sync_time

        if failed_count == 0:
            result["status"] = "success"

        return result

    def _update_last_full_sync_timestamp(self):
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

    def group_by_name(self, group_name):
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

    def _sync_group(
        self,
        group_download_result: GroupDownloadResult,
        full_flush=False,
        local_repo=None,
        operation_id=None,
    ):
        """
        Sync data from a single group and return the data. This operation is scoped to a transaction on the db.

        :param group_download_result
        :return:
        """
        total_updated_count = 0
        result = build_group_sync_result()
        result["group"] = group_download_result.group
        sync_started = None

        db = get_session()
        db.refresh(self.metadata)
        group_db_obj = self.group_by_name(group_download_result.group)

        if not group_db_obj:
            logger.error(
                log_msg_ctx(
                    operation_id,
                    group_download_result.feed,
                    group_download_result.group,
                    "Skipping group sync. Record not found in db, should have been synced already",
                )
            )
            return result

        sync_started = time.time()
        download_started = group_download_result.started.replace(
            tzinfo=datetime.timezone.utc
        )

        try:
            updated_images = (
                set()
            )  # To get unique set of all images updated by this sync

            if full_flush:
                logger.info(
                    log_msg_ctx(
                        operation_id,
                        group_download_result.feed,
                        group_download_result.group,
                        "Performing group data flush prior to sync",
                    )
                )
                self._flush_group(group_db_obj, operation_id=operation_id)

            mapper = self._load_mapper(group_db_obj)

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
                updated_images = updated_images.union(
                    set(updated_image_ids)
                )  # Record after commit to ensure in-sync.
                merged = db.merge(mapped)
                total_updated_count += 1
                count += 1

                if len(updated_image_ids) > 0:
                    db.flush()  # Flush after every one so that mem footprint stays small if lots of images are updated

                if count >= self.RECORDS_PER_CHUNK:
                    # Commit
                    group_db_obj.count = self.record_count(group_db_obj.name, db)
                    db.commit()
                    logger.info(
                        log_msg_ctx(
                            operation_id,
                            group_download_result.feed,
                            group_download_result.group,
                            "DB Update Progress: {}/{}".format(
                                total_updated_count, group_download_result.total_records
                            ),
                        )
                    )
                    db = get_session()
                    count = 0

            else:
                group_db_obj.count = self.record_count(group_db_obj.name, db)
                db.commit()
                logger.info(
                    log_msg_ctx(
                        operation_id,
                        group_download_result.feed,
                        group_download_result.group,
                        "DB Update Progress: {}/{}".format(
                            total_updated_count, group_download_result.total_records
                        ),
                    )
                )
                db = get_session()

            logger.debug(
                log_msg_ctx(
                    operation_id,
                    group_download_result.feed,
                    group_download_result.group,
                    "Updating last sync timestamp to {}".format(download_started),
                )
            )
            group_db_obj = self.group_by_name(group_download_result.group)
            group_db_obj.last_sync = download_started
            group_db_obj.count = self.record_count(group_db_obj.name, db)
            db.add(group_db_obj)
            db.commit()
        except Exception as e:
            logger.exception(
                log_msg_ctx(
                    operation_id,
                    group_download_result.feed,
                    group_download_result.group,
                    "Error syncing group",
                )
            )
            db.rollback()
            raise e
        finally:
            total_group_time = time.time() - download_started.timestamp()
            sync_time = time.time() - sync_started
            logger.info(
                log_msg_ctx(
                    operation_id,
                    group_download_result.feed,
                    group_download_result.group,
                    "Sync to db duration: {} sec".format(sync_time),
                )
            )
            logger.info(
                log_msg_ctx(
                    operation_id,
                    group_download_result.feed,
                    group_download_result.group,
                    "Total sync, including download, duration: {} sec".format(
                        total_group_time
                    ),
                )
            )

        result["updated_record_count"] = total_updated_count
        result["status"] = "success"
        result["total_time_seconds"] = total_group_time
        result["updated_image_count"] = 0
        return result

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

    def update_vulnerability(
        self, db, vulnerability_record, vulnerability_processing_fn=None
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
            except:
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

    def _flush_group(self, group_obj, operation_id=None):
        logger.info(
            log_msg_ctx(
                operation_id,
                group_obj.name,
                group_obj.feed_name,
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
            log_msg_ctx(
                operation_id,
                group_obj.name,
                group_obj.feed_name,
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
            log_msg_ctx(
                operation_id,
                group_obj.name,
                group_obj.feed_name,
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
    ) -> dict:
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
        except Exception as e:
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

    __group_data_mappers__ = {"gem": GemPackageDataMapper, "npm": NpmPackageDataMapper}

    def _dedup_data_key(self, item):
        return item.name

    def record_count(self, group_name, db):
        try:
            if group_name == "npm":
                return db.query(NpmMetadata).count()
            elif group_name == "gem":
                return db.query(GemMetadata).count()
            else:
                return 0
        except Exception as e:
            logger.exception(
                "Error getting feed data group record count in package feed for group: {}".format(
                    group_name
                )
            )
            raise

    def _flush_group(self, group_obj, flush_helper_fn=None, operation_id=None):
        db = get_session()
        if flush_helper_fn:
            flush_helper_fn(
                db=db, feed_name=group_obj.feed_name, group_name=group_obj.name
            )

        if group_obj.name == "npm":
            ent_cls = NpmMetadata
        elif group_obj.name == "gem":
            ent_cls = GemMetadata
        else:
            logger.info(
                log_msg_ctx(
                    operation_id,
                    group_obj.name,
                    group_obj.feed_name,
                    "Unknown group name {}. Nothing to flush".format(group_obj.name),
                )
            )
            return

        count = db.query(ent_cls).delete()
        logger.info(
            log_msg_ctx(
                operation_id,
                group_obj.name,
                group_obj.feed_name,
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

    def _flush_group(self, group_obj, flush_helper_fn=None, operation_id=None):
        db = get_session()
        if flush_helper_fn:
            flush_helper_fn(
                db=db, feed_name=group_obj.feed_name, group_name=group_obj.name
            )

        count = (
            db.query(CpeV2Vulnerability)
            .filter(CpeV2Vulnerability.namespace_name == group_obj.name)
            .delete()
        )
        logger.info(
            log_msg_ctx(
                operation_id,
                group_obj.name,
                group_obj.feed_name,
                "Flushed {} CpeV2Vuln records".format(count),
            )
        )
        count = (
            db.query(NvdV2Metadata)
            .filter(NvdV2Metadata.namespace_name == group_obj.name)
            .delete()
        )
        logger.info(
            log_msg_ctx(
                operation_id,
                group_obj.name,
                group_obj.feed_name,
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
        except Exception as e:
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
    __group_data_mappers__ = {}

    def sync(
        self,
        fetched_data: LocalFeedDataRepo,
        full_flush: bool = False,
        event_client: CatalogClient = None,
        operation_id=None,
        group=None,
    ) -> dict:
        logger.warn("Sync not supported for legacy nvd feed")
        result = build_feed_sync_results(feed="nvd", status="failed")
        result["status"] = "failed"
        return result

    def _flush_group(self, group_obj, flush_helper_fn=None, operation_id=None):

        db = get_session()
        if flush_helper_fn:
            flush_helper_fn(
                db=db, feed_name=group_obj.feed_name, group_name=group_obj.name
            )

        count = (
            db.query(CpeVulnerability)
            .filter(CpeVulnerability.namespace_name == group_obj.name)
            .delete()
        )
        logger.info(
            log_msg_ctx(
                operation_id,
                group_obj.name,
                group_obj.feed_name,
                "Flushed {} CpeVulnerability records".format(count),
            )
        )
        count = (
            db.query(NvdMetadata)
            .filter(NvdMetadata.namespace_name == group_obj.name)
            .delete()
        )
        logger.info(
            log_msg_ctx(
                operation_id,
                group_obj.name,
                group_obj.feed_name,
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

    def _flush_group(self, group_obj, flush_helper_fn=None, operation_id=None):
        db = get_session()

        if flush_helper_fn:
            flush_helper_fn(
                db=db, feed_name=group_obj.feed_name, group_name=group_obj.name
            )

        count = (
            db.query(VulnDBCpe)
            .filter(VulnDBCpe.namespace_name == group_obj.name)
            .delete()
        )
        logger.info(
            log_msg_ctx(
                operation_id,
                group_obj.name,
                group_obj.feed_name,
                "Flushed {} VulnDBCpe records".format(count),
            )
        )
        count = (
            db.query(VulnDBMetadata)
            .filter(VulnDBMetadata.namespace_name == group_obj.name)
            .delete()
        )
        logger.info(
            log_msg_ctx(
                operation_id,
                group_obj.name,
                group_obj.feed_name,
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
        except Exception as e:
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


def notify_event(event: EventBase, client: CatalogClient, operation_id=None):
    """
    Send an event or just log it if client is None
    Always log the event to info level
    """

    if client:
        try:
            client.add_event(event)
        except Exception as e:
            logger.warn("Error adding feed start event: {}".format(e))

    try:
        logger.info("Event: {} (operation_id={})".format(event.to_json(), operation_id))
    except:
        logger.exception("Error logging event")


def log_msg_ctx(operation_id, feed, group, msg):
    return "{} (operation_id={}, feed={}, group={})".format(
        msg, operation_id, feed, group
    )


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
    db = get_thread_scoped_session()
    for namespace_name in distro_namespace_obj.like_namespace_names:
        for vuln_feed in feed_registry.registered_vulnerability_feed_names():
            feed = get_feed_json(db_session=db, feed_name=vuln_feed)
            if feed and namespace_name in [x["name"] for x in feed.get("groups", [])]:
                # No records yet, but we have the feed, so may just not have any data yet
                return True
    else:
        return False
