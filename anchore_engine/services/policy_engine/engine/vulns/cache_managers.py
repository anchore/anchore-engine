import datetime
import enum
import hashlib
import json

from anchore_engine import utils
from anchore_engine.clients.services import internal_client_for, catalog
from anchore_engine.db import (
    Image,
    get_thread_scoped_session as get_session,
    CachedVulnerabilities,
)
from anchore_engine.services.policy_engine.engine.feeds.db import get_all_feeds
from anchore_engine.subsys import logger as log, metrics


class CacheStatus(enum.Enum):
    valid = "valid"
    stale = "stale"
    invalid = "invalid"
    missing = "missing"


class VulnerabilitiesCacheManager:

    __cache_bucket__ = "policy-engine-vulns-cache"

    def __init__(
        self,
        image_object: Image,
        storage_conn_timeout=-1,
        storage_read_timeout=-1,
    ):
        self.image = image_object

        self._catalog_client = internal_client_for(
            catalog.CatalogClient, userId=self.image.user_id
        )
        self._default_catalog_conn_timeout = storage_conn_timeout
        self._default_catalog_read_timeout = storage_read_timeout
        self.cache_key = self._compute_cache_key()

    def refresh(self):
        """
        Refreshes the cache state (not entry) for this initialized request.

        Has stateful side-effects of flushing objects from cache if determined to be invalid

        If a valid entry exists, it is loaded, if an invalid entry exists it is deleted

        :return:
        """
        session = get_session()
        match = None
        for result in self._lookup():
            if self._should_evaluate(result) != CacheStatus.valid:
                self._delete_entry(result)
            else:
                match = result

        session.flush()

        if match:
            if match.is_archive_ref():
                bucket, key = match.archive_tuple()
                try:
                    with self._catalog_client.timeout_context(
                        self._default_catalog_conn_timeout,
                        self._default_catalog_read_timeout,
                    ) as timeout_client:
                        data = timeout_client.get_document(bucket, key)
                except:
                    log.exception(
                        "Unexpected error getting document {}/{} from archive".format(
                            bucket, key
                        )
                    )
                    data = None
            else:
                data = match.result.get("result")
        else:
            data = None

        return data

    def _lookup(self):
        """
        Returns all entries for the image

        :return:
        """

        session = get_session()
        return (
            session.query(CachedVulnerabilities)
            .filter_by(account_id=self.image.user_id, image_digest=self.image.digest)
            .all()
        )

    def _should_evaluate(self, cache_entry: CachedVulnerabilities):
        """
        Decodes the cache key into elements capturing state of the system at the time of report generation and compares
        them to the current current state of the system. Returns true if they don't match to indicate that a new report
        must be generated, false otherwise
        """

        if cache_entry is None:
            metrics.counter_inc(name="anchore_vulnerabilities_cache_misses_notfound")
            return CacheStatus.missing

        if not cache_entry.cache_key:
            log.warn(
                "Unexpectedly got a cached report without a cache key, could be generated before the system was properly initialized"
            )
            metrics.counter_inc(name="anchore_vulnerabilities_cache_misses_invalid")
            return CacheStatus.invalid

        # The cached result is not for this exact grype-db, so result is invalid
        if cache_entry.cache_key != self.cache_key:
            log.debug("Got a stale cached vulns report")
            metrics.counter_inc(name="anchore_vulnerabilities_cache_misses_stale")
            return CacheStatus.stale
        else:
            return CacheStatus.valid

    def _compute_cache_key(self):
        raise NotImplementedError(
            "Function invoked on generic base class, use context specific cache managers"
        )

    def _delete_entry(self, entry):
        session = get_session()

        if entry.is_archive_ref():
            bucket, key = entry.archive_tuple()
            retry = 3
            while retry > 0:
                try:
                    with self._catalog_client.timeout_context(
                        self._default_catalog_conn_timeout,
                        self._default_catalog_read_timeout,
                    ) as timeout_client:
                        resp = timeout_client.delete_document(bucket, key)
                    break
                except:
                    log.exception(
                        "Could not delete policy eval from cache, will retry. Bucket={}, Key={}".format(
                            bucket, key
                        )
                    )
                    retry -= 1
            else:
                log.error(
                    "Could not flush policy eval from cache after all retries, may be orphaned. Will remove from index."
                )

        session.delete(entry)
        session.flush()

    def flush(self):
        """
        Flush all cache entries for the given image
        :return:
        """
        session = get_session()
        for entry in session.query(CachedVulnerabilities).filter_by(
            account_id=self.image.user_id, image_idgest=self.image.digest
        ):
            try:
                self._delete_entry(entry)
            except:
                log.exception("Could not delete vuln cache entry: {}".format(entry))

        return True

    def save(self, result, cache_key=None):
        """
        Persist the new result for this cache entry
        """
        report = CachedVulnerabilities()
        report.account_id = self.image.user_id
        report.image_digest = self.image.digest
        report.cache_key = cache_key if cache_key else self.cache_key

        # Send to archive
        key = (
            "sha256:"
            + hashlib.sha256(utils.ensure_bytes(str(report.key_tuple()))).hexdigest()
        )
        with self._catalog_client.timeout_context(
            self._default_catalog_conn_timeout, self._default_catalog_read_timeout
        ) as timeout_client:
            resp = timeout_client.put_document(self.__cache_bucket__, key, result)

        if not resp:
            raise Exception("Failed cache write to archive store")

        str_result = json.dumps(result, sort_keys=True)
        result_digest = (
            "sha256:" + hashlib.sha256(utils.ensure_bytes(str_result)).hexdigest()
        )

        report.add_remote_result(self.__cache_bucket__, key, result_digest)
        report.last_modified = datetime.datetime.utcnow()

        # Update index
        session = get_session()
        return session.merge(report)


class LegacyCacheManager(VulnerabilitiesCacheManager):
    """
    Cache manager for vulnerability reports generated by the legacy system using internal feeds.
    Employs feed sync timestamp as the cache key
    """

    def _compute_cache_key(self):
        """
        Cache key is the timestamp of the most recently updated feed
        """

        db = get_session()
        feed_group_updated_list = [
            group.last_sync
            if group and group.last_sync
            else datetime.datetime.utcfromtimestamp(0)
            for feed in get_all_feeds(db)
            for group in feed.groups
        ]

        return (
            max(feed_group_updated_list).isoformat()
            if feed_group_updated_list
            else datetime.datetime.utcfromtimestamp(0).isoformat()
        )


class GrypeCacheManager(VulnerabilitiesCacheManager):
    """
    Cache manager for vulnerability reports generated by grype. Employs grype-db checksum as the cache key
    """

    def _compute_cache_key(self):
        """
        Cache key is the grype-db checksum
        """
        return "foo"  # TODO call grype facade for current grype-db checksum and or version as necessary


cache_manager = LegacyCacheManager


def get_cache_manager(img, conn_timeout, read_timeout):
    return cache_manager(img, conn_timeout, read_timeout)
