import dataclasses
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
from anchore_engine.apis.context import ApiRequestContextProxy
from dataclasses import dataclass
from typing import Dict, List
from anchore_engine.services.policy_engine.api.models import ImageVulnerabilitiesReport

# Disabled by default, can be set in config file. Seconds for connection to cache
DEFAULT_CACHE_CONN_TIMEOUT = -1
# Disabled by default, can be set in config file. Seconds for first byte timeout
DEFAULT_CACHE_READ_TIMEOUT = -1


class CacheStatus(enum.Enum):
    valid = "valid"
    stale = "stale"
    invalid = "invalid"
    missing = "missing"


@dataclass
class CacheRecord:
    result: Dict
    status: CacheStatus


@dataclass(eq=True)
class GrypeMetadata:
    version: str
    db_version: str
    db_checksum: str

    @classmethod
    def from_dict(cls, data):
        return GrypeMetadata(
            data.get("version"), data.get("db_version"), data.get("db_checksum")
        )

    def to_dict(self):
        return self.__dict__


class GrypeCacheManager:

    __cache_bucket__ = "policy-engine-vulns-cache"

    def __init__(
        self,
        image_object: Image,
    ):
        self.image = image_object

        self._catalog_client = internal_client_for(
            catalog.CatalogClient, userId=self.image.user_id
        )
        self._default_catalog_conn_timeout = (
            ApiRequestContextProxy.get_service().configuration.get(
                "catalog_client_conn_timeout",
                DEFAULT_CACHE_CONN_TIMEOUT,
            )
        )
        self._default_catalog_read_timeout = (
            ApiRequestContextProxy.get_service().configuration.get(
                "catalog_client_read_timeout",
                DEFAULT_CACHE_READ_TIMEOUT,
            )
        )

    def fetch(self):
        """
        Tries to lookup the cache entry for the image and it's validity if one is available

        """
        session = get_session()
        db_record = (
            session.query(CachedVulnerabilities)
            .filter_by(account_id=self.image.user_id, image_digest=self.image.digest)
            .one_or_none()
        )

        if db_record:
            if db_record.is_archive_ref():
                bucket, key = db_record.archive_tuple()
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
                data = db_record.result.get("result")

            return CacheRecord(result=data, status=self._get_cache_status(db_record))
        else:
            return None

    def _lookup(self):
        """
        Returns all entries for the image

        :return:
        """

        session = get_session()
        return (
            session.query(CachedVulnerabilities)
            .filter_by(account_id=self.image.user_id, image_digest=self.image.digest)
            .order_by(CachedVulnerabilities.last_modified.desc())
            .all()
        )

    def _get_cache_status(self, cache_record: CachedVulnerabilities):
        """
        Decodes the cache key into elements capturing state of the system at the time of report generation and compares
        them to the current current state of the system.
        """
        # TODO polish this
        report_metadata = GrypeMetadata.from_dict(cache_record.cache_key.get("grype"))

        current_metadata = self._get_current_grype_metadata()

        if report_metadata == current_metadata:
            return CacheStatus.valid
        else:
            return CacheStatus.stale

    @staticmethod
    def _get_current_grype_metadata():
        """
        TODO Invoke the grype_wrapper and generate a grype metadata object, work with dspalmer
        """

        return GrypeMetadata("foo", "bar", "sha256:blah")

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
                        "Could not delete vulnerabilities report from cache, will retry. Bucket={}, Key={}".format(
                            bucket, key
                        )
                    )
                    retry -= 1
            else:
                log.error(
                    "Could not flush vulnerabilities report from cache after all retries, may be orphaned. Will remove from index."
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
            account_id=self.image.user_id, image_digest=self.image.digest
        ):
            try:
                self._delete_entry(entry)
            except:
                log.exception("Could not delete vuln cache entry: {}".format(entry))

        return True

    def _get_cache_key_from_report(self, report: ImageVulnerabilitiesReport):
        """
        Parse the report for grype metadata and generate GrypeMetadata object
        """
        # TODO implement this
        return GrypeMetadata("foo", "bar", "sha256:blah").to_dict()

    def save(self, report: ImageVulnerabilitiesReport):
        """
        Persist the new result for this cache entry
        """

        # delete all previous cached results
        self.flush()

        # save the new results as a new entry
        cache_entry = CachedVulnerabilities()
        cache_entry.account_id = self.image.user_id
        cache_entry.image_digest = self.image.digest
        cache_entry.cache_key = {"grype": self._get_cache_key_from_report(report)}

        # save it to db instead of object storage to be able to excute other queries over the data
        cache_entry.add_raw_result(report.to_json())
        # report.add_remote_result(self.__cache_bucket__, key, result_digest)
        cache_entry.last_modified = datetime.datetime.utcnow()

        # Update index
        session = get_session()
        return session.merge(cache_entry)
