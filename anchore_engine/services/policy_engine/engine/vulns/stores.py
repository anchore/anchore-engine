import datetime
import enum
from typing import Dict

import retrying

from anchore_engine.clients.grype_wrapper import GrypeWrapperSingleton
from anchore_engine.db import (
    Image,
    get_thread_scoped_session as get_session,
    ImageVulnerabilitiesReport as DbImageVulnerabilities,
)
from anchore_engine.services.policy_engine.api.models import ImageVulnerabilitiesReport
from anchore_engine.subsys import logger as log

# Disabled by default, can be set in config file. Seconds for connection to store
DEFAULT_STORE_CONN_TIMEOUT = -1
# Disabled by default, can be set in config file. Seconds for first byte timeout
DEFAULT_STORE_READ_TIMEOUT = -1

REPORT_SAVE_RETRIES = 5  # number of save attempts
REPORT_SAVE_WAIT = 1000  # wait between retries in milliseconds


class Status(enum.Enum):
    valid = "valid"
    stale = "stale"
    invalid = "invalid"
    missing = "missing"


class GrypeDBKey:
    """
    A key in the context of the image vulnerabilities store is the information that makes an entry in the store unique.
    The key class has functions for generating an instance from the store's report_key and a ImageVulnerabilitiesReport
    instance. It should also support a function for returning the status of the store entry

    This key is based only on Grype DB details of the generated report.

    To override the behaviour simply create a new key class and assign ImageVulnerabilitiesStore.__report_key_class__
    to the new class
    """

    def __init__(self, db_checksum=None):
        self.db_checksum = db_checksum
        # self.version
        # self.db_version

    @classmethod
    def from_db(cls, report_key: Dict):
        db_checksum = report_key.get("db_checksum") if report_key else None
        if db_checksum:
            return GrypeDBKey(db_checksum=db_checksum)
        else:
            raise ValueError(
                "Invalid or unexpected report_key format {}".format(report_key)
            )

    @classmethod
    def from_report(cls, report: ImageVulnerabilitiesReport):
        # TODO  update this to checksum in the report after grype makes it available
        db_checksum = (
            GrypeWrapperSingleton.get_instance().get_current_grype_db_checksum()
        )
        return GrypeDBKey(db_checksum=db_checksum)

    def to_dict(self):
        return self.__dict__

    def get_report_status(self, report_key: Dict):
        try:
            report_db_checksum = self.from_db(report_key).db_checksum
        except ValueError:
            report_db_checksum = None

        if report_db_checksum:
            # try getting the current active db checksum
            try:
                # TODO  update this to active grypedb lookup after db checksum is available
                active_db_checksum = (
                    GrypeWrapperSingleton.get_instance().get_current_grype_db_checksum()
                )
            except:
                active_db_checksum = None

            if active_db_checksum and active_db_checksum == report_db_checksum:
                status = Status.valid
            else:
                # active db checksum is invalid or doesn't match report's db checksum
                status = Status.expired
        else:
            # report's db checksum can't be parsed, something is really weird. invalidate the report
            status = Status.invalid

        return status


class ImageVulnerabilitiesStore:

    __report_key_class__ = GrypeDBKey

    def __init__(
        self,
        image_object: Image,
    ):
        self.image = image_object

    def fetch(self):
        """
        Tries to find a report for the image and it's validity if one is available

        """
        session = get_session()
        db_record = (
            session.query(DbImageVulnerabilities)
            .filter_by(account_id=self.image.user_id, image_digest=self.image.digest)
            .one_or_none()
        )

        if db_record:
            data = db_record.result.get("result")

            return data, self.__report_key_class__().get_report_status(
                db_record.report_key
            )
        else:
            return None, None

    def _lookup(self):
        """
        Returns all entries for the image

        :return:
        """

        session = get_session()
        return (
            session.query(DbImageVulnerabilities)
            .filter_by(account_id=self.image.user_id, image_digest=self.image.digest)
            .order_by(DbImageVulnerabilities.last_modified.desc())
            .all()
        )

    def delete_all(self):
        """
        Flush all report entries for the given image
        :return:
        """
        session = get_session()
        for entry in session.query(DbImageVulnerabilities).filter_by(
            account_id=self.image.user_id, image_digest=self.image.digest
        ):
            try:
                session.delete(entry)
                session.flush()
            except:
                log.exception("Could not delete vuln store entry: {}".format(entry))

        return True

    @retrying.retry(
        stop_max_attempt_number=REPORT_SAVE_RETRIES, wait_fixed=REPORT_SAVE_WAIT
    )
    def save(self, report: ImageVulnerabilitiesReport):
        """
        Persist the new result to store
        """

        # delete all previous stored results
        self.delete_all()

        # save the new results as a new entry
        db_record = DbImageVulnerabilities()
        db_record.account_id = self.image.user_id
        db_record.image_digest = self.image.digest
        db_record.report_key = self.__report_key_class__.from_report(report).to_dict()

        # save it to db instead of object storage to be able to execute other queries over the data
        db_record.add_raw_result(report.to_json())

        # Update session
        session = get_session()
        return session.merge(db_record)
