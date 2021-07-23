import datetime
import enum

import retrying

from anchore_engine.common.models.policy_engine import ImageVulnerabilitiesReport
from anchore_engine.db import Image
from anchore_engine.db import ImageVulnerabilitiesReport as DbImageVulnerabilities
from anchore_engine.db.db_grype_db_feed_metadata import (
    NoActiveGrypeDB,
    get_most_recent_active_grypedb,
)
from anchore_engine.subsys import logger

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

    To swap key implementation create a new key class with get_report_status() and assign the class to
    ImageVulnerabilitiesStore.__report_key_class__
    to the new class
    """

    @classmethod
    def from_report(cls, report: ImageVulnerabilitiesReport):
        return report.metadata.generated_by.get("db_checksum")

    def get_report_status(self, db_report: DbImageVulnerabilities, session):
        logger.debug(
            "Get report status by comparing grype-db checksums of the report and active-db"
        )
        report_db_checksum = db_report.report_key

        if report_db_checksum:
            # try getting the current active db checksum
            try:
                active_db = get_most_recent_active_grypedb(session)
                active_db_checksum = active_db.db_checksum
            except NoActiveGrypeDB:
                active_db_checksum = None

            logger.debug(
                "grype-db checksums report=%s, active=%s",
                report_db_checksum,
                active_db_checksum,
            )

            # compare report's checksum with active record in the system
            if active_db_checksum and active_db_checksum == report_db_checksum:
                status = Status.valid
            else:
                status = Status.stale
        else:
            logger.debug("Report checksum not found, marking this report invalid")
            # report's db checksum can't be parsed, something is really weird. invalidate the report
            status = Status.invalid

        return status


class ImageVulnerabilitiesStore:

    __report_key_class__ = GrypeDBKey

    def __init__(self, image_object: Image):
        self.image = image_object

    def fetch(self, session):
        """
        Tries to find a report for the image and it's validity if one is available

        """
        db_record = (
            session.query(DbImageVulnerabilities)
            .filter_by(account_id=self.image.user_id, image_digest=self.image.digest)
            .one_or_none()
        )

        if db_record:
            data = db_record.result.get("result")

            return data, self.__report_key_class__().get_report_status(
                db_record, session
            )
        else:
            return None, None

    def is_modified(self, session, since: datetime.datetime):
        """
        Looks up a report for the image and returns True if the report is newer than the timestamp.
        If the report was generated before the since timestamp, the logic checks for report status and returns True
        if the report needs a refresh, False otherwise

        """
        db_record = (
            session.query(DbImageVulnerabilities)
            .filter_by(account_id=self.image.user_id, image_digest=self.image.digest)
            .one_or_none()
        )

        if db_record:
            # found a report, check if it's valid
            if db_record.generated_at <= since:
                # report generated before since timestamp, verify status is valid
                is_modified = (
                    False
                    if self.__report_key_class__().get_report_status(db_record, session)
                    == Status.valid
                    else True
                )
            else:
                # report newer than since timestamp, so it's definitely modified
                is_modified = True
        else:
            # no report, nothing has been modified
            is_modified = False

        return is_modified

    def delete_all(self, session):
        """
        Flush all report entries for the given image
        :return:
        """
        for entry in session.query(DbImageVulnerabilities).filter_by(
            account_id=self.image.user_id, image_digest=self.image.digest
        ):
            try:
                session.delete(entry)
                session.flush()
            except:
                logger.exception("Could not delete vuln store entry: {}".format(entry))

        return True

    @retrying.retry(
        stop_max_attempt_number=REPORT_SAVE_RETRIES, wait_fixed=REPORT_SAVE_WAIT
    )
    def save(self, report: ImageVulnerabilitiesReport, session):
        """
        Persist the new result to store
        """
        logger.debug(
            "Saving report to store for %s/%s", report.account_id, report.image_id
        )

        # delete all previous stored results
        self.delete_all(session)

        # save the new results as a new entry
        db_record = DbImageVulnerabilities(
            account_id=self.image.user_id,
            image_digest=self.image.digest,
            generated_at=report.metadata.generated_at,
            report_key=self.__report_key_class__.from_report(report),
        )

        # save it to db instead of object storage to be able to execute other queries over the data
        db_record.add_raw_result(report.to_json())

        return session.merge(db_record)
