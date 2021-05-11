import typing
from typing import List, Tuple

import sqlalchemy.orm
from sqlalchemy import func, and_, or_
from sqlalchemy.orm import Session, joinedload

from anchore_engine.db import (
    ImageCpe,
    VulnDBCpe,
    Image,
    Vulnerability,
    CpeV2Vulnerability,
    DistroNamespace,
)
from anchore_engine.subsys import logger


class CpeDBQueryManager:
    def __init__(self, db_session: Session):
        self.db_session = db_session

    def joined_query_image_application_nvd_vulns(
        self, cpe_cls: typing.Type, image_id: str, account: str
    ) -> List[Tuple]:
        """
        Match image non-os packages against NVD cpes using a DB query to join for cpes of non-os packages that
        are entered in the db at image-load time.

        :param db: db session
        :param account: account name
        :param image_id: the image id
        :param cpe_cls: the class of CPE to match against in the db entities
        :return: list of ImageCpe, cpe_cls tuples
        """
        cpe_vulnerabilities = (
            self.db_session.query(ImageCpe, cpe_cls)
            .filter(
                ImageCpe.image_id == image_id,
                ImageCpe.image_user_id == account,
                func.lower(ImageCpe.name) == cpe_cls.name,
                ImageCpe.version == cpe_cls.version,
            )
            .options(joinedload(cpe_cls.parent, innerjoin=True))
            .all()
        )
        return cpe_vulnerabilities

    def joined_query_image_application_vulndb_vulns(
        self, image_id: str, user_id: str
    ) -> List[Tuple[ImageCpe, VulnDBCpe]]:
        """
        Return matches of image non-os packages against VulnDB data if present using a joined query in the DB for
        image cpes loaded into the db already

        :param user_id:
        :param image_id:
        :param db:
        :param image:
        :return:
        """
        matches = (
            self.db_session.query(ImageCpe, VulnDBCpe)
            .filter(
                ImageCpe.image_id == image_id,
                ImageCpe.image_user_id == user_id,
                func.lower(ImageCpe.name) == VulnDBCpe.name,
                ImageCpe.version == VulnDBCpe.version,
                VulnDBCpe.is_affected.is_(True),
            )
            .options(joinedload(VulnDBCpe.parent, innerjoin=True))
            .all()
        )
        return matches

    def query_image_application_vulnerabilities(
        self,
        cpe_cls: typing.Type,
        image: Image,
    ) -> List[Tuple]:
        """
        Find image cpes for non-distro packages (application packages) by doing a CPE match on the CPE-based feeds

        :return: list of (image_cpe, cpe_vulnerability) tuples
        """
        cpe_vulns = self.joined_query_image_application_nvd_vulns(
            cpe_cls, image.id, image.user_id
        )
        vulndb_vulns = self.joined_query_image_application_vulndb_vulns(
            image.id, image.user_id
        )

        # vulndb is similar to nvd cpes, add them here
        cpe_vulns.extend(vulndb_vulns)
        return cpe_vulns

    def matched_records_for_namespace(
        self, namespace: DistroNamespace, filter_ids: List[str]
    ) -> List[str]:
        """
        Utility function to lookup all vulns for the namespace

        :param namespace_name: string namespace (e.g. "alpine:3.8")
        :param match_set: the list of cve ids to query against
        :return: iterable for Vulnerability records
        """

        # Chunk on length of match_set
        chunk_size = 100
        idx = 0
        vuln_ids = []
        match_count = len(filter_ids)

        logger.info("Checking for sec db matches for %s", filter_ids)

        # Do a chunked query to ensure a long list of match_set doesn't break due to query length
        while idx < match_count:
            chunk = filter_ids[idx : idx + chunk_size]
            idx += chunk_size
            logger.info(
                "Query chunk %s with namespace %s",
                chunk,
                namespace.like_namespace_names,
            )

            qry = self.db_session.query(Vulnerability.id).filter(
                Vulnerability.namespace_name.in_(namespace.like_namespace_names),
                Vulnerability.id.in_(chunk),
            )

            result = _db_query_wrapper(qry, get_all=True)
            logger.info("Raw result = %s", str(result))
            vuln_ids.extend(result)

        logger.info("Found cve id matches for %s", vuln_ids)
        return vuln_ids

    def result_tuples_to_list(
        self, result_tulpe_rows: List[Tuple[str]], extract_tuple_index=0
    ):
        """
        Expects tuple input from a tuple-style query response (each row is a tuple of result columns)

        :param cve_tulpes:
        :return:
        """
        return (
            [row[extract_tuple_index] for row in result_tulpe_rows]
            if result_tulpe_rows
            else []
        )

    def query_nvd_cpe_matches(
        self, packages: List[ImageCpe], cpe_cls=CpeV2Vulnerability
    ) -> List:
        """
        DB Query helper to get NVD matches for the given product and version

        :param packages:
        :param cpe_cls: The cpe class to query
        :return:
        """

        chunk_size = 50  # Max number of and/or clauses per query
        count = 0
        results = []

        clauses = []
        # # OR the AND clauses together
        for image_cpe in packages:
            clauses.append(
                and_(
                    image_cpe.name == cpe_cls.product,
                    image_cpe.version == cpe_cls.version,
                )
            )
            count += 1

            if count >= chunk_size:
                # Run the query
                qry = self.db_session.query(cpe_cls).filter(or_(*clauses))
                results.extend(_db_query_wrapper(qry, get_all=True))
                count = 0
                clauses = []

        if count > 0:
            # Run the query to catch the last set
            qry = self.db_session.query(cpe_cls).filter(or_(*clauses))
            results.extend(_db_query_wrapper(qry, get_all=True))

        return results

    def query_vulndb_cpes(self, packages: List[ImageCpe]) -> List[VulnDBCpe]:
        """
        DB query helper to get VulnDB matches for hte given product and version
        :param db:
        :param packages:
        :return:
        """

        chunk_size = 50  # Max number of and/or clauses per query
        count = 0
        results = []

        # OR the AND clauses together
        clauses = []
        for cpe in packages:
            clauses.append(
                and_(
                    cpe.name == VulnDBCpe.name,
                    cpe.version == VulnDBCpe.version,
                )
            )
            count += 1

            if count >= chunk_size:
                # Run the query
                qry = (
                    self.db_session.query(VulnDBCpe)
                    .filter(VulnDBCpe.is_affected.is_(True))
                    .filter(*clauses)
                )
                results.extend(_db_query_wrapper(qry, get_all=True))
                clauses = []
                count = 0

        if count > 0:
            # Run the query to catch the last set
            qry = (
                self.db_session.query(VulnDBCpe)
                .filter(VulnDBCpe.is_affected.is_(True))
                .filter(*clauses)
            )
            results.extend(_db_query_wrapper(qry, get_all=True))

        return results


def _db_query_wrapper(query: sqlalchemy.orm.Query, get_all=True):
    """
    Logging wrapper on the query call to simplify debugging
    :param query:
    :param get_all:
    :return:
    """
    logger.debug("executing query: %s", str(query))
    # If get_all, then caller will iterate over results
    if get_all:
        return query.all()

    return query
