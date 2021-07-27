from anchore_engine.db import FixedArtifact, Vulnerability, session_scope
from anchore_engine.subsys import logger
from tests.utils import init_test_logging

init_test_logging(level="info")


def tearDown():
    with session_scope() as session:
        records = (
            session.query(Vulnerability)
            .filter(Vulnerability.id == "FA_TEST-1234")
            .all()
        )
        for record in records:
            logger.info("DELETING test record {}".format(record))
            session.delete(record)


def test_FixedArtifact_fix_observed_at_behavior(anchore_db):
    try:
        with session_scope() as session:
            testV = Vulnerability()
            testV.id = "FA_TEST-1234"
            testV.namespace_name = "fa_testnamespace:1"
            testV.severity = "Unknown"

            # this indicates a fix available
            testFA_wfix = FixedArtifact()
            testFA_wfix.name = "fa_testpkg1"
            testFA_wfix.version = "1.0"

            testV.fixed_in.append(testFA_wfix)

            # this indicates a vulnerable package (no fix available)
            testFA_wofix = FixedArtifact()
            testFA_wofix.name = "fa_testpkg2"
            testFA_wofix.version = "None"

            testV.fixed_in.append(testFA_wofix)

            session.add(testV)

        timestamps = {}
        logger.info("TESTING: state after initial insert")
        with session_scope() as session:
            records = (
                session.query(FixedArtifact)
                .filter(FixedArtifact.vulnerability_id == "FA_TEST-1234")
                .all()
            )
            for record in records:
                p = record.name
                logger.info(
                    "FOUND: record {} - version {} - fix_observed_at - {}".format(
                        record.vulnerability_id, record.version, record.fix_observed_at
                    )
                )
                if record.version == "None" and record.fix_observed_at is not None:
                    logger.info(
                        "FAIL: record shows no fix version, but fix_observed_at set"
                    )
                    assert False
                elif (
                    record.version is not None
                    and record.version != "None"
                    and record.fix_observed_at is None
                ):
                    logger.info(
                        "FAIL: record shows fix version, but fix_observed_at is null"
                    )
                    assert False
                else:
                    logger.info(
                        "SUCCESS: record {} is correct at this phase ({} - {})".format(
                            p, record.version, record.fix_observed_at
                        )
                    )
                timestamps[record.name] = record.fix_observed_at

        logger.info("TESTING: state after update of elements unrelated to fix version")
        with session_scope() as session:
            records = (
                session.query(FixedArtifact)
                .filter(FixedArtifact.vulnerability_id == "FA_TEST-1234")
                .all()
            )
            for record in records:
                record.version_format = "testformat"
                session.add(record)

        with session_scope() as session:
            records = (
                session.query(FixedArtifact)
                .filter(FixedArtifact.vulnerability_id == "FA_TEST-1234")
                .all()
            )
            for record in records:
                p = record.name
                logger.info(
                    "FOUND: record {} - version {} - fix_observed_at - {}".format(
                        record.vulnerability_id, record.version, record.fix_observed_at
                    )
                )
                if record.version == "None" and record.fix_observed_at is not None:
                    logger.info(
                        "FAIL: record shows no fix version, but fix_observed_at set"
                    )
                    assert False
                elif (
                    record.version is not None
                    and record.version != "None"
                    and record.fix_observed_at is None
                ):
                    logger.info(
                        "FAIL: record shows fix version, but fix_observed_at is null"
                    )
                    assert False
                else:
                    logger.info(
                        "SUCCESS: record {} is correct at this phase ({} - {})".format(
                            p, record.version, record.fix_observed_at
                        )
                    )

        logger.info("TESTING: state after update of elements related to fix version")
        with session_scope() as session:
            records = (
                session.query(FixedArtifact)
                .filter(FixedArtifact.vulnerability_id == "FA_TEST-1234")
                .all()
            )
            for record in records:
                record.version = "1.0"
                session.add(record)

            record = (
                session.query(FixedArtifact)
                .filter(
                    FixedArtifact.vulnerability_id == "FA_TEST-1234",
                    FixedArtifact.name == "fa_testpkg2",
                )
                .one()
            )
            timestamps["fa_testpkg2"] = record.fix_observed_at

        with session_scope() as session:
            for p in ["fa_testpkg1", "fa_testpkg2"]:
                record = (
                    session.query(FixedArtifact)
                    .filter(
                        FixedArtifact.vulnerability_id == "FA_TEST-1234",
                        FixedArtifact.name == p,
                    )
                    .one()
                )
                if record.fix_observed_at != timestamps[p]:
                    logger.info(
                        "FAIL: {} timestamp in DB is not equal to original set ({} != {})".format(
                            p, record.fix_observed_at, timestamps[p]
                        )
                    )
                    assert False
                else:
                    logger.info(
                        "SUCCESS: record {} is correct at this phase ({} - {})".format(
                            p, record.version, record.fix_observed_at
                        )
                    )

        logger.info(
            "TESTING: state after further update of elements related to fix version"
        )
        with session_scope() as session:
            records = (
                session.query(FixedArtifact)
                .filter(FixedArtifact.vulnerability_id == "FA_TEST-1234")
                .all()
            )
            for record in records:
                record.version = "2.0"
                session.add(record)

        with session_scope() as session:
            for p in ["fa_testpkg1", "fa_testpkg2"]:
                record = (
                    session.query(FixedArtifact)
                    .filter(
                        FixedArtifact.vulnerability_id == "FA_TEST-1234",
                        FixedArtifact.name == p,
                    )
                    .one()
                )
                if record.fix_observed_at != timestamps[p]:
                    logger.info(
                        "FAIL: {} timestamp in DB is not equal to original set ({} != {})".format(
                            p, record.fix_observed_at, timestamps[p]
                        )
                    )
                    assert False
                else:
                    logger.info(
                        "SUCCESS: record {} is correct at this phase ({} - {})".format(
                            p, record.version, record.fix_observed_at
                        )
                    )

    except Exception as err:
        logger.error("FAIL: exception - {}".format(err))
        raise (err)
    finally:
        tearDown()
