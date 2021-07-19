"""
Integration test for lease handling subsystem. Requires a running postgres database.
"""

import time
import uuid
from concurrent.futures.thread import ThreadPoolExecutor
from datetime import datetime, timedelta

import dateutil.parser

from anchore_engine.db import Lease, db_locks, session_scope
from anchore_engine.subsys import logger
from anchore_engine.subsys.logger import enable_test_logging

enable_test_logging()


def test_serial_lock(anchore_db):
    """
    Simple test of serial lease access ensuring it transfers between holders properly in simple cases (acquire, release, acquire, release)

    :param anchore_db:
    :return:
    """
    id = uuid.uuid1().hex
    id2 = uuid.uuid1().hex
    lock_id = "testlock"
    db_locks.init_lease(lock_id)

    r = db_locks.acquire_lease(lock_id, id)
    assert r is not None, "Should have gotten a valid lock return, not None"
    assert r["id"] == lock_id, "Lock id mismatch"

    r2 = db_locks.acquire_lease(lock_id, id2)
    assert r2 is None, "Should have failed to get the lock"

    release1 = db_locks.release_lease(lock_id, id, r["epoch"])
    assert (
        release1 is None
    ), "No one else should have the lock, should have released cleanly"

    r3 = db_locks.acquire_lease(lock_id, id2)
    assert r3 is not None, "Failed to get the lock"
    assert lock_id == r3["id"], "Wrong client with lock"

    bad_release = db_locks.release_lease(
        r["id"], r["held_by"], r["epoch"]
    )  # This shouldn't work, old epoch and wrong id, should return the actual holder
    assert (
        bad_release is None
    ), "Epoch and id should be stale and return the actual lock holder, not None: {}".format(
        bad_release
    )

    good_release = db_locks.release_lease(r3["id"], r3["held_by"], r3["epoch"])
    assert good_release is None, "Should have no lock/None: {}".format(good_release)


def test_expiration(anchore_db):
    """
    Test lease expiration by acquiring and holding past expiration. Ensures others can acquire the lock after the ttl.

    :param anchore_db:
    :return:
    """

    lock_id = "test_lock2"
    id = uuid.uuid4().hex
    id2 = uuid.uuid4().hex

    db_locks.init_lease(lock_id)

    l = db_locks.acquire_lease(lock_id, id, ttl=1)
    assert lock_id == l["id"], "Lock id mismatches"

    time.sleep(3)

    l2 = db_locks.acquire_lease(lock_id, id2, ttl=100)
    assert l2 is not None, "l2 should have a lock, not None"
    assert lock_id == l2["id"], "Lock id mismatch"

    assert (
        db_locks.release_lease(l2["id"], l2["held_by"], l2["epoch"]) is None
    ), "No lock should be held"


def test_contextmgr(anchore_db):
    lockid = "testlock"
    lockid2 = "test_lock_2"
    db_locks.init_lease(lockid)
    db_locks.init_lease(lockid2)
    with db_locks.least_with_ttl(lockid, "myid123", ttl=10) as lt:
        logger.info(str(lt))
        with session_scope() as db:
            logger.info(
                ("{}".format("\n".join([str(x) for x in db.query(Lease).all()])))
            )

    logger.info(str(lt))


def run_thread_lock_fn(wait_sleep_seconds):
    """
    Function run by each thread that tries to acquire the lease and backs off if not acquired.

    :param t: seconds to sleep between each attempt
    :return:
    """

    id = uuid.uuid4().hex
    lock_id = "testlock"
    db_locks.init_lease(lock_id)
    count = 10
    r = None

    while count > 0:
        inner = 5

        while inner > 0:
            r = db_locks.acquire_lease(lock_id, id, ttl=wait_sleep_seconds - 1)
            if not r:
                time.sleep(wait_sleep_seconds)
                inner -= 1
            else:
                break

        logger.info("{} Lock: {}".format(id, r))
        logger.info("Sleeping for {}".format(wait_sleep_seconds))
        time.sleep(wait_sleep_seconds)

        if r:
            db_locks.release_lease(r["id"], r["held_by"], r["epoch"])
            logger.info("{} Lock: {}".format(id, r))

        count -= 1

    return "Complete"


def test_threads(anchore_db):
    """
    Test concurrent lease contention and acquisition

    :param anchore_db:
    :return:
    """

    th = []
    t = ThreadPoolExecutor(max_workers=3)
    th.append(t.submit(run_thread_lock_fn, 2))
    th.append(t.submit(run_thread_lock_fn, 5))
    th.append(t.submit(run_thread_lock_fn, 1))

    for thread in th:
        # Wait for completion
        r = thread.result()
        logger.info(("Thread result {}".format(r)))


def test_refresh_lease(anchore_db):
    # Setup
    client_id = uuid.uuid4().hex
    lease_id = "testlease"
    db_locks.init_lease(lease_id)
    initial_ttl = 30
    db_locks.acquire_lease(lease_id, client_id, ttl=initial_ttl, timeout=5)

    # Attempt to refresh the lease
    later_ttl = 60
    db_locks.refresh_lease(lease_id, client_id, epoch=1, ttl=later_ttl)

    # Assert that the lease was refreshed
    # (Make sure the new TTL is later than the initial TTL)
    lease = db_locks.get(lease_id)
    lease_expiration = dateutil.parser.parse(lease["expires_at"])
    assert lease_expiration > datetime.now() + timedelta(seconds=initial_ttl)

    # Cleanup
    db_locks.release_lease(lease_id, client_id, epoch=1000)
