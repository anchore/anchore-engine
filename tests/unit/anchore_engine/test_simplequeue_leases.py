"""
Tests for the internal simplequeue client lease convenience functions.
"""
import pytest

from anchore_engine.clients.services.simplequeue import run_target_with_lease
from anchore_engine.subsys import logger
from anchore_engine.subsys.identities import HttpBasicCredential, IdentityManager

logger.enable_test_logging()

lease_id = "test1"
test_id = "test_client"
epoch = 0
do_ok = True
ttl = 60


def acquire_lease_mock(fail):
    def fn(*args, **kwargs):
        logger.info("Called acquire")
        if not fail:
            global lease_id, test_id, epoch
            epoch += 1
            return {"id": lease_id, "held_by": test_id, "epoch": epoch, "ttl": ttl}
        else:
            return None

    return fn


def release_lease_mock(fail):
    def fn(*args, **kwargs):
        logger.info("Called release")
        if not fail:
            global lease_id, test_id, epoch
            epoch += 1
            return {"id": lease_id, "held_by": None, "epoch": epoch, "ttl": ttl}
        else:
            return None

    return fn


def refresh_lease_mock(fail):
    def fn(*args, **kwargs):
        logger.info("Called refresh")
        if not fail:
            global lease_id, test_id, epoch
            epoch += 1
            return {"id": lease_id, "held_by": test_id, "epoch": epoch, "ttl": ttl}
        else:
            return None

    return fn


def list_leases_mock(fail):
    def fn(*args, **kwargs):
        logger.info("Called list")
        if not fail:
            global lease_id, test_id, epoch
            return [{"id": lease_id, "held_by": test_id, "epoch": epoch, "ttl": ttl}]
        else:
            return None

    return fn


def describe_lease_mock(fail):
    def fn(*args, **kwargs):
        logger.info("Called describe")
        if not fail:
            global lease_id, test_id, epoch
            return {"id": lease_id, "held_by": test_id, "epoch": epoch, "ttl": ttl}
        else:
            return None

    return fn


def create_lease_mock(fail):
    def fn(*args, **kwargs):
        logger.info("Called create")
        if not fail:
            global lease_id, test_id, epoch
            return {"id": lease_id, "held_by": test_id, "epoch": epoch, "ttl": ttl}
        else:
            return None

    return fn


def pass_target():
    return True


def fail_target():
    raise Exception("Target failed")


@pytest.mark.skip(
    msg="Disabled temporarily pending work to remove db requirement from internal client init"
)
def test_run_target_with_lease_ok():
    global SimpleQueueClient

    SimpleQueueClient.acquire_lease = acquire_lease_mock(fail=False)
    SimpleQueueClient.refresh_lease = refresh_lease_mock(fail=False)
    SimpleQueueClient.describe_lease = describe_lease_mock(fail=False)
    SimpleQueueClient.create_lease = create_lease_mock(fail=False)
    SimpleQueueClient.release_lease = release_lease_mock(fail=False)

    # Pre-load the cache to ensure no db hit needed
    IdentityManager._credential_cache.cache_it(
        "anchore-system", HttpBasicCredential("anchore-system", "somepass")
    )
    run_target_with_lease("user", "test_lease", pass_target, client_id="test1")


@pytest.mark.skip(
    msg="Disabled temporarily pending work to remove db requirement from internal client init"
)
def test_run_target_with_lease_conn_error():
    global SimpleQueueClient

    SimpleQueueClient.acquire_lease = acquire_lease_mock(fail=True)
    SimpleQueueClient.refresh_lease = refresh_lease_mock(fail=True)
    SimpleQueueClient.describe_lease = describe_lease_mock(fail=False)
    SimpleQueueClient.create_lease = create_lease_mock(fail=False)
    SimpleQueueClient.release_lease = release_lease_mock(fail=False)

    with pytest.raises(Exception) as raised_ex:
        run_target_with_lease("user", "test_lease", pass_target, client_id="test1")

    logger.info("Caught: {}".format(raised_ex))
