from anchore_engine.subsys import logger

logger.enable_test_logging()


def test_sync_fail(test_data_env, run_legacy_sync_for_feeds):
    # No such feed
    result = run_legacy_sync_for_feeds(["nvd"])
    assert len(result) == 0

    result = run_legacy_sync_for_feeds(["vulnerabilities", "packages", "nvdv2"])
    assert len(result) == 3
    assert not any(filter(lambda x: x.status == "failure", result))
