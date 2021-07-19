import pytest

from tests.functional.services.utils.http_utils import APIResponse, http_post


class TestSystemAPIPostReturns200:
    @pytest.mark.skip(
        reason="Sync is a heavy compute, high bandwidth task that will take a long time. "
        "Not to say that it should not be tested, but maybe not here"
    )
    def test_system_feeds_sync(self, api_conf):
        """
        Should run fairly close to last to ensure test performance
        """
        resp = http_post(["system", "feeds"], None, {"sync": True}, config=api_conf)

        assert resp == APIResponse(200)

    @pytest.mark.skip(
        reason="Flush is a heavy compute, high bandwidth task that will take a long time. "
        "Not to say that it should not be tested, but maybe not here"
    )
    def test_system_feeds_flush(self, api_conf):
        """
        Should run fairly close to last to ensure test performance
        """
        resp = http_post(["system", "feeds"], None, {"flush": True}, config=api_conf)

        assert resp == APIResponse(200)
