import pytest

from tests.functional.services.utils.http_utils import (
    APIResponse,
    RequestFailedError,
    http_del,
    http_get,
    http_put,
)


def ensure_second_feed_enabled(api_conf: callable):
    feed_list_resp = http_get(["system", "feeds"], config=api_conf)
    if feed_list_resp.code != 200:
        raise RequestFailedError(
            feed_list_resp.url, feed_list_resp.code, feed_list_resp.body
        )

    resp = http_put(
        ["system", "feeds", feed_list_resp.body[0].get("name")],
        query={"enabled": True},
        config=api_conf,
    )
    if resp.code != 200:
        raise RequestFailedError(resp.url, resp.code, resp.body)


class TestSystemAPIDeleteReturns200:
    @pytest.mark.skip(reason="This is taking a really long time to run for some reason")
    def test_disable_and_delete_system_feeds(self, api_conf):
        """
        Since this does kinda change some of the state around feeds be sure to not re-order without considering the
        other feed-related tests below
        """
        feed_list_resp = http_get(["system", "feeds"], config=api_conf)
        assert feed_list_resp == APIResponse(200)

        # Pick arbitrary first feed to disable & then delete
        feeds = feed_list_resp.body
        feed_to_delete = feeds[0].get("name")

        resp = http_put(
            ["system", "feeds", feed_to_delete],
            None,
            {"enabled": False},
            config=api_conf,
        )
        assert resp == APIResponse(200)

        resp = http_del(["system", "feeds", feed_to_delete], config=api_conf)
        assert resp == APIResponse(200)

    @pytest.mark.skip(reason="This is taking a really long time to run for some reason")
    def test_disable_and_delete_feed_group(self, api_conf):
        ensure_second_feed_enabled(api_conf)
        feed_list_resp = http_get(["system", "feeds"], config=api_conf)
        assert feed_list_resp == APIResponse(200)

        # Pick 2nd feed
        feeds = feed_list_resp.body
        feed = feeds[1]
        feed_name = feed.get("name")

        # Arbitrarily pick 1st group
        groups = feed.get("groups", [])
        group_to_delete = groups[0].get("name")

        resp = http_put(
            ["system", "feeds", feed_name, group_to_delete],
            None,
            {"enabled": False},
            config=api_conf,
        )
        assert resp == APIResponse(200)

        resp = http_del(
            ["system", "feeds", feed_name, group_to_delete], config=api_conf
        )
        assert resp == APIResponse(200)
