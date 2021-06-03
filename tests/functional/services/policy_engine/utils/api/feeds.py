from tests.functional.services.policy_engine.utils.api.conf import (
    policy_engine_api_conf,
)
from tests.functional.services.utils import http_utils


def feeds_sync(force_flush=None, feed=None):
    payload = {
        "user_id": policy_engine_api_conf().get("ANCHORE_API_USER"),
    }
    query = {
        "force_flush": force_flush,
        "feed": feed,
    }

    feed_sync_resp = http_utils.http_post(
        ["feeds"], payload, query=query, config=policy_engine_api_conf
    )

    if feed_sync_resp.code != 200:
        raise http_utils.RequestFailedError(
            feed_sync_resp.url, feed_sync_resp.code, feed_sync_resp.body
        )

    return feed_sync_resp


def get_feeds(include_counts=None, refresh_counts=None):
    query = {
        "include_counts": include_counts,
        "refresh_counts": refresh_counts,
    }
    get_feeds_resp = http_utils.http_get(
        ["feeds"], query, config=policy_engine_api_conf
    )

    if get_feeds_resp.code != 200:
        raise http_utils.RequestFailedError(
            get_feeds_resp.url,
            get_feeds_resp.code,
            get_feeds_resp.body,
        )

    return get_feeds_resp
