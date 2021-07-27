import pytest

from tests.functional import get_logger
from tests.functional.services.api.conftest import USER_API_CONFS
from tests.functional.services.utils.http_utils import (
    RequestFailedError,
    http_del,
    http_get,
    http_post,
)

ALPINE_LATEST_SUBSCRIPTION = {
    "subscription_key": "docker.io/alpine:latest",
    "subscription_type": "tag_update",
}
_logger = get_logger(__name__)


@pytest.fixture(scope="class", params=USER_API_CONFS)
def add_alpine_subscription(request):
    subscription = add_subscription(request.param)

    def remove_subscription():
        resp = http_del(
            ["subscriptions", subscription.get("subscription_id")], config=request.param
        )
        if resp.code != 200:
            raise RequestFailedError(resp.url, resp.code, resp.body)

    request.addfinalizer(remove_subscription)
    return subscription, request.param


def add_subscription(api_conf: callable):
    added_subscription = None
    resp = http_post(["subscriptions"], ALPINE_LATEST_SUBSCRIPTION, config=api_conf)
    if (
        resp.code == 500
        and resp.body.get("message") == "subscription already exists in DB"
    ):
        # Already exists
        resp = http_get(["subscriptions"], config=api_conf)
        subscription_list = resp.body
        for subscription in subscription_list:
            if (
                subscription.get("subscription_type") == "tag_update"
                and subscription.get("subscription_key") == "docker.io/alpine:latest"
            ):
                added_subscription = subscription
                break
    elif resp.code != 200:
        raise RequestFailedError(resp.url, resp.code, resp.body)
    else:
        added_subscription = resp.body[0]
    return added_subscription
