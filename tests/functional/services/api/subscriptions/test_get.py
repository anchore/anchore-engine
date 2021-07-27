import pytest

from tests.functional.services.api.subscriptions import SUBSCRIPTION_TYPES
from tests.functional.services.utils.http_utils import APIResponse, http_get


class TestSubscriptionsAPIGetReturns200:
    def test_list_subscriptions(self, add_alpine_subscription):
        # Chose not to parametrize here because of the type parameter in the test below
        subscription, api_conf = add_alpine_subscription
        resp = http_get(["subscriptions"], config=api_conf)
        assert resp == APIResponse(200)

    def test_list_subscriptions_with_key(self, add_alpine_subscription):
        subscription, api_conf = add_alpine_subscription
        resp = http_get(
            ["subscriptions"],
            query={"subscription_key": subscription.get("subscription_key")},
            config=api_conf,
        )
        assert resp == APIResponse(200)

    @pytest.mark.parametrize("s_type", SUBSCRIPTION_TYPES)
    def test_list_subscriptions_with_type(self, add_alpine_subscription, s_type):
        subscription, api_conf = add_alpine_subscription
        resp = http_get(
            ["subscriptions"], query={"subscription_type": s_type}, config=api_conf
        )
        assert resp == APIResponse(200)

    def test_get_subscription_by_id(self, add_alpine_subscription):
        subscription, api_conf = add_alpine_subscription

        # arbitrarily pick 1st subscription
        resp = http_get(
            ["subscriptions", subscription.get("subscription_id")], config=api_conf
        )
        assert resp == APIResponse(200)
