from tests.functional.services.utils.http_utils import APIResponse, http_put


class TestSubscriptionsAPIPutReturns200:
    def test_update_subscription(self, add_alpine_subscription):
        subscription, api_conf = add_alpine_subscription
        resp = http_put(
            ["subscriptions", subscription.get("subscription_id")],
            {"active": False, "subscription_value": "docker.io/alpine:latest"},
            config=api_conf,
        )
        assert resp == APIResponse(200)
