from tests.functional.services.policy_engine.utils.api.conf import (
    policy_engine_api_conf,
)
from tests.functional.services.utils import http_utils


def ingress_image(fetch_url: str, image_id: str) -> http_utils.APIResponse:
    if not fetch_url:
        raise ValueError("Cannot ingress image to policy engine without fetch url")

    if not image_id:
        raise ValueError("Cannot ingress image to policy engine without image id")

    payload = {
        "fetch_url": fetch_url,
        "user_id": policy_engine_api_conf().get("ANCHORE_API_USER"),
        "image_id": image_id,
    }

    ingress_image_resp = http_utils.http_post(
        ["images"], payload, config=policy_engine_api_conf
    )

    if ingress_image_resp.code != 200:
        raise http_utils.RequestFailedError(
            ingress_image_resp.url, ingress_image_resp.code, ingress_image_resp.body
        )

    return ingress_image_resp
