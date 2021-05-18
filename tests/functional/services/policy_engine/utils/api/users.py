from typing import Optional

from tests.functional.services.policy_engine.utils.api.conf import (
    policy_engine_api_conf,
)
from tests.functional.services.utils import http_utils


def delete_image(image_id: str) -> http_utils.APIResponse:
    if not image_id:
        raise ValueError("Cannot ingress image to policy engine without image id")

    delete_image_resp = http_utils.http_del(
        ["users", policy_engine_api_conf().get("ANCHORE_API_USER"), "images", image_id],
        config=policy_engine_api_conf,
    )

    if delete_image_resp.code > 299:
        raise http_utils.RequestFailedError(
            delete_image_resp.url, delete_image_resp.code, delete_image_resp.body
        )

    return delete_image_resp


def get_image_vulnerabilities(image_id: str) -> http_utils.APIResponse:
    if not image_id:
        raise ValueError("Cannot ingress image to policy engine without image id")

    image_vulnerabilities_resp = http_utils.http_get(
        [
            "users",
            policy_engine_api_conf().get("ANCHORE_API_USER"),
            "images",
            image_id,
            "vulnerabilities",
        ],
        config=policy_engine_api_conf,
    )

    if image_vulnerabilities_resp.code != 200:
        raise http_utils.RequestFailedError(
            image_vulnerabilities_resp.url,
            image_vulnerabilities_resp.code,
            image_vulnerabilities_resp.body,
        )

    return image_vulnerabilities_resp


def get_images_by_vulnerability(
    vulnerability_id: str,
    severity: Optional[str] = None,
    namespace: Optional[str] = None,
    affected_package: Optional[str] = None,
    vendor_only: bool = True,
) -> http_utils.APIResponse:
    if not vulnerability_id:
        raise ValueError("Cannot query image by vulnerability without vulnerability id")
    query = {"vulnerability_id": vulnerability_id, "vendor_only": vendor_only}
    if not isinstance(severity, type(None)):
        query["severity"] = severity
    if not isinstance(namespace, type(None)):
        query["namespace"] = namespace
    if not isinstance(affected_package, type(None)):
        query["affected_package"] = affected_package

    image_by_vuln_resp = http_utils.http_get(
        [
            "users",
            policy_engine_api_conf().get("ANCHORE_API_USER"),
            "query",
            "images",
            "by_vulnerability",
        ],
        query=query,
        config=policy_engine_api_conf,
    )

    if image_by_vuln_resp.code != 200:
        raise http_utils.RequestFailedError(
            image_by_vuln_resp.url,
            image_by_vuln_resp.code,
            image_by_vuln_resp.body,
        )

    return image_by_vuln_resp
