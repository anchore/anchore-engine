from tests.functional.services.policy_engine.utils.api.conf import (
    policy_engine_api_conf,
)
from tests.functional.services.utils import http_utils


def get_vulnerabilities(
    vulnerability_ids=[],
    affected_package=None,
    affected_package_version=None,
    namespace=None,
):
    if not vulnerability_ids:
        raise ValueError("Cannot fetch vulnerabilities without ids")

    query = {
        "id": ",".join(vulnerability_ids),
        "affected_package": affected_package,
        "affected_package_version": affected_package_version,
        "namespace": namespace,
    }
    vulnerabilities_resp = http_utils.http_get(
        ["query", "vulnerabilities"], query, config=policy_engine_api_conf
    )

    if vulnerabilities_resp.code != 200:
        raise http_utils.RequestFailedError(
            vulnerabilities_resp.url,
            vulnerabilities_resp.code,
            vulnerabilities_resp.body,
        )

    return vulnerabilities_resp
