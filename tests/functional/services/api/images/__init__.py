import time

from tests.functional import get_logger
from tests.functional.services.utils.http_utils import RequestFailedError, http_get

WAIT_TIMEOUT_SEC = 60 * 5

_logger = get_logger(__name__)


def get_image_id(api_resp):
    return api_resp.body[0].get("image_detail", {})[0].get("imageId")


def get_image_digest(api_resp):
    return api_resp.body[0].get("imageDigest")


def get_image_tag(api_resp):
    return api_resp.body[0].get("image_detail", {})[0].get("fulltag")


def get_alpine_latest_image_os_content(image_id, image_digest, api_conf: callable):
    wait_for_image_to_analyze(image_id, api_conf)

    resp = http_get(["images", image_digest, "content", "os"], config=api_conf)
    if resp.code != 200:
        raise RequestFailedError(resp.url, resp.code, resp.body)

    return resp


def get_alpine_latest_image_os_vuln(image_id, image_digest, api_conf: callable):
    wait_for_image_to_analyze(image_id, api_conf)

    resp = http_get(["images", image_digest, "vuln", "os"], config=api_conf)
    if resp.code != 200:
        raise RequestFailedError(resp.url, resp.code, resp.body)

    return resp


def wait_for_image_to_analyze(image_id, api_conf: callable):
    status = "analyzing"
    start_time_sec = time.time()
    while status != "analyzed" and time.time() - start_time_sec < WAIT_TIMEOUT_SEC:
        resp = http_get(["images", "by_id", image_id], config=api_conf)
        status = resp.body[0].get("analysis_status", None)
        if status != "analyzed":
            _logger.info(
                "Waiting for Image Analysis to complete. Elapsed Time={}sec".format(
                    int(time.time() - start_time_sec)
                )
            )
            time.sleep(5)
    if time.time() - start_time_sec >= WAIT_TIMEOUT_SEC:
        raise TimeoutError(
            "Timed out waiting for Image to Analyze (timeout={}sec)".format(
                WAIT_TIMEOUT_SEC
            )
        )
    else:
        _logger.info(
            "Image Analysis Complete, wait time: {}sec".format(
                int(time.time() - start_time_sec)
            )
        )
