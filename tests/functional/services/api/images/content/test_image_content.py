import json
import os

import pytest

from tests.functional.services.api.images import (
    get_image_digest,
    get_image_id,
    wait_for_image_to_analyze,
)
from tests.functional.services.utils.http_utils import (
    APIResponse,
    get_api_conf,
    http_get,
)

test_images = [
    "docker.io/anchore/test_images:vulnerabilities-alpine-f5e8952",
    "docker.io/anchore/test_images:vulnerabilities-centos-f5e8952",
    "docker.io/anchore/test_images:vulnerabilities-debian-f5e8952",
    "docker.io/anchore/test_images:ubuntu-content",
]


def sort_content(body):
    """
    Sorts the results by package name and sort sub arrays to be able to do a direct comparison
    """
    body["content"].sort(key=lambda result: result["package"])
    for result in body["content"]:
        result["cpes"].sort()
        if "licenses" in result:
            result["licenses"].sort()


@pytest.mark.parametrize("test_tag", test_images, scope="class")
class TestImageContent:
    @pytest.fixture(scope="class")
    def add_and_wait_for_image(self, test_tag, add_image_with_teardown):
        """
        Adds tag to anchore with a finalizer that removes the image. Will also wait until the image is analyzed
        Returns the response to create image
        """
        add_response = add_image_with_teardown(test_tag)
        image_id = get_image_id(add_response)
        wait_for_image_to_analyze(image_id, api_conf=get_api_conf)
        return add_response

    @pytest.fixture
    def read_expected_content(self):
        """
        Returns function used to read expected content. Reads from ../expected_content
        Uses content type as folder name and image_digest as the name of the json file
        """

        def _read_expected_content(content_type, filename):
            expected_content_path = os.path.join(
                os.path.dirname(__file__), "expected_content", content_type, filename
            )
            return json.load(open(expected_content_path))

        return _read_expected_content

    def test_image_os_content(self, add_and_wait_for_image, read_expected_content):
        image_digest = get_image_digest(add_and_wait_for_image)

        resp = http_get(["images", image_digest, "content", "os"], config=get_api_conf)
        assert resp == APIResponse(200)

        expected_content = read_expected_content("os", f"{image_digest}.json")

        sort_content(resp.body)
        sort_content(expected_content)

        assert expected_content == resp.body
        for result in resp.body["content"]:
            assert result["sourcepkg"] not in ["", None]

    def test_image_java_content(self, add_and_wait_for_image, read_expected_content):
        image_digest = get_image_digest(add_and_wait_for_image)

        resp = http_get(
            ["images", image_digest, "content", "java"], config=get_api_conf
        )
        assert resp == APIResponse(200)

        expected_content = read_expected_content("java", f"{image_digest}.json")

        sort_content(resp.body)
        sort_content(expected_content)

        assert expected_content == resp.body
        for result in resp.body["content"]:
            assert result["version"] not in ["", None]

    def test_image_gem_content(self, add_and_wait_for_image, read_expected_content):
        image_digest = get_image_digest(add_and_wait_for_image)

        resp = http_get(["images", image_digest, "content", "gem"], config=get_api_conf)
        assert resp == APIResponse(200)

        expected_content = read_expected_content("gem", f"{image_digest}.json")

        sort_content(resp.body)
        sort_content(expected_content)

        assert expected_content == resp.body

    def test_image_python_content(self, add_and_wait_for_image, read_expected_content):
        image_digest = get_image_digest(add_and_wait_for_image)

        resp = http_get(
            ["images", image_digest, "content", "python"], config=get_api_conf
        )
        assert resp == APIResponse(200)
        expected_content = read_expected_content("python", f"{image_digest}.json")

        sort_content(resp.body)
        sort_content(expected_content)

        assert expected_content == resp.body

    def test_image_npm_content(self, add_and_wait_for_image, read_expected_content):
        image_digest = get_image_digest(add_and_wait_for_image)

        resp = http_get(["images", image_digest, "content", "npm"], config=get_api_conf)
        assert resp == APIResponse(200)

        expected_content = read_expected_content("npm", f"{image_digest}.json")

        sort_content(resp.body)
        sort_content(expected_content)

        assert expected_content == resp.body
