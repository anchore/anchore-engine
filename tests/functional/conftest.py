import pytest

from tests.functional.services.api.images import (
    add_image,
    delete_image_by_id,
    get_image_id,
    wait_for_image_to_analyze,
)
from tests.functional.services.utils.http_utils import get_api_conf


@pytest.fixture(scope="package")
def add_image_with_teardown_package_scope(request):
    def _add_image_with_teardown(tag, api_conf=get_api_conf):
        # add image
        add_resp = add_image(tag, api_conf)
        image_id = get_image_id(add_resp)
        wait_for_image_to_analyze(image_id, api_conf)

        # add teardown
        request.addfinalizer(lambda: delete_image_by_id(image_id, api_conf))

        return add_resp

    return _add_image_with_teardown
