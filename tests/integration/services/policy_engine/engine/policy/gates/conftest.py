import pytest

from anchore_engine.db import Image, get_thread_scoped_session
from anchore_engine.services.policy_engine import _init_distro_mappings
from anchore_engine.services.policy_engine.engine.tasks import ImageLoadTask
from anchore_engine.subsys import logger
from tests.integration.services.policy_engine.conftest import run_legacy_sync


def load_images(request):
    for image_id, path in request.cls.test_env.image_exports():
        logger.info(
            "Ensuring loaded: image id: {} from file: {}".format(image_id, path)
        )
        t = ImageLoadTask(image_id=image_id, user_id="0", url="file://" + path)
        t.execute()

    db = get_thread_scoped_session()
    test_image = db.query(Image).get(
        (
            request.cls.test_env.get_images_named(request.cls.__default_image__)[0][0],
            "0",
        )
    )
    request.cls.test_image = test_image
    db.rollback()


@pytest.fixture(scope="class")
def cls_fully_loaded_test_env(cls_test_data_env2, request):
    """
    Load the test env, including a feed sync and image analysis. Places the env in the class's test_env and test_image vars

    :param cls_test_data_env:
    :param request:
    :return:
    """
    _init_distro_mappings()
    run_legacy_sync(
        request.cls.test_env, ["vulnerabilities", "packages", "nvdv2", "vulndb"]
    )
    load_images(request)


@pytest.fixture(scope="class")
def cls_no_feeds_test_env(cls_test_data_env2, request):
    """
    Same as fully_loaded_test_env but does not sync feeds

    :param cls_test_data_env:
    :param request:
    :return:
    """
    _init_distro_mappings()
    load_images(request)
