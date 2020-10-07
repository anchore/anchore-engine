import pytest

from tests.functional.utils.http_utils import get_api_conf, http_post, RequestFailedError, http_del
from tests.functional.services.api.images import get_image_id
from tests.functional.conftest import get_ft_user_api_conf, does_ft_account_exist, get_logger, FT_ACCOUNT

USER_API_CONFS = [pytest.param(get_api_conf, id='admin_account_root_user'),
                  pytest.param(get_ft_user_api_conf, id='functional_test_account_fullcontrol_user')]

_logger = get_logger(__name__)


@pytest.fixture(scope="session", params=USER_API_CONFS)
def add_alpine_latest_image(request):
    """
    Note: the test_subscriptions depends on this bit...because a subscription won't exist if there is no image added.
    For now, leave this as session scoped (we can make the subscription test create it's own images later)
    TODO: decouple test_subscriptions from this
    """

    resp = http_post(['images'], {'tag': 'alpine:latest'}, config=request.param)
    if resp.code != 200:
        raise RequestFailedError(resp.url, resp.code, resp.body)
    image_id = get_image_id(resp)

    def remove_image_by_id():
        remove_resp = http_del(['images', 'by_id', image_id], query={'force': True}, config=request.param)
        if remove_resp.code != 200:
            if not does_ft_account_exist():
                # Because this is a session fixture, can't guarantee the order it runs against the account cleanup
                # Therefore, I've observed this finalizer running after the account is deleted. It's not the end of
                # the world, shouldn't be a failed test. If I make this fixture autouse=True, it has been generating an
                # extra matrix of tests which is worse than just letting the finalizer skip
                _logger.info("{} account does not exist, ignoring for teardown".format(FT_ACCOUNT))
                return
            raise RequestFailedError(remove_resp.url, remove_resp.code, remove_resp.body)

    request.addfinalizer(remove_image_by_id)
    return resp, request.param
