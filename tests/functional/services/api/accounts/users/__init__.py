from tests.functional.services.api.conftest import FT_ACCOUNT
from tests.functional.services.utils.http_utils import (
    RequestFailedError,
    http_del,
    http_post,
)


def create_ft_account_user(username, password, api_conf: callable):
    create_resp = http_post(
        ["accounts", FT_ACCOUNT, "users"],
        {"username": username, "password": password},
        config=api_conf,
    )
    if create_resp.code != 200:
        raise RequestFailedError(create_resp.url, create_resp.code, create_resp.body)


def delete_ft_account_user(username, api_conf: callable):
    delete_resp = http_del(["accounts", FT_ACCOUNT, "users", username], config=api_conf)
    if delete_resp.code != 204:
        raise RequestFailedError(
            delete_resp.url,
            delete_resp.code,
            "" if not hasattr(delete_resp, "body") else delete_resp.body,
        )
