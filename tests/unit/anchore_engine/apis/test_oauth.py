import time

import pytest

from anchore_engine.apis.oauth import merge_client_metadata
from anchore_engine.apis.oauth import (
    setup_oauth_client,
    OAuth2Client,
    ANONYMOUS_CLIENT_ID,
)


@pytest.mark.parametrize(
    "existing_metadata, meta_to_add, expected_output",
    [
        (
            {"grant_types": []},
            {"grant_types": ["password"]},
            {"grant_types": ["password"]},
        ),
        (
            {"grant_types": ["password"]},
            {"grant_types": ["password"]},
            {"grant_types": ["password"]},
        ),
        (
            {"grant_types": ["password"]},
            {"grant_types": []},
            {"grant_types": ["password"]},
        ),
        (
            {"grant_types": ["password"]},
            {"grant_types": ["password", "bearer"]},
            {"grant_types": ["password", "bearer"]},
        ),
        (
            {"grant_types": ["password", "foobar"]},
            {"grant_types": ["password", "bearer"]},
            {"grant_types": ["password", "bearer", "foobar"]},
        ),
        (
            {},
            {"grant_types": ["password"]},
            {"grant_types": ["password"]},
        ),
        (
            {},
            {"grant_types": []},
            {"grant_types": []},
        ),
        (
            None,
            {"grant_types": []},
            {"grant_types": []},
        ),
        (
            None,
            {"grant_types": ["password"]},
            {"grant_types": ["password"]},
        ),
    ],
)
def test_merge_client_metadata(existing_metadata, meta_to_add, expected_output):
    """
    Unit test for merging client metadata records for the OAuth2Client

    :param existing_metadata:
    :param meta_to_add:
    :param expected_output:
    :return:
    """

    merged = merge_client_metadata(existing_metadata, meta_to_add)
    check_metadata(merged, expected_output)


def check_metadata(candidate: dict, expected: dict):
    for k, v in expected.items():
        if type(v) == list:
            assert sorted(candidate.get(k)) == sorted(v)

        else:
            assert (
                candidate.get(k) == v
            ), "Key {} from candidate {} did not match expected {}".format(
                k, candidate, v
            )


def password_oauth2_client():
    c = OAuth2Client()
    c.client_id = ANONYMOUS_CLIENT_ID
    c.user_id = None
    c.client_secret = None
    # These are no-ops effectively since the client isn't authenticated itself
    c.client_id_issued_at = time.time() - 100
    c.client_secret_expires_at = time.time() + 1000
    c.set_client_metadata(
        {
            "token_endpoint_auth_method": "none",  # This should be a function of the grant type input but all of our types are this currently
            "client_name": ANONYMOUS_CLIENT_ID,
            "grant_types": ["password"],
        }
    )
    return c


def legacy_password_oauth2_client():
    c = OAuth2Client()
    c.client_id = ANONYMOUS_CLIENT_ID
    c.user_id = None
    c.client_secret = None
    # These are no-ops effectively since the client isn't authenticated itself
    c.client_id_issued_at = time.time() - 100
    c.client_secret_expires_at = time.time() + 1000
    c.set_client_metadata(
        {
            "grant_types": ["password"],
        }
    )
    return c


def no_metadata_oauth2_client():
    c = OAuth2Client()
    c.client_id = ANONYMOUS_CLIENT_ID
    c.user_id = None
    c.client_secret = None
    # These are no-ops effectively since the client isn't authenticated itself
    c.client_id_issued_at = time.time() - 100
    c.client_secret_expires_at = time.time() + 1000
    return c


def empty_metadata_oauth2_client():
    c = OAuth2Client()
    c.client_id = ANONYMOUS_CLIENT_ID
    c.user_id = None
    c.client_secret = None
    # These are no-ops effectively since the client isn't authenticated itself
    c.client_id_issued_at = time.time() - 100
    c.client_secret_expires_at = time.time() + 1000
    c.set_client_metadata({})
    return c


def authorization_oauth2_client():
    c = OAuth2Client()
    c.client_id = ANONYMOUS_CLIENT_ID
    c.user_id = None
    c.client_secret = None
    c.client_id_issued_at = time.time() - 100
    c.client_secret_expires_at = time.time() + 1000
    c.set_client_metadata(
        {
            "token_endpoint_auth_method": "none",  # This should be a function of the grant type input but all of our types are this currently
            "client_name": ANONYMOUS_CLIENT_ID,
            "grant_types": ["authorization"],
        }
    )
    return c


def combined_oauth2_client():
    c = OAuth2Client()
    c.client_id = ANONYMOUS_CLIENT_ID
    c.user_id = None
    c.client_secret = None
    c.client_id_issued_at = time.time() - 100
    c.client_secret_expires_at = time.time() + 1000
    c.set_client_metadata(
        {
            "token_endpoint_auth_method": "none",  # This should be a function of the grant type input but all of our types are this currently
            "client_name": ANONYMOUS_CLIENT_ID,
            "grant_types": ["authorization", "password"],
        }
    )
    return c


@pytest.mark.parametrize(
    "found_client, add_client, expected_result",
    [
        (
            password_oauth2_client(),
            authorization_oauth2_client(),
            combined_oauth2_client(),
        ),
        (
            legacy_password_oauth2_client(),
            authorization_oauth2_client(),
            combined_oauth2_client(),
        ),
        (
            no_metadata_oauth2_client(),
            authorization_oauth2_client(),
            authorization_oauth2_client(),
        ),
        (
            empty_metadata_oauth2_client(),
            authorization_oauth2_client(),
            authorization_oauth2_client(),
        ),
    ],
)
def test_setup_oauth_client(found_client, add_client, expected_result):
    """

    :param found_client:
    :param add_client:
    :param expected_result:
    :return:
    """

    assert found_client.client_id == expected_result.client_id
    result = setup_oauth_client(found_client, add_client)
    assert result is not None
    check_metadata(
        result.client_metadata,
        expected_result.client_metadata,
    )
