import pytest

from anchore_engine.auth.oauth import token_manager
from anchore_engine.subsys import logger
from anchore_engine.subsys.auth.stores.verifier import JwtToken, BearerTokenVerifier
from anchore_engine.utils import ensure_str

logger.enable_test_logging()


def test_jwt_token():
    test_config = {
        "user_authentication": {
            "oauth": {"enabled": True, "default_token_expiration_seconds": 60}
        },
        "keys": {"secret": "abc123"},
    }
    global _token_manager
    _token_manager = None

    mgr = token_manager(test_config)
    t = mgr.generate_token("admin")
    logger.info("Using token: {}".format(t))
    j = JwtToken(token=t)
    assert j.credentials == t
    assert j.identifier == "admin"


def test_jwt_verifier():
    global _token_manager
    _token_manager = None
    mgr = token_manager(
        {
            "user_authentication": {
                "oauth": {"enabled": True, "default_token_expiration_seconds": 60}
            },
            "keys": {"secret": "abc123"},
        }
    )

    v = BearerTokenVerifier(settings={})

    # The lookup normally returns the uuid of the user
    info = {"authc_info": {"jwt": {"credential": "abc123uuid", "failed_attempts": []}}}

    t, exp = JwtToken.__factory__().generate_token("abc123uuid", return_expiration=True)
    logger.info("Using token: {}".format(t))
    test_token = JwtToken(token=ensure_str(t))
    bad_token = JwtToken(
        token="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjogImFkbWluIiwgImFjY291bnQiOiAiMTIzIn0.w6gV8ABimGTKth-xiwxtM6v------"
    )
    v.verify_credentials(authc_token=test_token, authc_info=info)

    with pytest.raises(Exception):
        v.verify_credentials(authc_token=bad_token, authc_info=info)
