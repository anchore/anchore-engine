import pytest

from anchore_engine.auth.oauth import (
    JwtTokenManager,
    TokenIssuer,
    TokenVerifier,
    load_keys,
    token_manager,
)
from anchore_engine.configuration.localconfig import (
    InvalidOauthConfigurationError,
    OauthNotConfiguredError,
)
from anchore_engine.subsys import logger
from anchore_engine.utils import ensure_str

logger.enable_test_logging()


def test_load_keys():
    config1 = {
        "public_key_path": "tests/data/certs/public.pem",
        "private_key_path": "tests/data/certs/private.pem",
    }

    cfg = load_keys(config1)
    assert cfg["private"] is not None
    assert cfg["public"] is not None
    assert cfg.get("secret") is None

    config1 = {"secret": "abc123"}

    cfg = load_keys(config1)
    assert cfg.get("private") is None
    assert cfg.get("public") is None
    assert cfg["secret"] == b"abc123"

    bad_config = {
        "public_key_path": "tests/data/certs/public.pem",
        "private_key_path": "tests/data/certs/private.pemz",
    }

    with pytest.raises(Exception) as ex:
        load_keys(bad_config)

    bad_config = {
        "public_key_path": "tests/data/certs/public.pemz",
        "private_key_path": "tests/data/certs/private.pem",
    }

    with pytest.raises(Exception) as ex:
        load_keys(bad_config)


def test_token_issuer():
    key = b"abc123"
    alg = "HS256"

    t = TokenIssuer(key, alg, 60)
    tok, expiration = t.generate_token("admin123")

    assert tok is not None

    v = TokenVerifier(key, alg)
    claims = v.verify_token(tok)
    assert claims["iss"] == t.issuer
    assert claims["exp"] is not None


def test_token_verifier():
    key = b"abc123"
    alg = "HS256"

    t = TokenIssuer(key, alg, 60)
    tok, expiration = t.generate_token("admin123")
    assert tok is not None
    logger.info("Generated token: {}".format(tok))
    v = TokenVerifier(key, alg)
    v.claim_options["iss"]["value"] = "testissuer"

    with pytest.raises(Exception) as ex:
        claims = v.verify_token(tok)

    v.claim_options["sub"]["value"] = "admin123"
    v.claim_options["iss"]["value"] = t.issuer
    claims = v.verify_token(tok)

    v.claim_options["sub"]["value"] = "admin"
    v.claim_options["iss"]["value"] = t.issuer
    with pytest.raises(Exception) as ex:
        claims = v.verify_token(tok)


def test_token_manager_secret():
    """
    Test the token manager using a shared secret
    :return:
    """
    mgr = JwtTokenManager(
        oauth_config={"enabled": True, "default_token_expiration_seconds": 180},
        keys_config={"secret": "abc123"},
    )

    t = mgr.generate_token("testuser")

    mgr.verify_token(t)

    t2 = ensure_str(t)
    t2 += "-"
    with pytest.raises(Exception) as ex:
        mgr.verify_token(t2)


def test_token_manager_keys():
    mgr = JwtTokenManager(
        oauth_config={"enabled": True, "default_token_expiration_seconds": 180},
        keys_config={
            "public_key_path": "tests/data/certs/public.pem",
            "private_key_path": "tests/data/certs/private.pem",
        },
    )

    t = mgr.generate_token("testuser")

    mgr.verify_token(t)

    t2 = ensure_str(t)
    t2 += "-"

    with pytest.raises(Exception) as ex:
        mgr.verify_token(t2)


def test_is_enabled():
    conf1 = {
        "user_authentication": {"oauth": {"enabled": False}},
        "keys": {"secret": None, "private_key_path": None, "public_key_path": None},
    }

    with pytest.raises(OauthNotConfiguredError):
        token_manager(conf1)

    conf1 = {
        "user_authentication": {
            "oauth": {"enabled": True, "default_token_expiration": 1000},
            "keys": {"secret": None, "private_key_path": None, "public_key_path": None},
        }
    }
    with pytest.raises(InvalidOauthConfigurationError):
        token_manager(conf1)

    conf1 = {
        "user_authentication": {
            "oauth": {"enabled": True, "default_token_expiration": "blah"},
            "keys": {
                "secret": "asecret",
                "private_key_path": None,
                "public_key_path": None,
            },
        }
    }
    with pytest.raises(InvalidOauthConfigurationError):
        token_manager(conf1)

    conf1 = {
        "user_authentication": {
            "oauth": {"enabled": True, "default_token_expiration": 1000},
            "keys": {},
        }
    }
    with pytest.raises(InvalidOauthConfigurationError):
        token_manager(conf1)
