import pytest
from anchore_engine.subsys.auth.stores.verifier import JwtToken, BearerTokenVerifier
from anchore_engine.subsys import logger
from anchore_engine.auth.oauth import JwtTokenManager, token_manager, _token_manager

logger.enable_test_logging()


def test_jwt_token():
    test_config = {
        'secret': '123abc456def'
    }
    global _token_manager
    _token_manager = None

    mgr = token_manager(test_config)
    t = mgr.generate_token('admin')
    logger.info('Using token: {}'.format(t))
    j = JwtToken(token=t)
    assert j.credentials == t
    assert j.identifier == 'admin'


def test_jwt_verifier():
    global _token_manager
    _token_manager = None
    mgr = token_manager({'secret': 'abc123'})

    v = BearerTokenVerifier(settings={})
    info = {
        'jwt': {'credential': 'signature_valid', 'failed_attempts': []}
    }

    t = JwtToken.__factory__().generate_token('admin')
    logger.info('Using token: {}'.format(t))
    test_token = JwtToken(token=t)
    bad_token = JwtToken(token=b'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjogImFkbWluIiwgImFjY291bnQiOiAiMTIzIn0.w6gV8ABimGTKth-xiwxtM6v------')
    v.verify_credentials(authc_token=test_token, authc_info=info)

    with pytest.raises(Exception):
        v.verify_credentials(authc_token=bad_token, authc_info=info)
