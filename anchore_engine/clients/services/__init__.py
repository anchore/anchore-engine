from .internal import InternalServiceClient
from anchore_engine.subsys.identities import manager_factory
from anchore_engine.db import session_scope


def _system_creds_provider():
    with session_scope() as session:
        mgr = manager_factory.for_session(session=session)
        return mgr.get_system_credentials()


def internal_client_for(internal_client_cls, userId):
    """
    Return an initialized  internal service client for the given userId (namespace)

    :param cls:
    :param userId:
    :param session:
    :return:
    """

    return internal_client_cls(credential_fn=_system_creds_provider, as_account=userId)
