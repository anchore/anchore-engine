from .internal import InternalServiceClient
from anchore_engine.subsys.identities import manager_factory
from anchore_engine.db import session_scope

def internal_client_for(internal_client_cls, userId):
    """
    Return an initialized  internal service client for the given userId (namespace)

    :param cls:
    :param userId:
    :param session:
    :return:
    """

    with session_scope() as session:
        mgr = manager_factory.for_session(session=session)
        credential = mgr.get_system_credentials()

        if credential is None:
            raise Exception('No cached system credentials found')

        return internal_client_cls(credential=credential, as_account=userId)
