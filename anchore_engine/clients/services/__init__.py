from .internal import InternalServiceClient
from anchore_engine.subsys.identities import manager_factory


def internal_client_for(internal_client_cls, userId):
    """
    Return an initialized  internal service client for the given userId (namespace)

    :param cls:
    :param userId:
    :param session:
    :return:
    """
    mgr = manager_factory.for_session(session=None)
    sysuser, syspass = mgr.get_system_credentials()

    if sysuser is None:
        raise Exception('No cached system credentials found')

    return internal_client_cls(user=sysuser, password=syspass, as_account=userId)
