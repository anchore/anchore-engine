from flask import g as request_globals, request
from anchore_engine.apis.authentication import IdentityContext


class ApiRequestContextProxy(object):
    """
    A proxy class for gathering the runtime context of a request.

    Not intended for use in async operations, only api requests.
    """

    @staticmethod
    def identity():
        """
        Returns an IdentityContext object
        :return:
        """
        try:
            return request_globals.identity
        except:
            return None


    @staticmethod
    def set_identity(ident: IdentityContext):
        request_globals.identity = ident

    @staticmethod
    def namespace():
        """
        Returns the namespace (account) for the request, computed from the auth info and headers
        :return:
        """
        try:
            override = request.headers.get('x-anchore-account')
            if override:
                return override
            else:
                return request_globals.identity.user_account
        except:
            return None

    @staticmethod
    def get_service():
        try:
            return request_globals.service
        except AttributeError:
            return None
