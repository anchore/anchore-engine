"""
Exception types for the analyzer service
"""
from anchore_engine.utils import AnchoreException


class ClientError(AnchoreException):
    def __init__(self, cause, msg="Failed to execute client call"):
        self.cause = str(cause)
        self.msg = msg

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        return "{} - exception: {}".format(self.msg, self.cause)


class PolicyEngineClientError(ClientError):
    def __init__(self, cause, msg="Failed to execute out policy engine API"):
        super().__init__(cause, msg=msg)


class CatalogClientError(ClientError):
    def __init__(self, cause, msg="Failed to execute out catalog API"):
        super().__init__(cause, msg=msg)
