import json


class AnchoreApiError(Exception):
    __response_code__ = 500

    def __init__(self, message: str, detail: dict):
        super().__init__()
        self.message = message
        self.detail = detail

    def __str__(self):
        return json.dumps({'message': self.message, 'detail': json.dumps(self.detail), 'httpcode': self.__response_code__})


class ResourceNotFound(AnchoreApiError):
    __response_code__ = 404

    def __init__(self, resource: str, detail: dict):
        super().__init__('Resource {} not found'.format(resource), detail)


class BadRequest(AnchoreApiError):
    __response_code__ = 400


class AccessDeniedError(AnchoreApiError):
    __response_code__ = 403


class PermissionDenied(AccessDeniedError):
    def __init__(self, permission):
        super().__init__('Access Denied', {'permission_required': permission})


class UnauthorizedError(AnchoreApiError):
    __response_code__ = 401


class BadCredentials(UnauthorizedError):
    def __init__(self):
        super().__init__('Invalid Credentials', None)


class InternalError(AnchoreApiError):
    __response_code__ = 500


class UnavailableError(AnchoreApiError):
    __response_code__ = 503


class BadGatewayError(AnchoreApiError):
    __response_code__ = 502
