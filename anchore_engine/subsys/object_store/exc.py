"""
Exception types for the archive drivers to normalize errors

"""


class ObjectStorageDriverError(StandardError):
    def __init__(self, cause=None):
        super(ObjectStorageDriverError, self).__init__()
        self.cause = cause


class DriverConfigurationError(ObjectStorageDriverError):
    """
    Base type for errors related to configuration issues, as opposed to server-side (of the driver's backing service) errors.
    """
    pass


class DriverBackendError(ObjectStorageDriverError):
    """
    Base type for errors related to the backend of the driver rather than driver code itself
    """
    pass


class DriverBackendClientError(DriverBackendError):
    """
    Errors related to the driver's client used to communicate with backend (if any, e.g. S3, Swift...)
    """

    pass


class DriverBackendServiceError(DriverBackendError):
    """
    Errors related to the driver's service backend (e.g. S3, Swift,...)
    """
    pass


class ObjectKeyNotFoundError(ObjectStorageDriverError):
    def __init__(self, userId, bucket, key, caused_by, msg=None):
        super(ObjectStorageDriverError, self).__init__(caused_by)
        self.cause = caused_by
        self.userId = userId
        self.bucket = bucket
        self.key = key
        self.detail_message = msg


class DriverNotInitializedError(StandardError):
    pass


class DriverBackendNotAvailableError(StandardError):
    pass

