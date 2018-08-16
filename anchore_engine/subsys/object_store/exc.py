"""
Exception types for the archive drivers to normalize errors

"""


class ObjectStorageDriverError(Exception):
    def __init__(self, cause=None):
        super(ObjectStorageDriverError, self).__init__()
        self.cause = cause


class DriverConfigurationError(ObjectStorageDriverError):
    """
    Base type for errors related to configuration issues, as opposed to server-side (of the driver's backing service) errors.
    """

    def __init__(self, message=None, cause=None):
        super(DriverConfigurationError, self).__init__(cause)
        self.message = message if message else 'Driver configuration error caused by: {}'.format(cause.args[0] if cause.args else 'Unknown')


class BadCredentialsError(DriverConfigurationError):
    def __init__(self, creds_dict, endpoint, cause=None):
        super(BadCredentialsError, self).__init__(cause)
        self.credentials = creds_dict
        self.endpoint = endpoint
        self.redacted_creds = {}
        for key, val in list(self.credentials.items()):
            if val is not None:
                if len(val) > 2:
                    self.redacted_creds[key] = val[:2] + ''.join(['*' for z in range(len(val) - 2)])
                else:
                    self.redacted_creds[key] = ['*' for z in val]
            else:
                self.redacted_creds[key] = val

        self.message = 'Invalid credentials used: {} for endpoint {}. Details: {}'.format(self.redacted_creds, endpoint, cause.args[0] if cause.args else 'Unknown')


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


class DriverNotInitializedError(Exception):
    pass


class DriverBackendNotAvailableError(Exception):
    pass

