"""
Common base type interfaces for object storage driver providers
"""

from urllib.parse import urlparse


class ObjectStorageDriverMeta(type):
    """
    Meta class for building a registry of drivers

    """
    def __init__(cls, name, bases, dct):
        if not hasattr(cls, 'registry'):
            cls.registry = {}
        else:
            if '__config_name__' in dct:
                driver_id = dct['__config_name__']
                if cls.registry.get(driver_id):
                    raise ValueError('Conflicting archive driver names found. Found two entries for name: {}. {} and {}'.format(driver_id, name, cls.registry[driver_id].__name__))

                cls.registry[driver_id] = cls

        super(ObjectStorageDriverMeta, cls).__init__(name, bases, dct)

    def driver_for_object_url(cls, url):
        """
        Returns the driver name to use for a given url based on url scheme. Does no db lookups, only based on currently registered drivers.

        :param url:
        :return: driver class or None if none found
        """

        parsed = urlparse(url)
        for d in list(cls.registry.values()):
            if d.__uri_scheme__ == parsed.scheme:
                return d

        return None


class ObjectStorageDriver(object, metaclass=ObjectStorageDriverMeta):
    """
    Interface spec for an object storage driver for simple key/value storage of content.

    __config_name__: is the name the will correspond to the value in the configuration that determines which driver to load. It should
    be unique for each driver

    __driver_version__: version number to allow for multiple versions of the same driver name and upgrades between them with different implementations
    if necessary.

    __uri_scheme__: the scheme this driver uses for uris for matching data to drivers (e.g. 'file://', or 's3://', or 'http://')

    A driver can also be loaded in a specific mode: 'rw' (default) is full read/write, while 'r' is read-only and indended for supporting concurrent migrations between drivers if multiple are configured.

    The expected flow for operating with a driver is to save data using the userid, bucket, key components, and retrieve data using the URI returned on save operations.

    The data is expected to be a file-like stream (e.g. StringIO, file, ...)


    """

    __config_name__ = None
    __uri_scheme__ = None
    __supports_compressed_data__ = True # Used mostly for the legacy db drivers that do implicit compression but take text content

    def __init__(self, config):
        """
        Initialize the driver given the driver-specifc section of the archive configuration in the config doc.

        :param config: a dictionary with configuration values
        """
        self.config = config
        self.initialized = False

    def put(self, userId, bucket, key, data):
        """
        Save the data in backend under key identified by userId, bucket, key

        :param userId:
        :param bucket:
        :param key:
        :param data: a read() compatible object (StringIO, file, etc)
        :return: URI that can be used to lookup the data directy in the backend using get_by_uri() if desired.
        """
        raise NotImplementedError()

    def get(self, userId, bucket, key):
        """
        Return a read-able object wth content for the specified key, as bytes

        :param userId:
        :param bucket:
        :param key:
        :return:
        """
        raise NotImplementedError()

    def get_by_uri(self, uri):
        """
        Reutrn a read-able object associated with the URI for the content of the object, as bytes

        :param uri:
        :return:
        """
        raise NotImplementedError()

    def delete(self, userId, bucket, key):
        raise NotImplementedError()

    def delete_by_uri(self, uri):
        raise NotImplementedError()

    def exists(self, uri):
        raise NotImplementedError()

    def uri_for(self, userId, bucket, key):
        """
        Return a URI for the identified resource.

        :param userId:
        :param bucket:
        :param archiveId:
        :return: str uri
        """
        raise NotImplementedError()
