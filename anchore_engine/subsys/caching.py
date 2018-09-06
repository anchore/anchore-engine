"""
Module implements functions for cache structures. Primarily focused on thread-local caches.

"""
import datetime
import threading
from anchore_engine.subsys import logger


class TTLCache(object):
    def __init__(self, default_ttl_sec=60):
        self.cache = {}
        self.default_ttl = default_ttl_sec

    def cache_it(self, key, obj, ttl=None):
        if ttl is None:
            ttl = self.default_ttl
        self.cache[key] = (datetime.datetime.now() + datetime.timedelta(seconds=ttl), obj)

    def lookup(self, key):
        found = self.cache.get(key)
        if found and found[0] >= datetime.datetime.now():
            logger.spew('TTLCache {} hit for {}'.format(self.__hash__(), key))
            return found[1]
        elif found:
            self.cache.pop(key)
            logger.spew('TTLCache {} miss due to ttl for {}'.format(self.__hash__(), key))
            return None
        else:
            logger.spew('TTLCache {} miss for {}'.format(self.__hash__(), key))
            return None

    def flush(self):
        self.cache.clear()

    def delete(self, key):
        try:
            self.cache.pop(key)
        except:
            pass

# Initialize a thread-local cache
local_cache = None


def thread_local_cache():
    """
    Returns an initialized thread-local cache with a TTLCache object already initialized as property 'general'.
    For other named caches can use 'local_named_cache(name)' function to supplement the 'general' cache with additional TTLCaches to avoid
    key conflicts.

    :return:
    """
    global local_cache
    if local_cache is None:
        logger.debug('Initializing config cache')
        local_cache = threading.local()

    if not hasattr(local_cache, 'general'):
        local_cache.general = TTLCache()
        logger.debug('Added general to cache: {}'.format(local_cache.general))

    return local_cache


def local_named_cache(name):
    cache = thread_local_cache()
    if not hasattr(cache, name):
        setattr(cache, name, TTLCache())
        logger.debug('Added {} to cache: {}'.format(name, cache))

    return getattr(cache, name)
