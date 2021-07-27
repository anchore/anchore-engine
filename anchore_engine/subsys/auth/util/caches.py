from threading import RLock

from yosai.core.cache import abcs

from anchore_engine.subsys import caching


class SimpleMemoryCache(abcs.CacheHandler):
    """
    An in-memory cache similar to the redis cache used for Yosai most of the time.
    """

    __global_cache__ = caching.TTLCache(default_ttl_sec=5)
    __cache_lock__ = RLock()

    def __init__(self, *args, **kwargs):
        # logger.debug('Instantiating a {}'.format(self.__class__.__name__))
        if "max_entries" in kwargs:
            self.max_entries = int(kwargs.get("max_entries"))
        else:
            self.max_entries = 1000

    def __call__(self, *args, **kwargs):
        # logger.debug('Calling {}'.format(self.__class__.__name__))
        return SimpleMemoryCache(*args, **kwargs)

    def get(self, domain, identifier):
        # logger.debug('Get from {}'.format(self.__class__.__name__))
        key = self.generate_key(domain, identifier)
        with SimpleMemoryCache.__cache_lock__:
            return SimpleMemoryCache.__global_cache__.lookup(key)

    def get_or_create(self, domain, identifier, creator_func, creator):
        # This does not match the parent type definition, but this is the signature actually used by Yosai, not what is in the interface def

        # logger.debug('GetOrCreate from {}'.format(self.__class__.__name__))
        # logger.debug('Cache: {}'.format(self.__global_cache__.cache))
        key = self.generate_key(domain, identifier)
        with SimpleMemoryCache.__cache_lock__:
            # logger.debug('Searching for {} in cache'.format(key))
            found = SimpleMemoryCache.__global_cache__.lookup(key)
            if found:
                # logger.debug("Cache hit!")
                return found
            else:
                # logger.debug("Cache miss!")
                value = creator_func(creator)
                self.set(domain, identifier, value)
                return value

    def set(self, domain, identifier, value):
        # logger.debug('Set from {}'.format(self.__class__.__name__))
        key = self.generate_key(domain, identifier)
        with SimpleMemoryCache.__cache_lock__:
            SimpleMemoryCache.__global_cache__.cache_it(key=key, obj=value)

        # logger.debug('Cache: {}'.format(self.__global_cache__.cache))
        return value

    def delete(self, domain, identifier):
        # logger.debug('Delete from {}'.format(self.__class__.__name__))
        key = self.generate_key(domain, identifier)
        with SimpleMemoryCache.__cache_lock__:
            SimpleMemoryCache.__global_cache__.delete(key)

        # logger.debug('Cache: {}'.format(self.__global_cache__.cache))
        return None

    def generate_key(self, domain, identifier):
        # simple for now yet TBD:
        return "yosai:{0}:{1}".format(domain, identifier)

    def hmget_or_create(self, domain, identifier, keys, creator_func, creator):
        # logger.debug('{} hmget_or_create'.format(self.__class__.__name__))
        # logger.debug('Cache: {}'.format(self.__global_cache__.cache))
        key = self.generate_key(domain, identifier)  # Was self.get()
        with SimpleMemoryCache.__cache_lock__:
            found = SimpleMemoryCache.__global_cache__.lookup(key)
            if not found:
                generated = creator_func(creator)
                if type(generated) != dict:
                    raise ValueError(
                        "Creator function must return a dict object for an HM get/create operation"
                    )

                SimpleMemoryCache.__global_cache__.cache_it(key, obj=generated)
                found = generated

            if type(found) != dict:
                raise ValueError("Must have a dict as the value of a hmget entry")

            result = [v for k, v in found.items() if k in keys]
            return result

    # TODO: add entry limit, and use random selection to evict from cache on boundary conditions

    # def get_ttl(self, key):
    #    return getattr(self, key + '_ttl', self.absolute_ttl)

    # def keys(self, pattern):
    #     #logger.debug('SimpleMemoryCache keys()')
    #     return []
