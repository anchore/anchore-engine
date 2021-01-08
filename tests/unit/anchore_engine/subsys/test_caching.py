#!usr/bin/env python3

import threading
import time
from typing import Optional

import pytest
from anchore_engine.subsys.caching import (
    TTLCache,
    local_named_cache,
    thread_local_cache,
)


class TestTTLCache:
    def test_cache_hit(self):
        ttl_cache: TTLCache = TTLCache()
        value: str = "test_value"
        ttl_cache.cache_it("test_key", value)
        cached: Optional[str] = ttl_cache.lookup("test_key")
        assert id(cached) == id(value)

    def test_cache_miss(self):
        ttl_cache: TTLCache = TTLCache()
        ttl_cache.cache_it("test_key", "test_value", 1)
        time.sleep(1)
        cached: Optional[str] = ttl_cache.lookup("test_key")
        assert isinstance(cached, type(None))

    def test_negative_ttl(self):
        ttl_cache: TTLCache = TTLCache()
        value: str = "test_value"
        ttl_cache.cache_it("test_key", value, -1)
        cached: Optional[str] = ttl_cache.lookup("test_key")
        assert id(cached) == id(value)

    def test_zero_ttl(self):
        ttl_cache: TTLCache = TTLCache()
        ttl_cache.cache_it("test_key", "test_value", 0)
        cached: Optional[str] = ttl_cache.lookup("test_key")
        assert isinstance(cached, type(None))

    def test_cache_flush(self):
        ttl_cache: TTLCache = TTLCache()
        ttl_cache.cache_it("test_key", "test_value")
        ttl_cache.flush()
        cached: Optional[str] = ttl_cache.lookup("test_key")
        assert isinstance(cached, type(None))

    def test_cache_delete(self):
        ttl_cache: TTLCache = TTLCache()
        ttl_cache.cache_it("test_key", "test_value")
        ttl_cache.delete("test_key")
        cached: Optional[str] = ttl_cache.lookup("test_key")
        assert isinstance(cached, type(None))


class TestLocalCaches:
    def test_threadlocal_singleton(self):
        cache: threading.local = thread_local_cache()
        cache2: threading.local = thread_local_cache()
        assert id(cache) == id(cache2)

    def test_threadlocal_has_cache(self):
        cache: threading.local = thread_local_cache()
        assert hasattr(cache, "general")
        assert isinstance(cache.general, TTLCache)

    def test_localnamed_has_name(self):
        cache: TTLCache = local_named_cache("mycache")
        tlocal: threading.local = thread_local_cache()
        assert isinstance(cache, TTLCache)
        assert hasattr(tlocal, "mycache")

    def test_threadlocal_is_thread_local(self):
        thread_cache_id: Optional[int] = None

        def thread_func():
            nonlocal thread_cache_id
            thread_cache_id = id(thread_local_cache().general)

        t1: threading.Thread = threading.Thread(target=thread_func)
        t1.start()
        t1.join()
        main_cache_id: int = id(thread_local_cache().general)
        assert main_cache_id != thread_cache_id
