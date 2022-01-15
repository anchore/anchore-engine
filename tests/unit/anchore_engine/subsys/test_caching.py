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


@pytest.fixture
def ttl_cache(request):
    cache: TTLCache = TTLCache()
    value: str = "test_value"
    cache.cache_it("test_key", value, request.param)
    return cache


class TestTTLCache:
    @pytest.mark.parametrize(
        "ttl_cache, sleep_time, expected_type",
        [
            (None, 0, str),
            (-1, 0, str),
            (1, 1, type(None)),
            (0, 0, type(None)),
        ],
        indirect=["ttl_cache"],
    )
    def test_cache(self, ttl_cache, sleep_time, expected_type):
        time.sleep(sleep_time)
        cached: Optional[str] = ttl_cache.lookup("test_key")
        assert isinstance(cached, expected_type)
        if expected_type != type(None):
            assert id(cached) == id("test_value")

    @pytest.mark.parametrize("ttl_cache", [(None)], indirect=["ttl_cache"])
    def test_cache_flush(self, ttl_cache):
        ttl_cache.flush()
        cached: Optional[str] = ttl_cache.lookup("test_key")
        assert isinstance(cached, type(None))

    @pytest.mark.parametrize("ttl_cache", [(None)], indirect=["ttl_cache"])
    def test_cache_delete(self, ttl_cache):
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
