import time

from anchore_engine.subsys import logger


def do_simple_pagination(input_items, page=1, limit=None, dosort=True, sortfunc=lambda x: x, query_digest="", ttl=0.0):
    page = int(page)
    next_page = None
    if not limit:
        return(1, None, input_items)

    limit = int(limit)
    if dosort:
        #input_items.sort()
        #input_items.sort(key=lambda x: x['image']['imageDigest'])
        input_items.sort(key=sortfunc)

    start = (page-1)*limit
    end = start + limit
    paginated_items = input_items[start:end]

    if len(paginated_items) == limit and (paginated_items[-1] != input_items[-1]):
        next_page = page + 1

    return(page, next_page, paginated_items)


pagination_cache = {}


def get_cached_pagination(query_digest=""):
    current_time = time.time()

    if query_digest not in pagination_cache:
        raise Exception("document not in pagination cache.")
    elif pagination_cache.get(query_digest, {}).get('ttl', 0.0) < current_time:
        logger.debug("expiring query cache content: {}".format(query_digest))
        el = pagination_cache.pop(query_digest, None)
        del(el)
        raise Exception("document is expired in pagination cache.")

    return(pagination_cache[query_digest]['content'])


def do_cached_pagination(input_items, page=None, limit=None, dosort=True, sortfunc=lambda x: x, query_digest="", ttl=0.0):
    current_time = time.time()

    if ttl <= 0.0:
        logger.debug("skipping cache as ttl is <= 0.0 ({})".format(ttl))
    elif query_digest not in pagination_cache:
        logger.debug("caching query content")
        pagination_cache[query_digest] = {
            'ttl': current_time + float(ttl),
            'content': list(input_items),
        }
    return(do_simple_pagination(input_items, page=page, limit=limit, dosort=dosort, sortfunc=sortfunc, query_digest=query_digest, ttl=ttl))


def make_response_paginated_envelope(input_items, envelope_key='result', page="1", limit=None, dosort=True, sortfunc=lambda x: x, pagination_func=do_simple_pagination, query_digest="", ttl=0.0):
    page, next_page, paginated_items = pagination_func(input_items, page=page, limit=limit, dosort=dosort, sortfunc=sortfunc, query_digest=query_digest, ttl=ttl)
    return_object = {
        envelope_key: paginated_items,
        'page': "{}".format(page),
        'returned_count': len(paginated_items),
        'total_count': len(input_items),
    }
    if next_page:
        return_object['next_page'] = "{}".format(next_page)

    return(return_object)