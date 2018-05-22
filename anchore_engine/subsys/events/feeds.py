from common import Event


class FeedSyncBegin(Event):
    __type__ = 'feed_sync_begin'

    def __init__(self, groups):
        super(FeedSyncBegin, self).__init__(user_id='admin', level='INFO', message='Begin feed sync', resource_type='feeds', details={'sync_feed_types': groups})


class FeedSyncComplete(Event):
    __type__ = 'feed_sync_complete'

    def __init__(self, groups):
        super(FeedSyncComplete, self).__init__(user_id='admin', level='INFO', message='Completed feed sync', resource_type='feeds', details={'sync_feed_types': groups})


class FeedSyncFail(Event):
    __type__ = 'feed_sync_fail'

    def __init__(self, groups, error):
        super(FeedSyncFail, self).__init__(user_id='admin', level='ERROR', message='Failed feed sync', resource_type='feeds', details={'error': str(error), 'sync_feed_types': groups})
