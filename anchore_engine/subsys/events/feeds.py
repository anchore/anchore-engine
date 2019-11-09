from .common import Event, UserEvent, SystemEvent

_feeds_resource_type = 'feeds'


class FeedSyncStart(SystemEvent):
    __event_type__ = 'feed_sync_start'
    __resource_type__ = _feeds_resource_type

    def __init__(self, groups):
        super(FeedSyncStart, self).__init__(user_id='admin', level='INFO', message='Feed sync started', details={'sync_feed_types': groups})


class FeedSyncComplete(SystemEvent):
    __event_type__ = 'feed_sync_complete'
    __resource_type__ = _feeds_resource_type

    def __init__(self, groups):
        super(FeedSyncComplete, self).__init__(user_id='admin', level='INFO', message='Feed sync completed', details={'sync_feed_types': groups})


class FeedSyncFail(SystemEvent):
    __event_type__ = 'feed_sync_fail'
    __resource_type__ = _feeds_resource_type

    def __init__(self, groups, error):
        super(FeedSyncFail, self).__init__(user_id='admin', level='ERROR', message='Feed sync failed', details={'cause': str(error), 'sync_feed_types': groups})
