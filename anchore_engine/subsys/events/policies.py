from .common import Event

_policy_resource_type = 'policy_bundle'


class PolicyBundleSyncFail(Event):
    __event_type__ = 'policy_bundle_sync_fail'
    __resource_type__ = _policy_resource_type

    def __init__(self, user_id, error=None):
        super(PolicyBundleSyncFail, self).__init__(user_id=user_id, level='ERROR', message='Failed to sync policy bundle', details=error)
