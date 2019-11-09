from .common import Event, UserEvent, SystemEvent

_policy_resource_type = 'policy_bundle'

# policy user category events

class ActivePolicyBundleIdChange(UserEvent):
    __event_type__ = 'active_policy_bundle_id_change'
    __resource_type__ = _policy_resource_type

    def __init__(self, user_id, data={}):
        super(ActivePolicyBundleIdChange, self).__init__(user_id=user_id, level='INFO', message='Active policy bundle ID changed', details=data)


class ActivePolicyBundleContentChange(UserEvent):
    __event_type__ = 'active_policy_bundle_content_change'
    __resource_type__ = _policy_resource_type

    def __init__(self, user_id, data={}):
        super(ActivePolicyBundleContentChange, self).__init__(user_id=user_id, level='INFO', message='Active policy bundle content changed', details=data)


# policy system category events

class PolicyBundleSyncFail(SystemEvent):
    __event_type__ = 'policy_bundle_sync_fail'
    __resource_type__ = _policy_resource_type

    def __init__(self, user_id, error=None):
        super(PolicyBundleSyncFail, self).__init__(user_id=user_id, level='ERROR', message='Failed to sync policy bundle', details=error)

