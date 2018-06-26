from common import Event

_service_resource_type = 'service'


class ServiceOrphanedEvent(Event):
    __event_type__ = 'service_orphaned'
    __resource_type__ = _service_resource_type

    def __init__(self, user_id, name, host, url, cause):
        super(ServiceOrphanedEvent, self).__init__(user_id=user_id, level='ERROR', message='Service orphaned', resource_id=url,
                                                   details={'service_name': name, 'host_id': host, 'cause': cause})
