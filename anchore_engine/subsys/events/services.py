from .common import Event

_service_resource_type = 'service'
_plugin_resource_type = 'plugin'


class ServiceOrphanedEvent(Event):
    __event_type__ = 'service_orphaned'
    __resource_type__ = _service_resource_type

    def __init__(self, user_id, name, host, url, cause):
        super(ServiceOrphanedEvent, self).__init__(user_id=user_id, level='ERROR', message='Service orphaned', resource_id=url,
                                                   details={'service_name': name, 'host_id': host, 'cause': cause})


class ServiceAuthzPluginHealthCheckFail(Event):
    __event_type__ = 'authz_plugin_healthcheck_failed'
    __resource_type__ = _service_resource_type

    def __init__(self, user_id, name, host, plugin, details):
        """

        :param user_id: User Id reporting
        :param name: str name of the service
        :param host: str host_id of service
        :param plugin: str name of the plugin
        :param details: json dict with
        """
        super(ServiceAuthzPluginHealthCheckFail, self).__init__(user_id=user_id,
                                                          level='ERROR',
                                                          message='Configured authz plugin failing health check',
                                                          details={'service_name': name, 'host_id': host, 'plugin': plugin, 'cause': details})

