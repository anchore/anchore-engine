import anchore_engine.subsys.servicestatus
import anchore_engine.subsys.metrics

from anchore_engine.service import ApiService


class ExternalApiService(ApiService):
    __service_name__ = 'apiext'
    __spec_dir__ = 'services/apiext/swagger'

    __monitors__ = {
        'service_heartbeat': {'handler': anchore_engine.subsys.servicestatus.handle_service_heartbeat, 'taskType': 'handle_service_heartbeat', 'args': [__service_name__], 'cycle_timer': 60, 'min_cycle_timer': 60, 'max_cycle_timer': 60, 'last_queued': 0, 'last_return': False, 'initialized': False},
    }
