
# anchore modules
import pkg_resources
import anchore_engine.subsys.servicestatus
import anchore_engine.subsys.metrics
from anchore_engine.service import UserFacingApiService


class K8sWebhookHandlerService(UserFacingApiService):
    __service_name__ = 'kubernetes_webhook'
    __spec_dir__ = pkg_resources.resource_filename(__name__, 'swagger')

    __monitors__ = {
        'service_heartbeat': {'handler': anchore_engine.subsys.servicestatus.handle_service_heartbeat, 'taskType': 'handle_service_heartbeat', 'args': [__service_name__], 'cycle_timer': 60, 'min_cycle_timer': 60, 'max_cycle_timer': 60, 'last_queued': 0, 'last_return': False, 'initialized': False}
    }
