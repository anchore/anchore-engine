import pkg_resources
import anchore_engine.subsys.servicestatus
import anchore_engine.subsys.metrics
from anchore_engine.apis.oauth import init_oauth, PasswordGrant
from anchore_engine.service import ApiService, UserFacingApiService, LifeCycleStages
from anchore_engine.configuration import localconfig


class ExternalApiService(UserFacingApiService):
    __service_name__ = "apiext"
    __spec_dir__ = pkg_resources.resource_filename(__name__, "swagger")

    __monitors__ = {
        "service_heartbeat": {
            "handler": anchore_engine.subsys.servicestatus.handle_service_heartbeat,
            "taskType": "handle_service_heartbeat",
            "args": [__service_name__],
            "cycle_timer": 60,
            "min_cycle_timer": 60,
            "max_cycle_timer": 60,
            "last_queued": 0,
            "last_return": False,
            "initialized": False,
        },
        "authz_healthchecks": {
            "handler": ApiService.build_authz_heartbeat(__service_name__),
            "taskType": "handle_authzhealthchecks",
            "args": [__service_name__],
            "cycle_timer": 60,
            "min_cycle_timer": 60,
            "max_cycle_timer": 60,
            "last_queued": 0,
            "last_return": False,
            "initialized": False,
        },
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._oauth_app = None

    def _register_instance_handlers(self):
        super()._register_instance_handlers()
        self.register_handler(LifeCycleStages.post_register, self.init_oauth)

    def init_oauth(self):
        # Initialize the oauth stuff as needed.
        expiration_config = {
            "authorization_code": 864000,
            "implicit": 3600,
            "password": int(
                localconfig.get_config()["user_authentication"]["oauth"].get(
                    "default_token_expiration_seconds"
                )
            ),
            "client_credentials": 864000,
        }

        self._oauth_app = init_oauth(
            self._application.app, [PasswordGrant], expiration_config
        )
