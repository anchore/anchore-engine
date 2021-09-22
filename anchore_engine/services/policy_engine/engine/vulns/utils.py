from anchore_engine.clients.services.common import get_service_endpoint
from anchore_engine.subsys import logger as log


def get_api_endpoint():
    """
    Utility function for fetching the url to external api
    """
    try:
        return get_service_endpoint("apiext").strip("/")
    except:
        log.warn(
            "Could not find valid apiext endpoint for links so will use policy engine endpoint instead"
        )
        try:
            return get_service_endpoint("policy_engine").strip("/")
        except:
            log.warn(
                "No policy engine endpoint found either, using default but invalid url"
            )
            return "http://<valid endpoint not found>"
