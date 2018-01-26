from anchore_engine.services.policy_engine.engine.policy.gate import BaseTrigger, Gate
from anchore_engine.services.policy_engine.engine.logs import get_logger
log = get_logger()

class AlwaysFireTrigger(BaseTrigger):
    """
    Trigger always fires if invoked. This is intended for implementing things like short-circuits or blacklist/whitelist of images
    """

    __trigger_name__ = 'ALWAYS'
    __trigger_id__ = 'ALWAYS'
    __description__ = 'Always fires if present in a policy being evaluated'

    __msg__ = 'Unconditional trigger match'
    __params__ = {}

    def evaluate(self, image_obj, context):
        self._fire()


class AlwaysGate(Gate):
    """

    """
    __gate_name__ = "ALWAYS"
    __triggers__ = [AlwaysFireTrigger]

    def prepare_context(self, image_obj, context):
        return context
