from anchore_engine.services.policy_engine.engine.policy.gate import BaseTrigger, Gate
from anchore_engine.services.policy_engine.engine.logs import get_logger
log = get_logger()


class AlwaysFireTrigger(BaseTrigger):
    """
    Trigger always fires if invoked. This is intended for implementing things like short-circuits or blacklist/whitelist of images
    """

    __trigger_name__ = 'always'
    __trigger_id__ = 'always'
    __description__ = 'Fires if present in a policy being evaluated. Useful for things like blacklisting images or testing mappings and whitelists by using this trigger in combination with policy mapping rules.'

    __msg__ = 'Unconditional trigger match'
    __params__ = {}

    def evaluate(self, image_obj, context):
        self._fire()


class AlwaysGate(Gate):
    __gate_name__ = 'always'
    __description__ = 'Triggers that fire unconditionally if present in policy, useful for things like testing and blacklisting.'
    __triggers__ = [AlwaysFireTrigger]

    def prepare_context(self, image_obj, context):
        """

        :rtype:
        """
        return context
