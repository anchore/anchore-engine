from __future__ import annotations

from anchore_engine.services.policy_engine.engine.policy.gate import (
    BaseTrigger,
    T,
    TriggerMatch,
)


class ErrorMatch(TriggerMatch):
    """
    An instance of a fired trigger
    """

    class EmptyGate(object):
        __gate_name__ = "gate_not_found"
        __description__ = "Placeholder for executions where policy includes a gate not found in the server"

    class EmptyTrigger(BaseTrigger[T]):
        __trigger_name__ = "empty"
        __description__ = (
            "Empty trigger definition for handling errors like trigger-not-found"
        )

        def __init__(self, parent_gate_cls, msg=None):
            self.gate_cls = parent_gate_cls if parent_gate_cls else ErrorMatch.EmptyGate
            self.msg = (
                "Trigger implementation not found, this is placeholder"
                if not msg
                else msg
            )

        def evaluate(self, artifact: T, context):
            """
            Evaluate against the image update the state of the trigger based on result.
            If a match/fire is found, this code should call self._fire(), which may be called for each occurrence of a condition
            match.

            Result is the population of self._fired_instances, which can be accessed via the 'fired' property
            """
            raise NotImplementedError

    def __init__(self, trigger, match_instance_id=None, msg=None):
        self.trigger = (
            trigger if trigger else ErrorMatch.EmptyTrigger(ErrorMatch.EmptyGate)
        )
        self.id = match_instance_id if match_instance_id else "evaluation_error"
        self.msg = msg

    def json(self):
        return {
            "trigger": self.trigger.__trigger_name__,
            "trigger_id": self.id,
            "message": self.msg,
        }


class WhitelistedTriggerMatch(TriggerMatch):
    """
    A recursive type extension for trigger match to indicate a whitelist match. May match against a base trigger match or
    another type of trigger match including other WhitelistedTriggerMatches.
    """

    def __init__(self, trigger_match, matched_whitelist_item):
        super(WhitelistedTriggerMatch, self).__init__(
            trigger_match.trigger, trigger_match.id, trigger_match.msg
        )
        self.whitelist_match = matched_whitelist_item

    def is_whitelisted(self):
        return self.whitelist_match is not None

    def whitelisted_json(self):
        return {
            "whitelist_name": self.whitelist_match.parent_whitelist.name,
            "whitelist_id": self.whitelist_match.parent_whitelist.id,
            "matched_rule_id": self.whitelist_match.id,
        }

    def json(self):
        j = super(WhitelistedTriggerMatch, self).json()

        # Note: encode this as an object in the 'whitelisted' col for tabular output.
        # Note when rendering to json for result, a regular FiredTrigger's 'whitelisted' column should = bool false
        j["whitelisted"] = {
            "whitelist_name": self.whitelist_match.parent_whitelist.name,
            "whitelist_id": self.whitelist_match.parent_whitelist.id,
            "matched_rule_id": self.whitelist_match.id,
        }
        return j
