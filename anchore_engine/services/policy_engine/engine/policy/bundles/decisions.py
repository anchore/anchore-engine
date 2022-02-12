from __future__ import annotations

import enum

from anchore_engine.services.policy_engine.engine.policy.bundles.trigger_matches import (
    ErrorMatch,
)


class GateAction(enum.IntEnum):
    """
    The outcome of a policy rule evaluation against a gate trigger
    """

    stop = -1
    warn = 0
    go = 1


class WhitelistAwarePolicyDecider(object):
    @classmethod
    def decide(cls, decisions):
        candidate_actions = [
            x.action
            for x in [d for d in decisions if not getattr(d, "is_whitelisted", False)]
        ]
        if candidate_actions:
            return min(candidate_actions)
        else:
            return GateAction.go  # No matches or everything is whitelisted


class AlwaysStopDecider(object):
    @classmethod
    def decide(cls, decisions):
        return GateAction.stop


class AlwaysGoDecider(object):
    @classmethod
    def decide(cls, decisions):
        return GateAction.go


class PolicyRuleDecision(object):
    """
    A policy decision is a combination of a TriggerMatch and an 'action' as defined by a policy.
    """

    def __init__(self, trigger_match, policy_rule):
        self.match = trigger_match
        self.policy_rule = policy_rule

    @property
    def action(self):
        """
        Returns the evaluated action from the trigger and mapped policy_rule
        :return: a rule evaluation's GateAction result
        """
        if self.match and not (
            hasattr(self.match, "is_whitelisted") and self.match.is_whitelisted
        ):
            return self.policy_rule.action
        else:
            return GateAction.go

    def json(self):
        return {
            "match": self.match.json(),
            "rule": self.policy_rule.json(),
            "action": self.action.name,
        }


class PolicyDecision(object):
    """
    A policy decision is a set of rule decisions and a final decision computed from those.
    Each policy rule decision can have whitelist decorators and if so will be ignored in the
    final decision computation.

    """

    __decider__ = WhitelistAwarePolicyDecider

    def __init__(self, policy_obj=None, rule_decisions=None):
        self.evaluated_policy = policy_obj
        self.decisions = rule_decisions if rule_decisions else []

    @property
    def final_decision(self):
        return self.__decider__.decide(self.decisions)

    def json(self):
        return {
            "policy": self.evaluated_policy.json() if self.evaluated_policy else None,
            "decisions": [r.json() for r in self.decisions] if self.decisions else None,
            "final_action": self.final_decision,
        }


class BundleDecision(object):
    """
    Extentions of a PolicyDecision to include Image Blacklist and Whitelist abilities
    """

    def __init__(self, policy_decisions, whitelist_match=None, blacklist_match=None):
        self.policy_decisions = (
            policy_decisions if policy_decisions else [FallThruPolicyDecision()]
        )
        self.whitelisted_image = whitelist_match if whitelist_match else None
        self.blacklisted_image = blacklist_match if blacklist_match else None

        self.final_policy_decision = min(
            [d.final_decision for d in self.policy_decisions]
        )

        if self.blacklisted_image:
            self.final_decision = GateAction.stop
            self.reason = "blacklisted"
        elif self.whitelisted_image:
            self.final_decision = GateAction.go
            self.reason = "whitelisted"
        else:
            self.final_decision = self.final_policy_decision
            self.reason = "policy_evaluation"

    def json(self):
        return {
            "policy_decisions": [
                policy_decision.json() for policy_decision in self.policy_decisions
            ]
            if self.policy_decisions
            else None,
            "policy_final_action": self.final_policy_decision.name,
            "matched_whitelisted_image_rule": self.whitelisted_image.json()
            if self.whitelisted_image
            else None,
            "matched_blacklisted_image_rule": self.blacklisted_image.json()
            if self.blacklisted_image
            else None,
            "final_action": self.final_decision.name,
            "reason": self.reason,
        }


class FallThruPolicyDecision(PolicyDecision):
    __decider__ = AlwaysGoDecider


class FailurePolicyDecision(PolicyDecision):
    __decider__ = AlwaysStopDecider


class PolicyRuleFailure(PolicyRuleDecision):
    """
    A failure indicator that the rule could not be evaluated.
    """

    def __init__(self, trigger_match, policy_rule, failure_msg, failure_cause):
        """
        A failure to execute. Failure-cause should be an exception, with addition info in the failure_msg

        :param trigger_match:
        :param policy_rule:
        :param failure_msg:
        :param failure_cause:
        """
        self.match = (
            trigger_match if trigger_match else ErrorMatch(None, msg=failure_msg)
        )
        self.policy_rule = policy_rule
        self.msg = failure_msg
        self.cause = failure_cause

    @property
    def action(self):
        """
        Since this is a failure indicator, it simply emits WARN actions that can be mapped to warnings

        :return: GateAction.warn
        """
        return GateAction.warn

    def json(self):
        return {
            "match": self.match.json(),
            "rule": self.policy_rule.json(),
            "action": self.action.name,
            "failed": True,
            "error_message": self.msg,
            "error_cause": self.cause.message
            if hasattr(self.cause, "message")
            else str(self.cause),
        }
