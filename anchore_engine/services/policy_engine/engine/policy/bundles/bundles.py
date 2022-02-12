from __future__ import annotations

import copy
import itertools
from abc import ABC, abstractmethod
from collections import OrderedDict
from typing import Dict, Optional, Type, Union

from anchore_engine.db import Image
from anchore_engine.services.policy_engine.engine.policy.bundles.decisions import (
    BundleDecision,
    FailurePolicyDecision,
    GateAction,
    PolicyDecision,
    PolicyRuleDecision,
)
from anchore_engine.services.policy_engine.engine.policy.bundles.mappings import (
    BaseMapping,
    ImageMappingRule,
    ImagePolicyMappingRule,
)
from anchore_engine.services.policy_engine.engine.policy.bundles.utils import (
    VersionedEntityMixin,
)
from anchore_engine.services.policy_engine.engine.policy.bundles.whitelists import (
    ExecutableWhitelistItem,
    HybridTriggerIdKeyedItemIndex,
    StandardCVETriggerIdKey,
)
from anchore_engine.services.policy_engine.engine.policy.exceptions import (
    BundleTargetTagMismatchError,
    DeprecationWarning,
    DuplicateIdentifierFoundError,
    EndOfLifedError,
    GateNotFoundError,
    InitializationError,
    InvalidGateAction,
    InvalidParameterError,
    ParameterValueInvalidError,
    PolicyError,
    PolicyEvaluationError,
    PolicyRuleValidationErrorCollection,
    ReferencedObjectNotFoundError,
    TriggerEvaluationError,
    TriggerNotFoundError,
    ValidationError,
)
from anchore_engine.services.policy_engine.engine.policy.gate import (
    BaseGate,
    BaseTrigger,
    ExecutionContext,
    GateRegistry,
    LifecycleStates,
)

# Load all the gate classes to ensure the registry is populated. This may appear unused but is necessary for proper lookup
from anchore_engine.services.policy_engine.engine.policy.gates import *
from anchore_engine.subsys import logger


class Evaluatable:
    @classmethod
    @abstractmethod
    def get_mapping_rule_class(cls) -> Type[BaseMapping]:
        ...

    @abstractmethod
    def matches_mapping(self, mapping: Union[ImageMappingRule]):
        ...

    @abstractmethod
    def execute_trigger(
        self,
        trigger: BaseTrigger,
        execution_context: ExecutionContext,
    ):
        ...

    @abstractmethod
    def prepare_gate_context(self, gate_obj: BaseTrigger, context: ExecutionContext):
        ...

    @abstractmethod
    def instantiate_bundle_execution(
        self, executable_bundle: ExecutableBundle
    ) -> BundleExecution:
        ...

    @abstractmethod
    def check_bundle_target_mismatch(self, bundle_target: Evaluatable) -> None:
        ...


class ImageEvaluatable(Evaluatable):
    _mapping_rule_class = ImageMappingRule

    def __init__(self, image_obj: Optional[Image], tag: Optional[str] = None):
        self.image_obj = image_obj
        self.tag = tag

    def __str__(self):
        return f"image {self.image_obj.digest}"

    @classmethod
    def get_mapping_rule_class(cls) -> Type[BaseMapping]:
        return cls._mapping_rule_class

    def matches_mapping(self, mapping: ImageMappingRule) -> bool:
        return mapping.matches(self.image_obj, self.tag)

    def execute_trigger(
        self, trigger: BaseTrigger, execution_context: ExecutionContext
    ) -> None:
        trigger.execute(self.image_obj, execution_context)

    def prepare_gate_context(self, gate_obj: BaseGate, context: ExecutionContext):
        return gate_obj.prepare_context(artifact=self.image_obj, context=context)

    def instantiate_bundle_execution(
        self, executable_bundle: ExecutableBundle
    ) -> BundleExecution:
        return BundleExecution(executable_bundle, self.image_obj.id, self.tag)

    def check_bundle_target_mismatch(self, bundle_target: Evaluatable):
        if bundle_target.tag and self.tag != bundle_target.tag:
            raise BundleTargetTagMismatchError(bundle_target.tag, self.tag)


class BundleExecution(object):
    """
    Bundle Execution is the resulting state from a bundle execution and includes output and warnings/errors
    occuring during execution or validation.

    """

    CLI_COMPATIBLE_HEADER_SET = [
        "Image_Id",
        "Repo_Tag",
        "Trigger_Id",
        "Gate",
        "Trigger",
        "Check_Output",
        "Gate_Action",
        "Whitelisted",
        "Policy_Id",
    ]

    def __init__(
        self,
        bundle: ExecutableBundle,
        image_id: str,
        tag: str,
        matched_mapping=None,
        decision=None,
    ):
        self.executed_bundle = bundle
        self.executed_mapping = matched_mapping
        self.image_id = image_id
        self.tag = tag
        self.bundle_decision = decision
        self.warnings = []
        self.errors = []

    def abort_with_failure(self, exception_obj):
        self.errors.append(exception_obj)
        self.bundle_decision = BundleDecision(
            policy_decisions=[FailurePolicyDecision()]
        )

    def json(self):
        return {
            "bundle": self.executed_bundle.json() if self.executed_bundle else None,
            "mapping": self.executed_mapping.json() if self.executed_mapping else None,
            "image_id": self.image_id,
            "tag": self.tag,
            "bundle_decision": self.bundle_decision.json()
            if self.bundle_decision
            else None,
            "warnings": [str(x) for x in self.warnings] if self.warnings else None,
            "errors": [str(x) for x in self.errors] if self.errors else None,
        }

    def _row_json(self, policy_rule_decision):
        """
        Return a table-row entry for the triggered item
        :param policy_rule_decision:
        :return: json-safe list of values
        """

        return [
            self.image_id,
            self.tag,
            policy_rule_decision.match.id,
            policy_rule_decision.match.trigger.gate_cls.__gate_name__,
            policy_rule_decision.match.trigger.__trigger_name__,
            policy_rule_decision.match.msg,
            policy_rule_decision.action.name,
            policy_rule_decision.match.whitelisted_json()
            if hasattr(policy_rule_decision.match, "whitelisted_json")
            else False,
            policy_rule_decision.policy_rule.parent_policy.id,
        ]

    def as_table_json(self):
        """
        Render as table-style json, compatible with anchore cli output
        :return:
        """

        aggregated_decisions = itertools.chain.from_iterable(
            [x.decisions for x in self.bundle_decision.policy_decisions]
        )
        # for policy_decision in self.bundle_decision.policy_decisions:
        #     for d in policy_decision.decisions:
        #         aggregated_decisions.append(d)

        rows = [self._row_json(t) for t in aggregated_decisions]

        table = {
            self.image_id: {
                "result": {
                    "header": self.CLI_COMPATIBLE_HEADER_SET,
                    "row_count": len(rows),
                    "rows": rows,
                    "final_action": self.bundle_decision.final_policy_decision.name,
                },
            },
            "policy_data": [],
            "whitelist_data": [],
            "policy_name": "",  # Use empty string here instead of 'null' to make more parser friendly
            "whitelist_names": [],
        }

        return table


class PolicyRule(object):
    def __init__(self, parent, policy_json=None):
        self.gate_name = policy_json.get("gate")
        self.trigger_name = policy_json.get("trigger")
        self.rule_id = policy_json.get("id")
        self.parent_policy = parent

        # Convert to lower-case for case-insensitive matches
        self.trigger_params = {
            p.get("name").lower(): p.get("value") for p in policy_json.get("params")
        }

        action = policy_json.get("action", "").lower()
        try:
            self.action = getattr(GateAction, action)
        except KeyError:
            raise InvalidGateAction(
                gate=self.gate_name,
                trigger=self.trigger_name,
                rule_id=self.rule_id,
                action=action,
                valid_actions=[
                    x for x in list(GateAction.__dict__.keys()) if not x.startswith("_")
                ],
            )

        self.error_exc = None
        self.errors = []

    def execute(self, image_obj, exec_context):
        pass


class ExecutablePolicyRule(PolicyRule):
    """
    A single rule to be compiled and executable.

    A rule is a single gate, trigger tuple with associated parameters for the trigger. The execution output
    is the set of fired trigger instances resulting from execution against a specific image.
    """

    def __init__(
        self, parent, policy_json=None, gate_registry: Type[GateRegistry] = GateRegistry
    ):
        super(ExecutablePolicyRule, self).__init__(parent, policy_json)

        # Configure the trigger instance
        try:
            self.gate_cls = gate_registry().get_gate_by_name(self.gate_name)
        except KeyError:
            # Gate not found
            self.error_exc = GateNotFoundError(
                gate=self.gate_name,
                valid_gates=gate_registry().registered_gate_names(),
                rule_id=self.rule_id,
            )
            self.configured_trigger = None
            raise self.error_exc

        try:
            selected_trigger_cls = self.gate_cls.get_trigger_named(
                self.trigger_name.lower()
            )
        except KeyError:
            self.error_exc = TriggerNotFoundError(
                valid_triggers=self.gate_cls.trigger_names(),
                trigger=self.trigger_name,
                gate=self.gate_name,
                rule_id=self.rule_id,
            )
            self.configured_trigger = None
            raise self.error_exc

        try:
            try:
                self.configured_trigger = selected_trigger_cls(
                    parent_gate_cls=self.gate_cls,
                    rule_id=self.rule_id,
                    **self.trigger_params,
                )
            except (
                TriggerNotFoundError,
                InvalidParameterError,
                ParameterValueInvalidError,
            ) as e:
                # Error finding or initializing the trigger
                self.error_exc = e
                self.configured_trigger = None

                if hasattr(e, "gate") and e.gate is None:
                    e.gate = self.gate_name
                if hasattr(e, "trigger") and e.trigger is None:
                    e.trigger = self.trigger_name
                if hasattr(e, "rule_id") and e.rule_id is None:
                    e.rule_id = self.rule_id
                raise e
        except PolicyError:
            raise  # To filter out already-handled errors
        except Exception as e:
            raise ValidationError.caused_by(e)

    def execute(self, evaluatable: Evaluatable, exec_context: ExecutionContext):
        """
        Execute the trigger specified in the rule with the image and gate (for prepared context) and exec_context)

        :param evaluatable: The source to execute against
        :param exec_context: The prepared execution context from the gate init
        :return: a tuple of a list of errors and a list of PolicyRuleDecisions, one for each fired trigger match produced by the trigger execution
        """

        try:
            if not self.configured_trigger:
                logger.error(
                    "No configured trigger to execute for gate {} and trigger: {}. Returning".format(
                        self.gate_name, self.trigger_name
                    )
                )
                raise TriggerNotFoundError(
                    trigger_name=self.trigger_name, gate_name=self.gate_name
                )

            if self.gate_cls.__lifecycle_state__ == LifecycleStates.eol:
                self.errors.append(
                    EndOfLifedError(
                        gate_name=self.gate_name,
                        superceded=self.gate_cls.__superceded_by__,
                    )
                )
            elif self.gate_cls.__lifecycle_state__ == LifecycleStates.deprecated:
                self.errors.append(
                    DeprecationWarning(
                        gate_name=self.gate_name,
                        superceded=self.gate_cls.__superceded_by__,
                    )
                )
            elif self.configured_trigger.__lifecycle_state__ == LifecycleStates.eol:
                self.errors.append(
                    EndOfLifedError(
                        gate_name=self.gate_name,
                        trigger_name=self.trigger_name,
                        superceded=self.configured_trigger.__superceded_by__,
                    )
                )
            elif (
                self.configured_trigger.__lifecycle_state__
                == LifecycleStates.deprecated
            ):
                self.errors.append(
                    DeprecationWarning(
                        gate_name=self.gate_name,
                        trigger_name=self.trigger_name,
                        superceded=self.configured_trigger.__superceded_by__,
                    )
                )

            try:
                evaluatable.execute_trigger(self.configured_trigger, exec_context)
            except TriggerEvaluationError:
                raise
            except Exception as e:
                logger.exception("Unmapped exception caught during trigger evaluation")
                raise TriggerEvaluationError(
                    trigger=self.configured_trigger,
                    message="Could not evaluate trigger",
                )

            matches = self.configured_trigger.fired
            decisions = []

            # Try all rules and record all decisions and errors so multiple errors can be reported if present, not just the first encountered
            for match in matches:
                try:
                    decisions.append(
                        PolicyRuleDecision(trigger_match=match, policy_rule=self)
                    )
                except TriggerEvaluationError as e:
                    logger.exception(
                        "Policy rule decision mapping exception: {}".format(e)
                    )
                    self.errors.append(str(e))

            return self.errors, decisions
        except Exception as e:
            logger.exception(
                "Error executing trigger {} on {}".format(
                    self.trigger_name, evaluatable
                )
            )
            raise

    def _safe_execute(self, image_obj, exec_context):
        """
        An alternate execution path that treats failures like specific triggers so they can be handled with
        whitelists etc. NOT CURRENTLY USED!

        :param image_obj:
        :param exec_context:
        :return:
        """
        pass
        # matches = None
        # try:
        #     if not self.configured_trigger:
        #         if self.gate_cls:
        #             err_trigger = ErrorMatch.EmptyTrigger(parent_gate_cls=self.gate_cls,
        #                                                   msg='Trigger not found: {}'.format(self.trigger_name))
        #             err_trigger._fire(instance_id='invalid_trigger',
        #                               msg='Trigger {} not found in gate'.format(self.trigger_name))
        #             self.configured_trigger = err_trigger
        #         else:
        #             match = None
        #             return [PolicyRuleFailure(trigger_match=match, policy_rule=self,
        #                                   failure_msg='No implementation found for gate/trigger: {}/{}'.format(
        #                                       self.gate_name, self.trigger_name), failure_cause=self.error_exc)]
        #     else:
        #         # Normal execution
        #         try:
        #             self.configured_trigger.execute(image_obj, exec_context)
        #         except Exception as e:
        #             log.exception('Error executing trigger on image {}'.format(image_obj.id))
        #             if self.configured_trigger.fired:
        #
        #
        #
        #     matches = self.configured_trigger.fired
        #     raise Exception('Always fail!!')
        #     decisions = [PolicyRuleDecision(trigger_match=match, policy_rule=self) for match in matches]
        #     return decisions
        # except Exception as e:
        #     if matches:
        #         return [PolicyRuleFailure(trigger_match=matches, policy_rule=self, failure_msg='Error evaluating rule', failure_cause=e)]
        #     else:
        #         return [PolicyRuleFailure(trigger_match=ErrorMatch(trigger=self.configured_trigger), policy_rule=self, failure_msg='Error evaluating rule', failure_cause=e)]

    def json(self):
        return {
            "gate": self.gate_name,
            "action": self.action.name,
            "trigger": self.trigger_name,
            "params": self.trigger_params,
        }


class ExecutablePolicy(VersionedEntityMixin):
    """
    A sequence of gate triggers to be executed with specific parameters.

    The build process establishes the set of gates and triggers and the order based on the policy and configures
    each with the parameters defined in the policy document.

    Execution is the process of invoking each trigger with the proper image context and collecting the results.
    Policy executions only depend on the image analysis context, not the tag mapping.

    BaseGate objects are used only to construct the triggers and to prepare the execution context for each trigger.

    """

    @staticmethod
    def policy_rule_factory(
        policy_obj,
        policy_json,
        gate_registry: Type[GateRegistry],
        strict_validation=True,
    ):
        rule = ExecutablePolicyRule(policy_obj, policy_json, gate_registry)
        if strict_validation:
            if rule.gate_cls.__lifecycle_state__ == LifecycleStates.eol:
                raise EndOfLifedError(
                    rule.gate_name, superceded=rule.gate_cls.__superceded_by__
                )
            elif rule.configured_trigger.__lifecycle_state__ == LifecycleStates.eol:
                raise EndOfLifedError(
                    rule.gate_name,
                    trigger_name=rule.trigger_name,
                    superceded=rule.configured_trigger.__superceded_by__,
                )
        return rule

    def __init__(
        self,
        raw_json=None,
        gate_registry: Type[GateRegistry] = GateRegistry,
        strict_validation=True,
    ):
        self.raw = raw_json
        if not raw_json:
            raise ValueError("Empty whitelist json")
        self.verify_version(raw_json)
        self.version = raw_json.get("version")

        self.id = raw_json.get("id")
        self.name = raw_json.get("name")
        self.comment = raw_json.get("comment")
        self.rules = []
        errors = []

        for x in raw_json.get("rules"):
            try:
                self.rules.append(
                    self.policy_rule_factory(
                        self,
                        x,
                        gate_registry=gate_registry,
                        strict_validation=strict_validation,
                    )
                )
            except PolicyRuleValidationErrorCollection as e:
                for err in e.validation_errors:
                    errors.append(err)
            except PolicyError as e:
                errors.append(e)
            except Exception as e:
                errors.append(ValidationError.caused_by(e))

        if errors:
            raise InitializationError(
                message="Policy initialization failed due to validation errors",
                init_errors=errors,
            )

        self.gates = OrderedDict()

        # Map the rule set into a minimal set of gates to execute linked to the list of rules for each gate
        for r in self.rules:
            if r.gate_cls not in self.gates:
                self.gates[r.gate_cls] = [r]
            else:
                self.gates[r.gate_cls].append(r)

    def execute(self, evaluatable: Evaluatable, context):
        """
        Execute the policy and return the result as a list of PolicyRuleDecisions

        :param evaluatable: the image object to evaluate
        :param context: an ExecutionContext object
        :return: a PolicyDecision object
        """

        results = []
        errors = []
        for gate, policy_rules in list(self.gates.items()):
            # Initialize the gate object
            gate_obj = gate()
            exec_context = evaluatable.prepare_gate_context(gate_obj, context)
            for rule in policy_rules:
                errs, matches = rule.execute(
                    evaluatable=evaluatable, exec_context=exec_context
                )
                if errs:
                    errors += errs
                if matches:
                    results += matches

        return errors, PolicyDecision(self, results)

    def json(self):
        if self.raw:
            return self.raw
        else:
            return {
                "id": self.id,
                "name": self.name,
                "version": self.version,
                "comment": self.comment,
                "rules": [r.json() for r in self.rules],
            }


class ExecutableMapping(object):
    """
    A set of mapping rules to be evaluated against a tag name and image (image identifiers can be in mapping rules)

    Evaluates the bundle mappings in order. Order is very important and must be preserved.
    """

    def __init__(self, mapping_json=None, rule_cls=ImageMappingRule):
        self.raw = mapping_json
        self.mapping_rules = [rule_cls(rule) for rule in mapping_json]

    def execute(self, evaluatable: Evaluatable):
        """
        Execute the mapping by performing a match and returning the policy and whitelists referenced.

        :param evaluatable: loaded image object from db
        :return: ExecutableMappingRule that is the first match in the ruleset
        """
        result = [y for y in self.mapping_rules if evaluatable.matches_mapping(y)]

        # Could have more than one match, in which case return the first
        if result and len(result) >= 1:
            return result[0]
        else:
            return None

    def json(self):
        if self.raw:
            return self.raw
        else:
            return [m.json() for m in self.mapping_rules]


class BundleProvider(ABC):
    @abstractmethod
    def init_artifact_mapping(self, raw_bundle_json: Dict):
        ...

    @abstractmethod
    def init_whitelist_artifact_mapping(
        self, raw_bundle_json: Dict
    ) -> ExecutableMapping:
        ...

    @abstractmethod
    def init_blacklist_artifact_mapping(
        self, raw_bundle_json: Dict
    ) -> ExecutableMapping:
        ...

    @abstractmethod
    def optimize_mapping(self, mapping: ExecutableMapping):
        ...

    @abstractmethod
    def check_bundle_target_mismatch(self, evaluatable: Evaluatable):
        ...

    @property
    @abstractmethod
    def gate_registry(self) -> Type[GateRegistry]:
        ...


class ExecutableWhitelist(VersionedEntityMixin):
    """
    A list of items to whitelist. Executable in the sense that the whitelist can be executed against a policy output
    to result in a WhitelistedPolicyEvaluation.
    """

    _use_indexes = True

    def __init__(self, whitelist_json):
        self.raw = whitelist_json
        if not whitelist_json:
            raise ValueError("Empty whitelist json")

        self.verify_version(whitelist_json)
        self.version = whitelist_json.get("version")

        self.id = whitelist_json.get("id")
        self.name = whitelist_json.get("name")
        self.comment = whitelist_json.get("comment")

        self.items = []
        self.whitelist_item_index = HybridTriggerIdKeyedItemIndex(
            item_key_fn=StandardCVETriggerIdKey.whitelist_item_key,
            match_key_fn=StandardCVETriggerIdKey.decision_item_key,
        )
        self.items_by_gate = OrderedDict()

        for item in self.raw.get("items"):
            i = ExecutableWhitelistItem(item, self)
            self.items.append(i)
            self.whitelist_item_index.add(i)

            if not item.get("gate").lower() in self.items_by_gate:
                self.items_by_gate[item.get("gate").lower()] = []
            self.items_by_gate[item.get("gate").lower()].append(
                ExecutableWhitelistItem(item, self)
            )

    def execute(self, policyrule_decisions):
        """
        Transform the given list of fired triggers into a set of WhitelistedFiredTriggers as defined by this policy.
        Resulting list may contain a mix of FiredTrigger and WhitelistedFiredTrigger objects.

        Any trigger already whitelisted should be modified and simply passed thru.

        :param evaluation_result: a list of TriggerMatch objects or WhitelistedTrigger objects to process
        :return: a new modified list of TriggerMatch objects updated with the policy specified by this whitelist
        """

        processed_decisions = copy.deepcopy(policyrule_decisions)

        for decision in processed_decisions:
            if ExecutableWhitelist._use_indexes:
                rules = self.whitelist_item_index.candidates_for(decision)
            else:
                rules = self.items_by_gate.get(
                    decision.match.trigger.gate_cls.__gate_name__.lower(), []
                )

            # If whitelist match, wrap it with the match data, else pass thru
            for rule in rules:
                decision.match = rule.execute(decision.match)

        return processed_decisions

    def json(self):
        return {
            "id": self.id,
            "version": self.version,
            "name": self.name,
            "comment": self.comment,
            "items": [i.json() for i in self.items],
        }


class ExecutableBundle(VersionedEntityMixin):
    """
    An executable representation of a policy bundle. Usage is to configure the bundle and then
    execute it with a specific image and tag tuple. Tag is necessary for the mapping evaluation.

    The bundle is compiled without the image directly so it can be executed repeatedly with different tags and images
    each time for efficiency.
    """

    def __init__(
        self, bundle_json, bundle_provider: BundleProvider, strict_validation=True
    ):
        """
        Build and initialize the bundle. If errors are encountered they are buffered until the end and all returned
        at once in an aggregated InitializationError to ensure that all errors can be presented back to the user, not
        just the first one. The exception to that rule is the version check on the bundle itself, which is returned directly
        if the UnsupportedVersionError is raised since parsing cannot proceed reliably.

        :param bundle_json: the json the build
        :param tag: a string tag value to use to execute mapping and optimize bundle for if present (optional)
        :param strict_validation: bool to toggle support for eol/deprecated gates
        """
        if not bundle_json:
            raise ValidationError("No bundle json received")

        self.verify_version(bundle_json)

        self.raw = bundle_json
        self.id = self.raw.get("id")
        self.name = self.raw.get("name")
        self.version = self.raw.get("version")
        self.comment = self.raw.get("comment")
        self.policies = {}
        self.whitelists = {}
        self.mapping = None
        self.whitelisted_artifact_mapping = None
        self.blacklisted_artifact_mapping = None
        self.bundle_provider = bundle_provider

        self.init_errors = []

        try:
            # Build the mapping first, then build reachable policies and whitelists
            self.mapping = bundle_provider.init_artifact_mapping(self.raw)
            self.whitelisted_artifact_mapping = (
                self.bundle_provider.init_whitelist_artifact_mapping(self.raw)
            )
            self.blacklisted_artifact_mapping = (
                self.bundle_provider.init_blacklist_artifact_mapping(self.raw)
            )

            self.bundle_provider.optimize_mapping(self.mapping)

            for rule in self.mapping.mapping_rules:
                try:
                    # Build the specified policy for the rule
                    policies = {
                        policy_id: [
                            x
                            for x in self.raw.get("policies", [])
                            if x["id"] == policy_id
                        ]
                        for policy_id in rule.policy_ids
                    }

                    for policy_id in rule.policy_ids:
                        if len(policies[policy_id]) > 1:
                            raise DuplicateIdentifierFoundError(
                                identifier=policy_id, identifier_type="policy"
                            )
                        if not policies[policy_id]:
                            raise ReferencedObjectNotFoundError(
                                reference_id=policy_id, reference_type="policy"
                            )

                        self.policies[policy_id] = ExecutablePolicy(
                            policies[policy_id][0],
                            gate_registry=self.bundle_provider.gate_registry,
                            strict_validation=strict_validation,
                        )

                except Exception as e:
                    if isinstance(e, InitializationError):
                        self.init_errors += e.causes
                    else:
                        self.init_errors.append(e)

                # Build the whitelists for the rule
                for wl in rule.whitelist_ids:
                    try:
                        whitelist = [
                            x for x in self.raw.get("whitelists", []) if x["id"] == wl
                        ]
                        if not whitelist:
                            raise ReferencedObjectNotFoundError(
                                reference_id=wl, reference_type="whitelist"
                            )
                        elif len(whitelist) > 1:
                            raise DuplicateIdentifierFoundError(
                                identifier=wl, identifier_type="whitelist"
                            )

                        self.whitelists[wl] = ExecutableWhitelist(whitelist[0])
                    except Exception as e:
                        if isinstance(e, InitializationError):
                            self.init_errors += e.causes
                        else:
                            self.init_errors.append(e)

        except Exception as e:
            if isinstance(e, InitializationError):
                self.init_errors += e.causes
            else:
                self.init_errors.append(e)

    def _validate_mappings(self):
        # Validate mapping references
        for m in self.mapping.mapping_rules:
            for policy_id in m.policy_ids:
                if policy_id not in self.policies:
                    raise ReferencedObjectNotFoundError(
                        reference_id=policy_id, reference_type="policy"
                    )
            for w in m.whitelist_ids:
                if w not in self.whitelists:
                    raise ReferencedObjectNotFoundError(
                        reference_id=w, reference_type="whitelist"
                    )

    def validate(self):
        """
        Executes a validation pass on the policy bundle as constructed. Does not alter any state.
        :return: list of errors, if empty, the validation has passed
        """

        return self.init_errors

    def _process_mapping(self, bundle_exec, evaluatable: Evaluatable):
        # Execute the mapping to find the policy and whitelists to execute next

        try:
            if self.mapping:
                bundle_exec.executed_mapping = self.mapping.execute(evaluatable)
            else:
                bundle_exec.executed_mapping = None
                bundle_exec.bundle_decision = BundleDecision(
                    policy_decisions=[FailurePolicyDecision()]
                )

            return bundle_exec
        except PolicyError as e:
            logger.exception("Error executing bundle mapping")
            bundle_exec.abort_with_failure(e)
            return bundle_exec
        except Exception as e:
            logger.exception("Error executing bundle mapping")
            bundle_exec.abort_with_failure(PolicyError.caused_by(e))
            return bundle_exec

    def _process_mapping_result(
        self,
        bundle_exec: BundleExecution,
        evaluatable: Evaluatable,
        context: ExecutionContext,
    ):
        # Evaluate the selected policy or set none if none found

        try:
            if bundle_exec.executed_mapping:
                evaluated_policies = [
                    self.policies[p_id]
                    for p_id in bundle_exec.executed_mapping.policy_ids
                ]
            else:
                evaluated_policies = None
        except KeyError:
            # Referenced policy is not found, mark error
            bundle_exec.abort_with_failure(
                ReferencedObjectNotFoundError(
                    reference_id=bundle_exec.executed_mapping.policy_id,
                    reference_type="policy",
                )
            )
            return bundle_exec

        try:
            policy_decisions = []
            if evaluated_policies:
                for evaluated_policy in evaluated_policies:
                    errors, policy_decision = evaluated_policy.execute(
                        evaluatable=evaluatable, context=context
                    )
                    if errors:
                        logger.warn(
                            "Evaluation encountered errors/warnings: {}".format(errors)
                        )
                        bundle_exec.errors += errors

                    # Send thru the whitelist handlers
                    for wl in bundle_exec.executed_mapping.whitelist_ids:
                        policy_decision.decisions = self.whitelists[wl].execute(
                            policy_decision.decisions
                        )

                    policy_decisions.append(policy_decision)
            else:
                errors = None

            # Send thru the whitelist mapping
            whitelisted_artifact_match = None
            if self.whitelisted_artifact_mapping:
                whitelisted_artifact_match = self.whitelisted_artifact_mapping.execute(
                    evaluatable
                )

            # Send thru the blacklist mapping
            blacklisted_artifact_match = None
            if self.blacklisted_artifact_mapping:
                blacklisted_artifact_match = self.blacklisted_artifact_mapping.execute(
                    evaluatable
                )

            bundle_exec.bundle_decision = BundleDecision(
                policy_decisions=policy_decisions,
                whitelist_match=whitelisted_artifact_match,
                blacklist_match=blacklisted_artifact_match,
            )

        except PolicyEvaluationError as e:
            bundle_exec.errors.append(e.errors)

        return bundle_exec

    def execute(self, evaluatable: Evaluatable, context: ExecutionContext):
        """
        Execute the bundle evaluation in isolated context (includes db session if necessary)

        :param image_id:
        :param tag_list:
        :return:
        """

        self.bundle_provider.check_bundle_target_mismatch(evaluatable)

        bundle_exec = evaluatable.instantiate_bundle_execution(self)

        if self.init_errors:
            raise InitializationError(
                message="Initialization of the bundle failed with errors",
                init_errors=self.init_errors,
            )

        bundle_exec = self._process_mapping(bundle_exec, evaluatable)

        bundle_exec = self._process_mapping_result(bundle_exec, evaluatable, context)

        return bundle_exec

    def json(self):
        if self.raw:
            return self.raw
        else:
            return {
                "id": self.id,
                "name": self.name,
                "version": self.version,
                "comment": self.comment,
                "policies": [p.json() for p in self.policies],
                "whitelists": [w.json() for w in self.whitelists],
                "mappings": self.mapping.json(),
            }


class ImageBundleProvider(BundleProvider):
    _artifact_mapping_key = "mappings"
    _wl_artifact_mapping_key = "whitelisted_images"
    _bl_artifact_mapping_key = "blacklisted_images"

    def __init__(self, tag: Optional[str] = None):
        self.target_tag = tag
        self.evaluatable = ImageEvaluatable(image_obj=None, tag=self.target_tag)

    def init_artifact_mapping(self, raw_bundle_json: Dict):
        return ExecutableMapping(
            raw_bundle_json.get(self._artifact_mapping_key, []),
            rule_cls=ImagePolicyMappingRule,
        )

    def init_whitelist_artifact_mapping(
        self, raw_bundle_json: Dict
    ) -> ExecutableMapping:
        return ExecutableMapping(
            raw_bundle_json.get(self._wl_artifact_mapping_key, []),
            rule_cls=ImageMappingRule,
        )

    def init_blacklist_artifact_mapping(
        self, raw_bundle_json: Dict
    ) -> ExecutableMapping:
        return ExecutableMapping(
            raw_bundle_json.get(self._bl_artifact_mapping_key, []),
            rule_cls=ImageMappingRule,
        )

    def optimize_mapping(self, mapping: ExecutableMapping) -> None:
        # If building for a specific tag target, only build the mapped rules, else build all rules
        if self.target_tag:
            rule = mapping.execute(self.evaluatable)
            if rule is not None:
                mapping.mapping_rules = [rule]
            else:
                mapping.mapping_rules = []

    def check_bundle_target_mismatch(self, evaluatable: Evaluatable):
        evaluatable.check_bundle_target_mismatch(bundle_target=self.evaluatable)

    @property
    def gate_registry(self) -> Type[GateRegistry]:
        return GateRegistry


def build_empty_error_execution(image_obj, tag, bundle, errors=None, warnings=None):
    """
    Creates an empty BundleExecution suitable for use in error cases where the bundle was not actually run but this object
    is needed to populate errors and warnings for return.

    :param image_obj:
    :param tag:
    :param bundle:
    :return: BundleExecution object with bundle, image, and tag set and a STOP final action.
    """

    b = BundleExecution(bundle=bundle, image_id=image_obj.id, tag=tag)
    b.bundle_decision = BundleDecision(policy_decisions=[FailurePolicyDecision()])
    b.errors = errors
    b.warnings = warnings
    return b


def build_bundle(bundle_json, for_tag=None, allow_deprecated=False):
    """
    Parse and build an executable bundle from the input. Handles versions to construct the
    proper bundle object or raises an exception if version is not supported.

    If for_tag is provided, will return a bundle build to only execute the given tag. If the mapping section
    of the bundle_json does not provide a mapping for the tag, None is returned since there is no bundle to execute for that tag.

    :param bundle_json:
    :param for_tag: the tag to build the bundle for exclusively
    :return: ExecutableBundle object
    """
    if bundle_json:
        try:
            bundle = ExecutableBundle(
                bundle_json,
                bundle_provider=ImageBundleProvider(tag=for_tag),
                strict_validation=(not allow_deprecated),
            )
        except KeyError:
            if for_tag:
                bundle = None
            else:
                raise
    else:
        raise ValueError("No bundle json found")
    return bundle
