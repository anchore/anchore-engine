"""
Exceptions related to policy initialization and evaluation
"""


class PolicyError(StandardError):
    """
    Base type for all policy-specific errors
    """
    severity = 'error'

    @classmethod
    def caused_by(cls, cause):
        return PolicyError(cause)

    def __str__(self):
        return '{}: severity:{} message:{}'.format(self.__class__.__name__, self.severity, self.message)


class PolicyWarning(PolicyError):
    severity = 'warn'


class NoMatchedMappingWarning(PolicyWarning):
    def __init__(self, tag):
        super(NoMatchedMappingWarning, self).__init__('No mapping rule matched the given tag {} for the bundle'.format(tag))


class EvaluationError(PolicyError):
    """
    Any error during execution of the a policy or policy component
    """
    pass


class InitializationError(PolicyError):
    """
    An error during initialization and construction of the policy bundle execution. Contains a collection of related
    errors potentially, each encountered during intialization of the bundle. This is an aggregation exception type to
    allow reporting of multiple init errors in a single raised exception.

    """
    def __init__(self, init_errors, message=None):
        super(InitializationError, self).__init__(message)
        self.causes = init_errors

    def __str__(self):
        return '{}: message:"{}" causes:{}'.format(self.__class__.__name__, self.message, [str(x) for x in self.causes] if self.causes else [])


class ValidationError(PolicyError):
    """
    An error validating the content of the policy itself against the code executing on the host. Includes everything from basic
    json schema validation to parameter validation and version checks of elements. Also includes things like runtime parameter
    validation.

    """
    pass


class PolicyNotFoundError(ValidationError):
    def __init__(self, policy_id):
        super(ValidationError, self).__init__('Policy {} not found in bundle for execution'.format(policy_id))
        self.policy = policy_id


class DuplicatePolicyIdFoundError(ValidationError):
    def __init__(self, policy_id):
        super(ValidationError, self).__init__('Policy id {} found multiple times in bundle for execution'.format(policy_id))
        self.policy = policy_id

class DuplicateWhitelistIdFoundError(ValidationError):
    def __init__(self, whitelist_id):
        super(ValidationError, self).__init__('Whitelist id {} found multiple times in bundle for execution'.format(whitelist_id))
        self.whitelist = whitelist_id


class WhitelistNotFoundError(ValidationError):
    def __init__(self, whitelist_id):
        super(ValidationError, self).__init__('Whitelist {} not found in bundle for execution'.format(whitelist_id))
        self.policy = whitelist_id


class GateNotFoundError(ValidationError):
    def __init__(self, gate_name):
        super(GateNotFoundError, self).__init__('Gate {} not found'.format(gate_name))
        self.gate = gate_name


class TriggerNotFoundError(ValidationError):
    def __init__(self, trigger_name, gate_name):
        self.trigger = trigger_name
        self.gate = gate_name

        super(TriggerNotFoundError, self).__init__('Trigger {} not found for gate {}'.format(self.trigger, self.gate))


class GateEvaluationError(EvaluationError):
    """
    Error occurred during gate initializeation or context preparation
    """
    gate = None

    def __init__(self, gate, message):
        super(GateEvaluationError, self).__init__('Gate evaluation failed for gate {} due to: {}. Detail: {}'.format(self.gate.__gate_name__, self.message, message))
        self.gate = gate


class TriggerEvaluationError(EvaluationError):
    """
    An error occured during trigger evaluation
    """
    gate = None
    trigger = None

    def __init__(self, trigger, message=None):
        params = trigger.eval_params if trigger and trigger.eval_params else []
        trigger_name = trigger.__trigger_name__ if trigger else 'unset'
        gate_name = trigger.gate_cls.__gate_name__ if trigger and trigger.gate_cls else 'unset'
        msg = 'Trigger evaluation failed for gate {} and trigger {}, with parameters: ({}) due to: {}'.format(
            gate_name, trigger_name, params, message)

        super(TriggerEvaluationError, self).__init__(msg)
        self.trigger = trigger
        self.gate = trigger.gate_cls


class TriggerNotAvailableError(PolicyError):
    """
    This trigger is not available for execution at this time and will not be evaluated.

    """
    gate = None
    trigger = None
    severity = 'warn'


class InputParameterValidationError(ValidationError):
    parameter = None
    expected = None
    got = None

    def __init__(self, parameter, expected, got, message=None):
        msg = 'Parameter {} is not formatted correctly or contains an invalid value: {}. Expected: {}. Detail:"{}"'.format(parameter,
                                                                                                        got, expected, message)
        super(InputParameterValidationError, self).__init__(msg)
        self.parameter = parameter
        self.expected = expected
        self.got = got


class InvalidParameterError(ValidationError):
    parameter = None
    valid_parameters = None

    def __init__(self, parameter, valid_parameters, message=None):
        msg = 'Parameter {} is not in the valid parameters list: {}. Detail:"{}"'.format(parameter, valid_parameters, message)
        super(InvalidParameterError, self).__init__(msg)
        self.parameter = parameter
        self.valid_parameters = valid_parameters


class InvalidGateAction(ValidationError):
    action = None
    valid_actions = None

    def __init__(self, gate_name, trigger_name, action, valid_actions):
        super(InvalidGateAction, self).__init__('Invalid gate action: {} specified with gate {} and trigger {}. Not in list of valid actions: {}'.format(action, gate_name, trigger_name, valid_actions))
        self.action = action
        self.valid_actions = valid_actions


class UnsupportedVersionError(ValidationError):
    """
    A bundle, policy, or whitelist version is unsupported.
    """
    supported_versions = None
    found_version = None

    def __init__(self, got_version, supported_versions, message):
        msg = 'Found version {}, expected one of supported versions {}. Detail:"{}"'.format(got_version, supported_versions, message)
        super(UnsupportedVersionError, self).__init__(msg)
        self.supported_versions = supported_versions
        self.found_version = got_version


class PolicyEvaluationError(EvaluationError):
    """
    Collection of errors encountered during a single policy evaluation and aggregated

    """
    errors = None

    def __init__(self, errors, message=None):
        super(PolicyEvaluationError, self).__init__(message)
        self.errors = errors


class BundleTargetTagMismatchError(EvaluationError):
    """
    A tag was used to construct the bundle but execution was attempted against a different tag value.

    """

    def __init__(self, expected_tag, attempted_tag):
        super(BundleTargetTagMismatchError, self).__init__('Bundle was initialized for tag {} but execution attempted against tag {}'.format(expected_tag, attempted_tag))

