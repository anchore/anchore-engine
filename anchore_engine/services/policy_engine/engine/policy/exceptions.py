"""
Exceptions related to policy initialization and evaluation
"""


class PolicyError(Exception):
    """
    Base type for all policy-specific errors
    """
    severity = 'error'

    def __init__(self, message):
        super().__init__(message)
        self.message = message

    @classmethod
    def caused_by(cls, cause):
        return PolicyError(cause)

    def __str__(self):
        return '{}: severity:{} message:{}'.format(self.__class__.__name__, self.severity, self.message)

    def details(self):
        """
        Returns nicely formatted detail string for user consumption about the exception. Optional
        :return:
        """

        return self.message


class PolicyWarning(PolicyError):
    severity = 'warn'


class NoMatchedMappingWarning(PolicyWarning):
    def __init__(self, tag):
        super().__init__('No mapping rule matched the given tag {} for the bundle'.format(tag))


class EvaluationError(PolicyError):
    """
    Any error during execution of the a policy or policy component
    """


class PolicyEvaluationError(EvaluationError):
    """
    Collection of errors encountered during a single policy evaluation and aggregated

    """
    errors = None

    def __init__(self, errors, message=None):
        super().__init__(message)
        self.errors = errors


class BundleTargetTagMismatchError(EvaluationError):
    """
    A tag was used to construct the bundle but execution was attempted against a different tag value.

    """

    def __init__(self, expected_tag, attempted_tag):
        super().__init__('Bundle was initialized for tag {} but execution attempted against tag {}'.format(expected_tag, attempted_tag))


class InitializationError(PolicyError):
    """
    An error during initialization and construction of the policy bundle execution. Contains a collection of related
    errors potentially, each encountered during initialization of the bundle. This is an aggregation exception type to
    allow reporting of multiple init errors in a single raised exception.

    """

    def __init__(self, init_errors, message=None):
        super().__init__(message)
        self.causes = init_errors

    def __str__(self):
        return '{}: message:"{}" causes:{}'.format(self.__class__.__name__, self.message, [str(x) for x in self.causes] if self.causes else [])


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

        super().__init__(msg)
        self.trigger = trigger
        self.gate = trigger.gate_cls


class TriggerNotAvailableError(PolicyError):
    """
    This trigger is not available for execution at this time and will not be evaluated.

    """
    gate = None
    trigger = None
    severity = 'warn'


class ValidationError(PolicyError):
    """
    An error validating the content of the policy itself against the code executing on the host. Includes everything from basic
    json schema validation to parameter validation and version checks of elements. Also includes things like runtime parameter
    validation.

    """

    def details(self):
        return "{} ({})".format(self.message, ','.join(['{}={}'.format(y[0], y[1]) for y in [x for x in list(vars(self).items()) if x[0] != 'message' and not x[0].startswith('_')]]))


class ReferencedObjectNotFoundError(ValidationError):
    def __init__(self, reference_type, reference_id):
        super().__init__('Referenced bundle object not found')
        self.reference_type = reference_type
        self.reference_id = reference_id


class DuplicateIdentifierFoundError(ValidationError):
    def __init__(self, identifier_type, identifier):
        super().__init__('Object identifier found multiple times, not unique')
        self.identifier = identifier
        self.identifier_type = identifier_type


class UnsupportedVersionError(ValidationError):
    """
    A bundle, policy, or whitelist version is unsupported.
    """
    supported_versions = None
    found_version = None

    def __init__(self, got_version, supported_versions, message):
        msg = 'Found version {}, expected one of supported versions {}. Detail:"{}"'.format(got_version, supported_versions, message)
        super().__init__(msg)
        self.supported_versions = supported_versions
        self.found_version = got_version


class PolicyRuleValidationError(ValidationError):
    """
    A ValidationError for a specific policy rule, including gate, trigger, and optionally an id if present.

    """

    def __init__(self, message=None, gate=None, trigger=None, rule_id=None):
        super().__init__('Rule validation error' if not message else message)
        self.gate = gate
        self.trigger = trigger
        self.rule_id = rule_id


class GateNotFoundError(PolicyRuleValidationError):
    def __init__(self, valid_gates=None, **kwargs):
        """
        :param valid_gates:
        :param kwargs:
        """
        super().__init__('The specified gate is not found in the policy engine as a valid gate name', **kwargs)
        self.valid_gates = valid_gates


class TriggerNotFoundError(PolicyRuleValidationError):
    def __init__(self, valid_triggers, **kwargs):
        super().__init__('Trigger not found for specified gate. Valid triggers are: {}'.format(valid_triggers), **kwargs)


class GateEvaluationError(EvaluationError):
    """
    Error occurred during gate initialization or context preparation
    """
    gate = None

    def __init__(self, gate_name, message=None):
        if not message:
            message = 'Gate evaluation failed for gate {}'.format(gate_name)
        super().__init__(message)
        self.gate = gate_name


class EndOfLifedError(GateEvaluationError):
    severity = 'error'

    def __init__(self, gate_name, trigger_name=None, superceded=None):
        if trigger_name:
            msg = 'Gate/trigger {}/{} has been End-of-Lifed. It will not be evaluated, and should be removed from policies'.format(gate_name, trigger_name) + (" and replaced with '{}'".format(superceded) if superceded else '')
        else:
            msg = 'Gate {} has been End-of-Lifed. It will not be evaluated, and should be removed from policies'.format(gate_name) + (" and replaced with '{}'".format(superceded) if superceded else '')
        super().__init__(gate_name, msg)
        self.gate_name = gate_name
        self.trigger_name = trigger_name
        self.superceded_by = superceded


class DeprecationWarning(GateEvaluationError):
    severity = 'warn'

    def __init__(self, gate_name, trigger_name=None, superceded=None):
        if trigger_name:
            msg = 'Gate/trigger {}/{} is deprecated. It will continue to function, but it should be removed from policies'.format(gate_name, trigger_name) + (" and replaced with '{}'".format(superceded) if superceded else '')
        else:
            msg = 'Gate {} is deprecated. It will continue to function, but it should be removed from policies'.format(gate_name) + (" and replaced with '{}'".format(superceded) if superceded else '')
        super().__init__(gate_name, msg)
        self.gate_name = gate_name
        self.trigger_name = trigger_name
        self.superceded_by = superceded


class ParameterValueInvalidError(PolicyRuleValidationError):
    def __init__(self, validation_error, **kwargs):
        super().__init__(validation_error.message, **kwargs)
        self._validation_exception = validation_error


    @classmethod
    def from_validation_error(cls, validation_error, **kwargs):
        return ParameterValueInvalidError(message=validation_error.message, validation_error=validation_error, **kwargs)


class ParameterValidationError(ValidationError):
    def __init__(self, parameter, expected, value, message=None, **kwargs):
        super().__init__('Parameter validation failed: {}'.format(message), **kwargs)
        self.parameter = parameter
        self.expected = expected
        self.value = value


class InvalidParameterError(PolicyRuleValidationError):
    parameter = None
    valid_parameters = None

    def __init__(self, parameter, valid_parameters, **kwargs):
        msg = 'Parameter {} is not in the valid parameters list: {}'.format(parameter, valid_parameters)
        super().__init__(**kwargs)
        self.parameter = parameter
        self.valid_parameters = valid_parameters


class InvalidGateAction(PolicyRuleValidationError):
    action = None
    valid_actions = None

    def __init__(self, action, valid_actions, **kwargs):
        super().__init__(message='Invalid gate action specified', **kwargs) #: {} specified. Not in list of valid actions: {}'.format(action, valid_actions), **kwargs)
        self.action = action
        self.valid_actions = valid_actions


class RequiredParameterNotSetError(PolicyRuleValidationError):
    def __init__(self, parameter_name, **kwargs):
        super().__init__(message='Required parameter', **kwargs)#{} cannot be null'.format(parameter_name), **kwargs)
        self.required_parameter = parameter_name


class PolicyRuleValidationErrorCollection(PolicyRuleValidationError):
    """
    A collection of validation errors during an initialization. Allows aggregation of issues for a single rule validation.

    """

    def __init__(self, validation_errors, gate=None, trigger=None, rule_id=None):
        message = 'Trigger parameter validation errors encountered during rule validation'
        super().__init__(message, gate=gate, trigger=trigger)
        self.validation_errors = validation_errors
        self.gate = gate
        self.trigger = trigger
        self.rule_id = rule_id

        for err in self.validation_errors:
            if err.rule_id is None:
                err.rule_id = self.rule_id

    def __str__(self):
        return '{}: Message={} Validation errors={}'.format(self.__class__.__name__, self.message, ', '.join(['<{}>'.format(str(e)) for e in self.validation_errors]))

    def json(self):
        return {
            'error_type': self.__class__.__name__,
            'gate': self.gate,
            'trigger': self.trigger,
            'rule_id': self.rule_id,
            'message': self.message,
            'validation_errors': [str(e) for e in self.validation_errors]
        }
