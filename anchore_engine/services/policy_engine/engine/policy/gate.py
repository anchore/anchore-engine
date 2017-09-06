"""
Base types for gate implementations and triggers.

"""
import hashlib
from anchore_engine.subsys import logger

from anchore_engine.services.policy_engine.engine.policy.exceptions import InputParameterValidationError, InvalidParameterError, TriggerNotFoundError, \
    TriggerEvaluationError


class GateMeta(type):
    """
    Metaclass to create a registry for all subclasses of Gate for finding, building, and documenting the gates.
    
    """
    def __init__(cls, name, bases, dct):
        if not hasattr(cls, 'registry'):
            cls.registry = {}
        else:
            if '__gate_name__' in dct:
                gate_id = dct['__gate_name__'].lower()
                cls.registry[gate_id] = cls

        super(GateMeta, cls).__init__(name, bases, dct)


class ExecutionContext(object):
    """
    Execution context defines the gate execution environment including logging, db connections, and cache space.
    The context is configured and set for each gate invocation.
    
    """

    def __init__(self, db_session, configuration, **params):
        self.db = db_session
        self.configuration = configuration
        self.params = params
        self.data = {}


class TriggerMatch(object):
    """
    An instance of a fired trigger
    """

    def __init__(self, trigger, match_instance_id=None, msg=None):
        self.trigger = trigger
        self.id = match_instance_id
        self.msg = msg

        # Compute a hash-based trigger_id for matching purposes (this is legacy from Anchore CLI)
        if not self.id:
            gate_id = self.trigger.gate_cls.__gate_name__
            self.id = hashlib.md5(''.join([gate_id, self.trigger.__trigger_name__, self.msg])).hexdigest()

    def json(self):
        return {
            'trigger': self.trigger.__trigger_name__,
            'trigger_id': self.id,
            'message': self.msg
        }

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        return '<{}.{} Trigger:{}, Id: {}, Msg: {}>'.format(self.__class__.__module__, self.__class__.__name__, self.trigger, self.id, self.msg)


class BaseTrigger(object):
    """
    An evaluation trigger, representing something found image analysis specifically requested. Contained
    by a single gate, with execution context defined by the parent gate object.

    """

    __trigger_name__ = None  # The base name of the trigger
    __description__ = None  # The test description of the trigger for users.
    __params__ = {}  # Set of parameter names and types (int, str, float, etc) for parameterizing the trigger check
    __msg__ = None  # Default message if not defined for specific trigger instance
    __trigger_id__ = None  # If trigger has a specific id, set here, else it is calculated at evaluation time

    def __init__(self, parent_gate_cls, **kwargs):
        """
        Instantiate the trigger with a specific set of parameters. Does not evaluate the trigger, just configures
        it for execution.
        """
        self.gate_cls = parent_gate_cls
        self.msg = None
        self.eval_params = {}
        self._fired_instances = []

        # There is a more terse way to copy, but want to raise exc on mismatches... so a bit longer
        if kwargs:
            for k, v in kwargs.items():
                if k not in self.__class__.__params__:
                    raise InvalidParameterError(parameter=k, valid_parameters=self.__class__.__params__.keys(), message='Invalid parameter received. Cannot evaluate trigger with parameter')

                if callable(self.__class__.__params__[k]):
                    expected = self.__class__.__params__[k].validation_criteria() if hasattr(
                        self.__class__.__params__[k], 'validation_criteria') else 'unspecified custom validator'
                    try:
                        if not self.__class__.__params__[k](v):
                            raise InputParameterValidationError(parameter=k, expected=expected, got=v,
                                                                message='Parameter validation failed')
                    except InputParameterValidationError:
                        raise
                    except Exception  as e:
                        raise InputParameterValidationError(parameter=k, expected=expected, got=v,
                                                            message='Parameter validation failed: {}'.format(e.message))

                if (type(self.__class__.__params__[k]) == type and not isinstance(v, self.__class__.__params__[k]) and not (type(v) == unicode and self.__class__.__params__[k] == str)):
                    raise InputParameterValidationError(parameter=k, expected=self.__class__.__params__[k], got=v,
                                                        message='Parameter validation failed')
                else:
                    self.eval_params[k] = v

    def legacy_str(self):
        """
        Returns a string in the format of the old anchore gate file outputs:
        <TRIGGER> <MSG>
        :return: str
        """
        return self.__trigger_name__ + ' ' + self.msg

    def execute(self, image_obj, context):
        """
        Main entry point for the trigger execution. Will clear any previously saved exec state and call the evaluate() function.
        :param image_obj:
        :param context:
        :return:
        """
        self.reset()
        try:
            self.evaluate(image_obj, context)
        except Exception as e:
            logger.exception('Error evaluating trigger. Aborting trigger execution')
            raise TriggerEvaluationError(trigger=self, message='Error executing gate {} trigger {} with params: {}. Msg: {}'.format(self.gate_cls.__gate_name__, self.__trigger_name__, self.eval_params, e.message))

        return True

    def evaluate(self, image_obj, context):
        """
        Evaluate against the image update the state of the trigger based on result.
        If a match/fire is found, this code should call self._fire(), which may be called for each occurrence of a condition
        match.

        Result is the population of self._fired_instances, which can be accessed via the 'fired' property
        """
        raise NotImplementedError()

    def _fire(self, instance_id=None, msg=None):
        """
        Internal function used by evaluation code to indicate a match found. May be called many times and results in
        a record added to the _fired_instances list

        :param instance_id: an id to associate with this specific firing. optional. e.g. CVE ID, filename, etc
        :param msg: A specific message (may be visible to users) for detail on the fired trigger
        :return: 
        """
        if not msg:
            msg = self.__msg__

        self._fired_instances.append(TriggerMatch(self, match_instance_id=instance_id, msg=msg))

    @property
    def did_fire(self):
        return len(self._fired_instances) > 0

    @property
    def fired(self):
        return self._fired_instances

    def reset(self):
        """
        To be called between invocations with different images and contexts
        :return:
        """
        self._fired_instances = []

    def json(self):
        return {
            'name': self.__trigger_name__,
            'trigger_id': self.__trigger_id__,
            'params': self.__params__.keys() if self.__params__ else [],
            'fired': [f.json() for f in self.fired]
        }

    @classmethod
    def config_json(cls):
        return {
            'name': cls.__trigger_name__,
            'params': cls.__params__.keys() if cls.__params__ else [],
            'id': cls.__trigger_id__
        }

    def __repr__(self):
        return '<{}.{} object Name:{}, TriggerId:{}, Params:{}>'.format(self.__class__.__module__, self.__class__.__name__, self.__trigger_name__, self.__trigger_id__, self.__params__ if self.__params__ else [])

class Gate(object):
    """
    Base type for a gate module.
    
    __gate_name__: The name to map to the policy item (e.g. DOCKERFILECHECK)
    
    To associate triggers with a gate, declare scoped classes within the Gate class. E.g.
    class MyGate(Gate):
       class MyTrigger(BaseTrigger):
         __trigger_base__ = 'MyTrigger1'
         __description__ = 'My testing trigger that fires for, like, no reason at all.'
         __params__ = {'Danger': bool, 'Zone': str}
         
    To ensure a gate is updated on data changes, configure __watches__ to include the list of WatchFilters for
    the entity classes that impact this gate. Example: AnchoreSec gate watches Vulnerabilities, and GemCheck watches AppliationPackages
    
    A gate is a collection of Triggers and a configured execution environment for each. It receives a basic execution
    context from the caller, but can customize it before executing each trigger. Generally a gate groups a set of triggers
    that use a common setup and execution context (e.g. docker file checks or vulnerability checks)
    
    The result of a gate evaluation is an ExecutionResult.
    
    """
    __metaclass__ = GateMeta

    __gate_name__ = None
    __triggers__ = []

    @classmethod
    def has_trigger(cls, name):
        """
        Returns true if the given name is a valid trigger name for triggers associated with this Gate
        :param name: 
        :return: 
        """
        return any(map(lambda x: x.__trigger_name__ == name, cls.__triggers__))

    @classmethod
    def get_trigger_named(cls, name):
        """
        Returns an the trigger class with the specified name
        :param name: name to match against the trigger classes' __trigger_name__ value 
        :return: a trigger class object 
        """
        found = filter(lambda x: x.__trigger_name__ == name, cls.__triggers__)
        if found:
            return found[0]
        else:
            raise TriggerNotFoundError(trigger_name=name, gate_name=cls.__gate_name__)

    def __init__(self):
        """
        Intialize the gate for execution with the specified context from C{ExecutionContext}.
        
        :param context: a context providing db connections, etc 
        """
        self.image = None
        self.selected_triggers = None
        self.evaluated_triggers = []
        self.evaluated_at = None
        self.evaluation_duration = None
        self.evaluation_success = False

    def prepare_context(self, image_obj, context):
        """
        Called immediately prior to gate execution, a hook to allow optimizations or prep of the context or image
        data prior to execution of the gate/triggers.
        :return:         
        """
        return context

    def json(self):
        """
        Return a json-dict of the gate definition
        :return: 
        """
        trigger_json = [t.config_json() for t in self.__triggers__]
        eval_json = [t.json() for t in self.evaluated_triggers] if self.evaluated_triggers else []

        return {
            'name': self.__gate_name__,
            'configured_triggers': trigger_json,
            'evaluation': {
                'triggers': eval_json,
                'timestamp': self.evaluated_at,
                'duration': self.evaluation_duration
            }
        }

    @classmethod
    def config_json(cls):
        """
        Return a json-dict of the gate definition
        :return: 
        """
        trigger_json = [t.json() for t in cls.__triggers__]
        return {
            'name': cls.__gate_name__,
            'triggers': trigger_json
        }

    def __repr__(self):
        return '<Gate {}>'.format(self.__gate_name__)