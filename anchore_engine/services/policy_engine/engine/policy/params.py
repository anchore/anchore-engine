import re
import jsonschema
import copy

from anchore_engine.services.policy_engine.engine.policy.exceptions import RequiredParameterNotSetError, ValidationError, ParameterValidationError


class InputValidator(object):
    __validator_description__ = None
    __validator_type__ = None

    def validation_criteria(self):
        """
        Returns a description of the validation criteria. May be a regex or similar executable type of validation. Returns an object with keys:

        "validator_type": <id>
        "validation_criteria": <obj>

        :return:
        """
        return None

    def json(self):
        """
        Returns a description of this validator as a json-serializable object

        :return: dict
        """
        return {
            "description": self.__validator_description__,
            "criteria": self.validation_criteria(),
            "type": self.__validator_type__
        }

    def validate(self, value):
        """
        Returns true if the value passes validation, raises an exception otherwise with details on the failure.

        Raises a ValidationError object

        :param value:
        :return:
        """
        return True

    def __call__(self, *args, **kwargs):
        if args and len(args) > 0:
            value = args[0]
        else:
            value = None

        return self.validate(value)


class JsonSchemaValidator(InputValidator):
    __validator_type__ = "JSONSchemaValidator"
    __validator_description__ = "Validates input against the specified json schema"
    __validation_schema__ = {} # Will pass everything

    def __init__(self):
        self.validation_schema = copy.deepcopy(self.__validation_schema__)

    def validate(self, value):
        try:
            jsonschema.validate(instance=value, schema=self.validation_schema)
            return True
        except jsonschema.ValidationError as e:
            raise ValidationError('JSON Schema validation failed. Schema={}, Detail={}'.format(e.schema, e.message))

    def validation_criteria(self):
        return self.validation_schema


class TypeValidator(JsonSchemaValidator):
    """
    Validates the input against a specific python type: str, int, etc.

    """
    __validator_description__ = 'A single value of a basic json type: {}'
    __validator_type__ = 'type'
    __json_types__ = ["null", "boolean", "object", "array", "number", "string", "integer"]

    def __init__(self, expected_type):
        """
        Configure validator with type name. Type names are the jsonschema type names

        :param expected_type: str name of type
        """
        super(TypeValidator, self).__init__()

        if expected_type not in self.__json_types__:
            raise ValueError('Not supported json type: {}. Must be one of: {}'.format(expected_type, self.__json_types__))

        self.expected_type = expected_type
        self.validation_schema['type'] = self.expected_type
        self.__validator_description__ = TypeValidator.__validator_description__.format(self.expected_type)


class BooleanStringValidator(JsonSchemaValidator):
    __validator_description__ = 'Value must be string representation of a boolean. One of: ["true","false"], case insensitive'
    __validator_type__ = 'BooleanString'
    __validation_schema__ = {
        'type': 'string',
        'enum': [ 'true', 'false']
    }

    def validate(self, value):
        value = str(value).lower() # handle any weird unicode chars
        return super(BooleanStringValidator, self).validate(value)


class RegexParamValidator(JsonSchemaValidator):
    __regex__ = '.*'
    __validator_type__ = 'RegexValidator'
    __validator_description__ = 'Value must pass regex match'
    __validation_schema__ = {
        'type': 'string',
        'pattern': '.*'
    }

    def __init__(self, regex=None):
        super(RegexParamValidator, self).__init__()

        if regex:
            self.regex = regex
        else:
            self.regex = self.__regex__


        # update with instance-value of subclassed, etc
        self.validation_schema['pattern'] = self.regex

    def legacy_call(self, value):
        """
        Returns boolean True for pass, False for fail validation
        :param args:
        :param kwargs:
        :return:
        """
        if type(value) not in [str, str]:
            return False
        return re.match(self.regex, value) is not None


class DelimitedStringValidator(RegexParamValidator):
    __regex__ = '^\s*(\s*({item})\s*{delim})*\s*({item}){mult}\s*$'
    __validator_description__ = 'A string of character delimited values validated by a regex'
    __validator_type__ = 'DelimitedString'
    __item_regex__ = '.*'
    __delim__ = ','

    def __init__(self, item_regex=None, delim=None):
        super(DelimitedStringValidator, self).__init__()

        if item_regex:
            self.item_regex = item_regex
        else:
            self.item_regex = self.__item_regex__

        if delim:
            self.delim = delim
        else:
            self.delim = self.__delim__

        self.regex = self.__regex__
        self.regex = self.regex.format(item=self.item_regex, delim=self.delim, mult='{1}')
        self.validation_schema['pattern'] = self.regex


class CommaDelimitedNumberListValidator(DelimitedStringValidator):
    __item_regex__ = '\d+'
    __validator_type__ = 'CommaDelimitedStringOfNumbers'
    __validator_description__ = 'Comma delimited list of numbers'


class NameVersionListValidator(DelimitedStringValidator):
    __validator_description__ = 'Comma delimited list of name/version strings of format: name|version.'
    __validator_type__ = 'CommaDelimitedStringOfNameVersionPairs'
    __item_regex__ = '[^|,]+\|[^|,]+'
    __delim__ = ','


class CommaDelimitedStringListValidator(DelimitedStringValidator):
    __item_regex__ = '[^,]+'
    __delim__ = ','
    __validator_type__ = 'CommaDelimitedStringList'
    __validator_description__ = 'Comma delimited list of strings'


class PipeDelimitedStringListValidator(DelimitedStringValidator):
    __item_regex__ = '[^|]+'
    __delim__ = '\|'
    __validator_type__ = 'PipeDelimitedStringList'
    __validator_description__ = 'Pipe delimited list of strings'


class IntegerValidator(RegexParamValidator):
    __regex__ = '^\s*[\d]+\s*$'
    __validator_type__ = 'IntegerString'
    __validator_description__ = 'Single integer number as a string'


class EnumValidator(JsonSchemaValidator):
    __enums__ = []
    __validation_schema__ = {
        'type': 'string',
        'enum': []
    }

    __validator_type__ = 'EnumString'

    def __init__(self, enums):
        super(EnumValidator, self).__init__()
        if enums:
            self.__enums__ = enums
        self.validation_schema['enum'] = self.__enums__
        self.__validator_description__= 'One of [{}]'.format(self.__enums__)


class DelimitedEnumStringValidator(RegexParamValidator):
    __enums__ = []
    __regex__ = '^\s*(({enums})\s*{delim}\s*)*({enums})\s*$'
    __validator_type__ = 'DelimitedEnumString'

    def __init__(self, enum_choices, delimiter=','):
        if enum_choices:
            self.__enums__ = enum_choices

        choice_regex = '|'.join(self.__enums__)
        self.delimiter = delimiter

        regex = self.__regex__.format(enums=choice_regex, delim=delimiter)
        super(DelimitedEnumStringValidator, self).__init__(regex=regex)
        self.__validator_description__ = 'Delimited (char={}) string where each item must be one of: [{}]'.format(self.delimiter, self.__enums__)


def delim_parser(param_value, item_delimiter=','):
    if param_value:
        return [i.strip() for i in param_value.strip().split(item_delimiter)]
    else:
        return []


def nested_item_delim_parser(param_value, item_delimiter=',', item_splitter='|'):
    """
    A parser for lists of items with a delimter where each item has a splitter (e.g. for name, version tuples)
    e.g. a|b,c|d,e|f -> {'a':'b', 'c':'d', 'e':'f'}

    :param param_value: the value to parse
    :param item_delimiter: string to delimit items
    :param item_splitter: string to split item key value pairs on
    :return:
    """
    matches = {}
    if not param_value:
        return matches

    try:
        for param in param_value.strip().split(item_delimiter):
            param = param.strip()
            if param != ['']:
                k, v = param.split(item_splitter)
                matches[k.strip()] = v.strip()
    except:
        raise ValueError(param_value)

    return matches


class TriggerParameter(object):
    """
    A generic trigger parameter and associated validation configuration to support self-describing triggers and validation functions.

    To create a parameter for a trigger, instantiate this class with a validations function.
    param = TriggerParameter('strname', description='a string', is_required=False, validator=lambda x: bool(str(x)))


    In kwargs, options are:

    sort_order: allows the trigger to define the output order of parameters in the policy spec display. It does not affect evaluation.

    """

    # Optional class-level validator if it does not require instance-specific configuration
    __validator__ = None

    def __init__(self, name, description=None, is_required=False, related_to=None, validator=None, example_str=None, **kwargs):
        """

        :param name: The name to use for the parameter, will be matched and displayed in docs (converted to lower-case for comparisons)
        :param validator: An InputValidator object to call against the input
        :param is_required: Boolean, is this a required param or not
        :param related_to: List of strings for other parameter names related to this parameter (primarily for user comprehension)
        """

        self.name = name.lower() # Use lower case for comparisons
        self.description = description
        self.required = is_required
        self.related_params = related_to
        self._param_value = None
        self.sort_order = kwargs.get('sort_order', 100)
        self.aliases = kwargs.get('aliases', [])
        self.example = example_str

        if validator:
            self.validator = validator
        else:
            self.validator = self.__validator__

    def _output_value(self):
        return self._param_value

    def value(self, default_if_none=None):
        if self._param_value is not None:
            return self._output_value()
        else:
            return default_if_none

    def set_value(self, input_value):
        if input_value is None:
            if self.required:
                raise RequiredParameterNotSetError(parameter_name=self.name)

            # Skip validation if None, no value set. This means no way to validate json 'null' cleanly but not really a use-case for that.
        else:
            try:
                if not self.validator.validate(input_value):
                    raise ParameterValidationError(parameter=self.name, value=input_value, expected=self.validator.validation_criteria())
            except ParameterValidationError:
                raise
            except Exception as e:
                raise ParameterValidationError(parameter=self.name, value=input_value, expected=self.validator.validation_criteria(), message=e.message)

        self._param_value = input_value

    def schema_json(self):
        """
        Return a json schema for this trigger parameter
        :return:
        """

        return {
            "name": self.name,
            "aliases": self.aliases,
            "description": self.description,
            "is_required": self.required,
            "related_parameters": self.related_params,
            "validator": self.validator.json()
        }


class CommaDelimitedStringListParameter(TriggerParameter):
    """
    Convenience class for paramters where the value is string of comma-delimited strings. e.g. "a,b,c"
    """

    __validator__ = CommaDelimitedStringListValidator()

    def _output_value(self):
        return delim_parser(self._param_value, ',')


class SimpleStringParameter(TriggerParameter):
    """
    Convenience class for paramters where the value is string of comma-delimited strings. e.g. "a"
    """

    __validator__ = TypeValidator(expected_type="string")


class PipeDelimitedStringListParameter(TriggerParameter):
    """
    Convenience class for paramters where the value is string of pipe-delimited strings. e.g. "a|b|c"
    """

    __validator__ = PipeDelimitedStringListValidator()

    def _output_value(self):
        return delim_parser(self._param_value, '|')


class CommaDelimitedNumberListParameter(TriggerParameter):
    """
    Convenience class for paramters where the value is string of comma-delimited strings. e.g. "1,2,3"
    """

    __validator__ = CommaDelimitedNumberListValidator()

    def _output_value(self):
        return [int(x.strip()) for x in delim_parser(self._param_value, ',')]


class NameVersionStringListParameter(TriggerParameter):
    """
    Convenience class for parameters where the value is string of comma-delimited strings. e.g. "a|b,c|d,e|f"
    """

    __validator__ = NameVersionListValidator()

    def _output_value(self):
        return nested_item_delim_parser(self._param_value, item_delimiter=',', item_splitter='|')


class EnumStringParameter(TriggerParameter):
    """
    Parameter that allows one of a list of values.

    """
    __choices__ = None
    __validator__ = None

    def __init__(self, name, description, is_required=False, related_to=None, enum_values=None, **kwargs):
        """
        :param name:
        :param description:
        :param is_required:
        :param related_to:
        :param enum_values: the list of acceptable strings
        """
        if not enum_values:
            enum_values = self.__choices__

        super(EnumStringParameter, self).__init__(name, description, is_required=is_required, related_to=related_to, validator=EnumValidator(enum_values), **kwargs)


class EnumCommaDelimStringListParameter(TriggerParameter):
    """
    A parameter that is a string that is comma delimited list of other strings each of which must be one of a set of strings.

    """

    __choices__ = None
    __validator__ = None

    def __init__(self, name, description, is_required=False, related_to=None, enum_values=None, **kwargs):
        """
        :param name:
        :param description:
        :param is_required:
        :param related_to:
        :param enum_values: the list of acceptable strings
        """
        if not enum_values:
            enum_values = self.__choices__

        super(EnumCommaDelimStringListParameter, self).__init__(name, description, is_required=is_required, related_to=related_to, validator=DelimitedEnumStringValidator(enum_values, delimiter=','), **kwargs)

    def _output_value(self):
        return delim_parser(self._param_value, item_delimiter=',')


class BooleanStringParameter(TriggerParameter):
    __validator__ = BooleanStringValidator()

    def _output_value(self):
        """
        Convert the string value into a python boolean
        :return: boolean or None if not set
        """

        return self._param_value.lower() == 'true' if self._param_value else None

class IntegerStringParameter(TriggerParameter):
    __validator__ = IntegerValidator()

    def _output_value(self):

        """
        Return a python int if set

        :return: integer or None
        """

        return int(self._param_value) if self._param_value is not None else None
