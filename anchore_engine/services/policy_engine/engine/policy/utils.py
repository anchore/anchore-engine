import re


class InputValidator(object):
    __validator_description__ = None

    def validation_criteria(self):
        raise NotImplemented()


class TypeValidator(InputValidator):
    """
    Validates the input against a specific python type: str, int, etc.

    """
    __validator_description__ = 'Must match a specific type'

    def __init__(self, expected_type):
        self.expected_type = expected_type

    def __call__(self, *args, **kwargs):
        value = args[0]
        return type(value) != self.expected_type

    def validation_criteria(self):
        return str(self.expected_type.__name__)


class RegexParamValidator(InputValidator):
    __regex__ = None
    __validator_description__ = None

    def __init__(self, regex=None):
        if regex:
            self.regex = regex
        else:
            self.regex = self.__regex__

    def validation_criteria(self):
        return self.__regex__

    def __call__(self, *args, **kwargs):
        """
        Returns boolean True for pass, False for fail validation
        :param args:
        :param kwargs:
        :return:
        """
        value = args[0]
        if type(value) not in [str, unicode]:
            return False
        return re.match(self.regex, args[0]) is not None


class CommaDelimitedNumberListValidator(RegexParamValidator):
    __regex__ = '^\s*(\d+\s*,?\s*)*\s*$'
    __validator_description__ = 'Comma delimited list of numbers'


class NameVersionListValidator(RegexParamValidator):
    __regex__ = '^\s*(\s*\S+\|\S+\s*,?\s*)*\s*$'
    __validator_description__ = 'Comma delimited list of name/version strings of format: name|version.'


class CommaDelimitedStringListValidator(RegexParamValidator):
    __regex__ = '.*'
    __validator_description__ = 'Comma delmited list of strings'


class PipeDelimitedStringListValidator(RegexParamValidator):
    __regex__ = '.*'
    __validator_description__ = 'Pipe delimited list of strings'


class IntegerValidator(RegexParamValidator):
    __regex__ = '^[\d]+$'
    __validator_description__ = 'Single integer number'


def delim_parser(param_value, item_delimiter=','):
    if param_value:
        return [i.strip() for i in param_value.strip().split(item_delimiter)]
    else:
        return []


def barsplit_comma_delim_parser(param_value, item_delimiter=',', item_splitter='|'):
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