import unittest

from anchore_engine.services.policy_engine.engine.policy.params import JsonSchemaValidator, BooleanStringValidator, TypeValidator, CommaDelimitedNumberListValidator, EnumValidator, \
    DelimitedEnumStringValidator, IntegerValidator, NameVersionListValidator, PipeDelimitedStringListValidator, CommaDelimitedStringListValidator, RegexParamValidator, nested_item_delim_parser, \
    delim_parser
from anchore_engine.services.policy_engine.engine.policy import params
from anchore_engine.services.policy_engine.engine.policy import gate
from anchore_engine.services.policy_engine.engine.policy.exceptions import ParameterValueInvalidError, ValidationError, RequiredParameterNotSetError


class ValidatorTestMixin(object):
    """
    Mixin for helpers for parameter validation tests
    """

    def run_matrix_test(self, value_matrix, validator):
        for input, expected in value_matrix:
            print(('Testing value: {} with expected output: {}'.format(input, expected)))
            if expected:
                self.assertTrue(validator.validate(input), msg='Expected true for input: {}'.format(input))
            else:
                with self.assertRaises(ValidationError, msg='Expected exception for input: {}'.format(input)) as e:
                    validator.validate(input)


class TestParamParsers(unittest.TestCase):
    def _run_test_table(self, table, fn):
        for t in table:
            self.assertEqual(t['result'], fn(t['test']))

    def testDelimParser(self):
        test_table = [
            {'test': 'a,b', 'result': ['a', 'b']},
            {'test': ' a , b ', 'result': ['a', 'b']},
            {'test': 'a,b,', 'result': ['a', 'b', '']}
        ]
        self._run_test_table(test_table, delim_parser)

        test_table = [
            {'test': 'a|b', 'result': ['a', 'b']},
            {'test': ' a | b ', 'result': ['a', 'b']},
            {'test': 'a|b|', 'result': ['a', 'b', '']}
        ]
        self._run_test_table(test_table, lambda x: delim_parser(param_value=x, item_delimiter='|'))

    def testBarsplitCommaDelimParser(self):
        test_table = [
            {'test': 'a|b,c|d', 'result': {'a': 'b', 'c': 'd'}},
            {'test': ' a|b , c|d ', 'result': {'a': 'b', 'c': 'd'}},
            {'test': ' a|b,c|d ', 'result': {'a': 'b', 'c': 'd'}},
            {'test': ' a-b.c-09-e|b,c|d ', 'result': {'a-b.c-09-e': 'b', 'c': 'd'}},
        ]
        self._run_test_table(test_table, nested_item_delim_parser)


class TestTypeValidator(unittest.TestCase, ValidatorTestMixin):
    def test_boolean(self):
        matrix = [
            (True, True),
            (False, True),
            ('true', False),
            ('True', False),
            ('false', False),
            ('False', False),
            ('abc', False),
            (1, False),
            (['a'], False),
            ({'a': 'b'}, False)
        ]

        self.run_matrix_test(value_matrix=matrix, validator=TypeValidator("boolean"))

    def test_object(self):
        matrix = [
            ('blah', False),
            (1, False),
            (['a'], False),
            ({}, True),
            ({'a': 'b'}, True)
        ]

        self.run_matrix_test(value_matrix=matrix, validator=TypeValidator('object'))

    def test_string(self):
        matrix = [
            ('blah', True),
            ('', True),
            (1, False),
            (['a'], False),
            ({}, False),
            ({'a': 'b'}, False)
        ]

        self.run_matrix_test(value_matrix=matrix, validator=TypeValidator('string'))

    def test_array(self):
        matrix = [
            ('blah', False),
            (1, False),
            (['a'], True),
            ([], True),
            ({'a': 'b'}, False),
            ('null', False)
        ]

        self.run_matrix_test(value_matrix=matrix, validator=TypeValidator('array'))

    def test_integer(self):
        matrix = [
            ('blah', False),
            (1, True),
            (1.0, False),
            (['a'], False),
            ({}, False),
            ({'a': 'b'}, False)
        ]

        self.run_matrix_test(value_matrix=matrix, validator=TypeValidator('integer'))

    def test_number(self):
        matrix = [
            ('blah', False),
            (1, True),
            (1.0, True),
            (['a'], False),
            ({}, False),
            ({'a': 'b'}, False)
        ]

        self.run_matrix_test(value_matrix=matrix, validator=TypeValidator('number'))


class TestBooleanStringValidator(unittest.TestCase, ValidatorTestMixin):
    def test_boolean_strings(self):
        matrix = [
            ('True', True),
            ('False', True),
            ('true', True),
            ('TRUE', True),
            ('FALSE', True),
            ('false', True),
            ('blah', False),
            (1, False),
            ('1.0', False),
            ('1', False),
            ({'a': 'b'}, False),
            (['a'], False)
        ]

        self.run_matrix_test(matrix, BooleanStringValidator())


class TestJsonSchemaValidator(unittest.TestCase, ValidatorTestMixin):
    class CustomValidator(JsonSchemaValidator):
        __validation_schema__ = {
            'type': 'object',
            'required': ['id', 'name'],
            'properties': {
                'id': {
                    'type': 'string'
                },
                'name': {
                    'type': 'string'
                },
                'count': {
                    'type': 'integer'
                }
            }
        }

    def test_json(self):
        matrix = [
            ({'id': 'abc', 'name': 'testname', 'count': 123}, True),
            ({'id': 'abc', 'name': 'test'}, True),
            ('a', False),
            (1.0, False),
            ('1.1', False),
            (['a', 1, 1], False),
            ({'name': 'testname', 'count': 123}, False),  # Missing a required key
            ({'id': 'v1', 'name': 'v2', 'count': 123, 'blah': 'hello'}, True)
        ]

        v = TestJsonSchemaValidator.CustomValidator()
        self.run_matrix_test(matrix, v)


class TestRegexValidator(unittest.TestCase, ValidatorTestMixin):
    def test_regex(self):
        v = RegexParamValidator('.*')
        matrix = [
            ('abadfasd.asdfonweo;ianvoaisealnefq;olq23--=23512=5=-w=215', True),
            (1, False),
            ('', True)
        ]

        self.run_matrix_test(matrix, v)

        v = RegexParamValidator('[0-9]+')
        matrix = [
            ('1231231', True),
            ('abc', False),
            ('', False),
            (' ', False)
        ]

        self.run_matrix_test(matrix, v)


class TestRegexRelatedValidators(unittest.TestCase, ValidatorTestMixin):
    def test_commadelim_numberlist_validator(self):
        v = CommaDelimitedNumberListValidator()
        matrix = [
            ('1,2,3', True),
            (' 1, 2, 3 ', True),
            ('1', True),
            ('a', False),
            ('1,2,c', False),
            ('1,,2', False)
        ]

        self.run_matrix_test(matrix, v)

    def test_nameversion_list_validator(self):
        v = NameVersionListValidator()
        matrix = [
            ('a|1.0,b|2.0', True),
            ('a|b,c|defefes|', False),
            ('a|b', True),
            ('a|b,c|d', True),
            ('a,b', False),
            ('|a', False),
            ('a,', False),
            ('a||', False),
            ('a|,c|d', False),
            ('a', False),
            ('a,b', False),
            ('pkg1|0.1.1.1 pkg2|1.2.', False)
        ]

        self.run_matrix_test(matrix, v)

    def test_commadelim_stringlist_validator(self):
        v = CommaDelimitedStringListValidator()
        matrix = [
            ('a,b,c', True),
            ('aa,,bb', False),
            (',a', False),
            ('a,', False)
        ]

        self.run_matrix_test(matrix, v)

    def test_pipe_delim_validator(self):
        v = PipeDelimitedStringListValidator()
        matrix = [
            ('ab', True),
            ('abc|c', True),
            ('ab|c|d', True),
            ('|a', False),
            ('a|', False)
        ]

        self.run_matrix_test(matrix, v)

    def test_integer_validator(self):
        v = IntegerValidator()
        matrix = [
            ('1', True),
            ('1,2,3', False),
            ('a,b,c', False),
            ('a', False),
            ('1,2,c', False)
        ]

        self.run_matrix_test(matrix, v)

    def test_enum_validator(self):
        v = EnumValidator(['value1', 'value2'])
        matrix = [
            ('value1', True),
            ('value2', True),
            ('3', False),
            ('value1,value2', False)
        ]

        self.run_matrix_test(matrix, v)

    def test_enum_list_validator(self):
        v = DelimitedEnumStringValidator(['value1', 'value2'])
        matrix = [
            ('value1', True),
            ('value2', True),
            ('value1,value2', True),
            ('value3', False),
            ('value1,value3', False)
        ]

        self.run_matrix_test(matrix, v)


class FakeTrigger(gate.BaseTrigger):
    __trigger_name__ = 'TestingTrigger'
    __description__ = 'Not real'
    __trigger_id__ = 'Blah123'

    param1 = params.TriggerParameter(name='param_test', example_str='somevalue', description='Test parameter', validator=TypeValidator("string"), is_required=False)

    def test1(self):
        print((type(self.param1)))

class FakeGate(gate.Gate):
    __gate_name__ = 'Somegate'
    __triggers__ = [FakeTrigger]

class TestTriggerParams(unittest.TestCase):

    def test_param_basics(self):
        p = params.TriggerParameter('TestParam1', description='Param for testing basic strings', validator=TypeValidator("string"), related_to='ThisOtherParam')

        print('Trying string that should pass validation')

        # Should pass validation
        print((p.set_value('somestring')))
        print(('Got value: {}'.format(p.value())))

        print('Trying an int that should fail validation')

        # Should fail validation
        with self.assertRaises(ValidationError) as ex:
            print((p.set_value(10)))

        print(('Correctly got exception {}'.format(ex.exception)))


    def test_param_integration(self):
        t = FakeTrigger(parent_gate_cls=FakeGate, param_test='blah')
        # print('Inst value: {}'.format(t.eval_params.get(t.param1.name)))
        print(('Inst value: {}'.format(t.param1.value())))
        print(('Class value: {}'.format(t.__class__.param1.value())))
        t.test1()


class ValidatedParameterTestMixin(object):
    """
    Mixin for helpers for parameter validation tests
    """

    def run_matrix_test(self, value_matrix, parameter):
        for input, expected in value_matrix:
            print(('Testing value: {} with expected output: {}'.format(input, expected)))
            if expected:
                parameter.set_value(input)
                output = parameter.value()
                self.assertEqual(output, expected)
            else:
                with self.assertRaises(ValidationError) as e:
                    parameter.set_value(input)


class TestParameters(unittest.TestCase, ValidatedParameterTestMixin):
    def test_nameversion_stringlist_parameter(self):
        p = params.NameVersionStringListParameter(name='test1', description='test_description', is_required=False)

        test_matrix = [
            ('a|b,c|d', {'a': 'b', 'c': 'd'}),
            ('pkg1|0.1.1-abc,pkg2|1.3.5-asdf0', {'pkg1': '0.1.1-abc', 'pkg2': '1.3.5-asdf0'}),
            (' a|b , c|d', {'a': 'b', 'c': 'd'}),
            ('a,b', False),
            ('a b c', False),
            ('a|b,c,d', False),
            ('a|b|c|d', False),
            ('pkg1|0.1.1.1 pkg2|1.2.', False)
        ]

        self.run_matrix_test(test_matrix, p)

    def test_enum_string_parameter(self):
        p = params.EnumStringParameter(name='test1', description='test1_description', is_required=False, enum_values=['value1', 'value2'])

        test_matrix = [
            ('value1', 'value1'),
            ('value2', 'value2'),
            ('value3', False),
            ('value1,value2', False),
            (' ', False),
            ('', False)
        ]

        self.run_matrix_test(test_matrix, p)

    def test_enumcomma_stringlist_parameter(self):
        p = params.EnumCommaDelimStringListParameter(name='test1', description='test1_description', is_required=False, enum_values=['value1', 'value2'])

        test_matrix = [
            ('value1', ['value1']),
            ('value1,value2', ['value1', 'value2']),
            ('value1 , value2', ['value1', 'value2']),
            ('value1, value2', ['value1', 'value2']),
            ('value1, value2, value1', ['value1', 'value2', 'value1']),
            ('value3', False),
            (' ', False),
            ('', False)
        ]

        self.run_matrix_test(test_matrix, p)


if __name__ == '__main__':
    unittest.main()
