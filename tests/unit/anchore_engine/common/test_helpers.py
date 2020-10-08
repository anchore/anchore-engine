import pytest
from anchore_engine.common import helpers


values = [
    pytest.param("{}", {}, id="'{}'"),
    pytest.param({}, {}, id="{}"),
    pytest.param("a string", "a string", id="'a string'"),
]


class TestSafeExtractJsonValue:

    @pytest.mark.parametrize("value, expected", values)
    def test_inputs(self, value, expected):
        result = helpers.safe_extract_json_value(value)
        assert result == expected
