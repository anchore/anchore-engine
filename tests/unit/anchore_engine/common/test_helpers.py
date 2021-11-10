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


class TestExtractPythonContent:

    IMAGE_DATA_STRUCTURE = {
        "imagedata": {
            "analysis_report": {
                "package_list": {
                    "pkgs.python": {
                        "base": {
                            "/usr/lib/python3/dist-packages/PyYAML": '{"cpes": ["cpe:2.3:a:PyYAML:PyYAML:3.10:*:*:*:*:python:*:*","cpe:2.3:a:python-PyYAML:PyYAML:3.10:*:*:*:*:python:*:*","cpe:2.3:a:*:PyYAML:3.10:*:*:*:*:python:*:*","cpe:2.3:a:PyYAML:PyYAML:3.10:*:*:*:*:*:*:*","cpe:2.3:a:python-PyYAML:PyYAML:3.10:*:*:*:*:*:*:*","cpe:2.3:a:*:PyYAML:3.10:*:*:*:*:*:*:*"],"license": "MIT","licenses": ["MIT"],"location": "/usr/lib/python3/dist-packages/PyYAML","origin": "Kirill Simonov <xi@resolvent.net>","package": "PyYAML","type": "PYTHON","version": "3.10"}'
                        }
                    }
                }
            }
        }
    }

    def test_valid_data(self):
        extracted_content = helpers.extract_python_content(self.IMAGE_DATA_STRUCTURE)
        key = "/usr/lib/python3/dist-packages/PyYAML"
        assert extracted_content is not None
        assert key in extracted_content
        assert extracted_content[key]["package"] == "PyYAML"
        assert extracted_content[key]["type"] == "PYTHON"
        assert extracted_content[key]["version"] == "3.10"
        assert extracted_content[key]["location"] == key
        assert extracted_content[key]["license"] == "MIT"
        assert len(extracted_content[key]["licenses"]) == 1
        assert extracted_content[key]["licenses"][0] == "MIT"
        assert len(extracted_content[key]["cpes"]) > 0


class TestMakeResponseError:
    class TestException(Exception):
        def __init__(self, msg, anchore_error_json=None):
            super().__init__(msg)
            if anchore_error_json is not None:
                self.anchore_error_json = anchore_error_json

    params = [
        pytest.param(
            {
                "errmsg": "basic-test-case",
                "in_httpcode": None,
                "details": None,
                "expected": {
                    "message": "basic-test-case",
                    "httpcode": 500,
                    "detail": {"error_codes": []},
                },
            },
            id="basic",
        ),
        pytest.param(
            {
                "errmsg": "basic-test-case",
                "in_httpcode": 400,
                "details": None,
                "expected": {
                    "message": "basic-test-case",
                    "httpcode": 400,
                    "detail": {"error_codes": []},
                },
            },
            id="basic-with-httpcode",
        ),
        pytest.param(
            {
                "errmsg": "basic-test-case",
                "in_httpcode": None,
                "details": {"test": "value"},
                "expected": {
                    "message": "basic-test-case",
                    "httpcode": 500,
                    "detail": {
                        "test": "value",
                        "error_codes": [],
                    },
                },
            },
            id="basic-with-details",
        ),
        pytest.param(
            {
                "errmsg": "basic-test-case",
                "in_httpcode": None,
                "details": {"error_codes": [500, 404]},
                "expected": {
                    "message": "basic-test-case",
                    "httpcode": 500,
                    "detail": {"error_codes": [500, 404]},
                },
            },
            id="basic-with-error-codes",
        ),
        pytest.param(
            {
                "errmsg": Exception("thisisatest"),
                "in_httpcode": None,
                "details": None,
                "expected": {
                    "message": "thisisatest",
                    "httpcode": 500,
                    "detail": {"error_codes": []},
                },
            },
            id="basic-exception",
        ),
        pytest.param(
            {
                "errmsg": TestException(
                    "testexception",
                    anchore_error_json={
                        "message": "test",
                        "httpcode": 500,
                        "detail": {"error_codes": [404]},
                    },
                ),
                "in_httpcode": 400,
                "details": None,
                "expected": {
                    "message": "test",
                    "httpcode": 500,
                    "detail": {"error_codes": [404]},
                },
            },
            id="basic-exception-with-anchore-error-json",
        ),
        pytest.param(
            {
                "errmsg": TestException(
                    "testexception",
                    anchore_error_json={
                        "message": "test",
                        "httpcode": 500,
                        "detail": {"error_codes": [404]},
                        "error_code": 401,
                    },
                ),
                "in_httpcode": 400,
                "details": None,
                "expected": {
                    "message": "test",
                    "httpcode": 500,
                    "detail": {"error_codes": [404, 401]},
                },
            },
            id="basic-exception-with-anchore-error-json-and-error-code",
        ),
        pytest.param(
            {
                "errmsg": TestException(
                    "testexception",
                    anchore_error_json='{"message": "test", "httpcode": 500, "detail": {"error_codes": [404]}}',
                ),
                "in_httpcode": 400,
                "details": None,
                "expected": {
                    "message": "test",
                    "httpcode": 500,
                    "detail": {"error_codes": [404]},
                },
            },
            id="basic-exception-with-json-string",
        ),
        pytest.param(
            {
                "errmsg": TestException(
                    "testexception",
                    anchore_error_json='{"message" "test", "httpcode": 500, "detail": {"error_codes": [404]}}',
                ),
                "in_httpcode": 400,
                "details": None,
                "expected": {
                    "message": "testexception",
                    "httpcode": 400,
                    "detail": {"error_codes": []},
                },
            },
            id="basic-exception-with-bad-json-string",
        ),
    ]

    @pytest.mark.parametrize("param", params)
    def test_make_response_error(self, param):
        actual = helpers.make_response_error(
            param["errmsg"], param["in_httpcode"], param["details"]
        )
        assert actual["message"] == param["expected"]["message"]
        assert actual["httpcode"] == param["expected"]["httpcode"]
        assert actual["detail"] == param["expected"]["detail"]
