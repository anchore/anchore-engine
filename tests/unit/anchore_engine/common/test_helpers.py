import pytest

from anchore_engine.common import helpers
from anchore_engine.common.helpers import make_anchore_exception

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


class TestMakeAnchoreException:

    # This handles the case where attributes are already set on the exception passed in
    err_with_attrs = Exception("test")
    err_with_attrs.anchore_error_json = {
        "message": "attr-test",
        "detail": {
            "raw_exception_message": "attribute test",
            "error_codes": [],
        },
        "httpcode": 500,
    }
    err_with_attrs.error_code = 404

    @pytest.mark.parametrize(
        "param",
        [
            pytest.param(
                {
                    "err": "test",
                    "input_message": None,
                    "input_httpcode": None,
                    "input_detail": None,
                    "override_existing": None,
                    "input_error_codes": None,
                    "expected_msg": "test",
                    "expected_anchore_json": {
                        "message": "test",
                        "detail": {
                            "raw_exception_message": "test",
                            "error_codes": [],
                        },
                        "httpcode": 500,
                    },
                },
                id="string-err-only",
            ),
            pytest.param(
                {
                    "err": Exception("test"),
                    "input_message": None,
                    "input_httpcode": None,
                    "input_detail": None,
                    "override_existing": None,
                    "input_error_codes": None,
                    "expected_msg": "test",
                    "expected_anchore_json": {
                        "message": "test",
                        "detail": {
                            "raw_exception_message": "test",
                            "error_codes": [],
                        },
                        "httpcode": 500,
                    },
                },
                id="err-only",
            ),
            pytest.param(
                {
                    "err": err_with_attrs,
                    "input_message": None,
                    "input_httpcode": None,
                    "input_detail": None,
                    "override_existing": None,
                    "input_error_codes": None,
                    "expected_msg": "test",
                    "expected_anchore_json": {
                        "message": "attr-test",
                        "detail": {
                            "raw_exception_message": "attribute test",
                            "error_codes": [404],
                        },
                        "httpcode": 500,
                    },
                },
                id="err-only-with-attrs",
            ),
            pytest.param(
                {
                    "err": err_with_attrs,
                    "input_message": "override-msg",
                    "input_httpcode": 401,
                    "input_detail": {"unit": "test"},
                    "override_existing": True,
                    "input_error_codes": [402, 403],
                    "expected_msg": "test",
                    "expected_anchore_json": {
                        "message": "override-msg",
                        "detail": {"unit": "test", "error_codes": [402, 403, 404]},
                        "httpcode": 401,
                    },
                },
                id="override-successful",
            ),
        ],
    )
    def test_make_anchore_exception(self, param):
        actual = make_anchore_exception(
            param["err"],
            param["input_message"],
            param["input_httpcode"],
            param["input_detail"],
            param["override_existing"],
            param["input_error_codes"],
        )

        assert str(actual) == param["expected_msg"]
        assert actual.anchore_error_json == param["expected_anchore_json"]
