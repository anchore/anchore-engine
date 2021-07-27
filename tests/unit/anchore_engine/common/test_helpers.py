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
