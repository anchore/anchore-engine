import os

import pytest

from anchore_engine.analyzers.utils import dig, write_kvfile_fromdict


class TestDig:
    @pytest.fixture()
    def mixed_data(self):
        return {
            "a": {
                "b": {"c": 1},
                "d": [2, 3, 4],
                "e": (5, 6),
                "f": [{"g": (7, 8)}],
            }
        }

    def test_nested_mixed_dictionary(self, mixed_data):
        assert dig(mixed_data, "a", "b", "c") == 1

    def test_nested_mixed_list(self, mixed_data):
        assert dig(mixed_data, "a", "d", 1) == 3

    def test_nested_mixed_tuple(self, mixed_data):
        assert dig(mixed_data, "a", "e", 0) == 5

    def test_nested_mixed_depth(self, mixed_data):
        assert dig(mixed_data, "a", "f", 0, "g", 1) == 8

    def test_missing_value(self, mixed_data):
        assert dig(mixed_data, "a", "not here") == None

    def test_missing_value_with_default(self, mixed_data):
        assert dig(mixed_data, "a", "not here", default="N/A") == "N/A"

    def test_missing_value_with_fail(self, mixed_data):
        with pytest.raises(KeyError):
            assert dig(mixed_data, "a", "not here", fail=True)

    def test_missing_index_with_fail(self, mixed_data):
        with pytest.raises(IndexError):
            assert dig(mixed_data, "a", "d", 111, fail=True)

    def test_none_value(self):
        assert dig({"a": None}, "a") == None

    def test_empty_value_with_force_default(self):
        assert dig({"a": ""}, "a", force_default=12) == 12

    def test_false_value_with_force_default(self):
        assert dig({"a": False}, "a", force_default=12) == 12

    def test_explicit_empty_value_with_force_default(self):
        assert dig({"a": None}, "a", force_default=12) == 12

    def test_none_empty_value_with_force_default(self):
        assert dig({"a": "b!"}, "a", force_default=12) == "b!"


# This fixture runs to include the teardown of the file that is created as part of the
# tested method's normal execution. It also provides the parameters to the unit test below
@pytest.fixture(
    params=[
        pytest.param(
            {
                "filename": "./basic-file-test.json",
                "dict": {"key": "value"},
                "expected": "key value \n",
            },
            id="basic-file",
        ),
        pytest.param(
            {
                "filename": "./null-value-test.json",
                "dict": {"key": ""},
                "expected": "key none \n",
            },
            id="null-value",
        ),
        pytest.param(
            {
                "filename": "./nonstring-key-test.json",
                "dict": {2: ""},
                "expected": TypeError(
                    "Expected value of key 2 to be a string, found int"
                ),
            },
            id="nonstring-key",
        ),
        pytest.param(
            {
                "filename": "./key-with-spaces-test.json",
                "dict": {"space key": "value"},
                "expected": "space____key value \n",
            },
            id="key-with-spaces",
        ),
        pytest.param(
            {
                "filename": "./multiple-keys-test.json",
                "dict": {
                    "key1": "value1",
                    "key2": "value2",
                },
                "expected": "key1 value1 \nkey2 value2 \n",
            },
            id="multiple-keys",
        ),
    ]
)
def kvfile_fixture(request):
    filename = request.param.get("filename", None)
    if filename is not None:

        def delete_file():
            os.remove(filename)

        request.addfinalizer(delete_file)
    else:
        raise Exception("can't get filename")

    return request.param


def test_write_kvfile_fromdict(kvfile_fixture):
    param = kvfile_fixture
    if isinstance(param["expected"], TypeError):
        with pytest.raises(TypeError) as actualerr:
            write_kvfile_fromdict(param["filename"], param["dict"])
            assert actualerr == param["expected"]
            with open(param["filename"], "r") as f:
                actual = f.read()
                assert actual == ""
    else:
        write_kvfile_fromdict(param["filename"], param["dict"])
        with open(param["filename"], "r") as f:
            actual = f.read()
            assert actual == param["expected"]
