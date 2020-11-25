import pytest

from anchore_engine.analyzers.utils import dig


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
