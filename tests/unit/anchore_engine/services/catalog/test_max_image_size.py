import pytest
from unittest.mock import patch
from anchore_engine.services.catalog.catalog_impl import is_image_valid_size

max_image_size_tests = [
    {
        "image_info": {"compressed_size": 300000000},
        "get_config": lambda: {"max_compressed_image_size": 700000000},
        "is_valid": True,
    },
    {
        "image_info": {"compressed_size": 300000000},
        "get_config": lambda: {"max_compressed_image_size": 200000000},
        "is_valid": False,
    },
    {
        "image_info": {"compressed_size": 300000000},
        "get_config": lambda: {"max_compressed_image_size": None},
        "is_valid": True,
    },
    {
        "image_info": {"compressed_size": 300000000},
        "get_config": lambda: {},
        "is_valid": True,
    },
    {"image_info": {}, "get_config": lambda: {}, "is_valid": True},
    {
        "image_info": {},
        "get_config": lambda: {"max_compressed_image_size": 300000000},
        "is_valid": True,
    },
]


@patch(
    "anchore_engine.services.catalog.catalog_impl.anchore_engine.configuration.localconfig"
)
@pytest.mark.parametrize("test_context", max_image_size_tests)
def test_is_image_valid_size(mock_config, test_context):
    mock_config.get_config = test_context["get_config"]

    assert is_image_valid_size(test_context["image_info"]) == test_context["is_valid"]
