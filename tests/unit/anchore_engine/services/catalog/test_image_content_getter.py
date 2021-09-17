import pytest

from anchore_engine.services.catalog.image_content.get_image_content import (
    MultipleContentTypesGetter,
)
from anchore_engine.subsys.object_store import manager


class TestMultipleContentTypesGetter:
    @pytest.fixture
    def initialize_storage_manager(self):
        manager.manager_singleton = {manager.DEFAULT_OBJECT_STORE_MANAGER_ID: "bar"}

    @pytest.mark.parametrize(
        "request_types, content_type, expected",
        [
            pytest.param([], "", False, id="blank-blank"),
            pytest.param(None, None, False, id="none-none"),
            pytest.param([], None, False, id="blank-none"),
            pytest.param(None, "", False, id="none-blank"),
            pytest.param(["all"], "manifest", False, id="all-manifest"),
            pytest.param(["all"], "dockerfile", False, id="all-dockerfile"),
            pytest.param(["all"], "binary", True, id="all-supported"),
            pytest.param(["java"], "npm", False, id="supported-not-match"),
            pytest.param(["gem"], "gem", True, id="supported-match"),
        ],
    )
    def test_is_content_type_match(
        self, request_types, content_type, expected, initialize_storage_manager
    ):
        assert (
            MultipleContentTypesGetter(
                account_id="foo", content_types=request_types, image_digest=""
            )._is_content_type_match(content_type)
            == expected
        )
