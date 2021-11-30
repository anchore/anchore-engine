import pytest

from anchore_engine.subsys.object_store import manager


class TestManager:
    def test_get_manager_missing(self):
        with pytest.raises(Exception) as e:
            manager.get_manager()
            assert (
                e
                == "Archive object_store not initialized. Must call initialize() first"
            )

    def test_get_manager_success(self):
        manager.manager_singleton["unittest"] = True
        assert manager.get_manager("unittest") is True
