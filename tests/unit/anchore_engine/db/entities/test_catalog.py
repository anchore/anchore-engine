from anchore_engine.db.entities.catalog import QueueItem


def test_to_schema_returns_value():
    assert QueueItem.to_schema() is not None
