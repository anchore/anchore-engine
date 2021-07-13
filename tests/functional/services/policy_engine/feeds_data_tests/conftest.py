from os import path

import pytest

from anchore_engine.db.entities.policy_engine import (
    CpeV2Vulnerability,
    FeedGroupMetadata,
    FeedMetadata,
    FixedArtifact,
    Vulnerability,
)

CURRENT_DIR = path.dirname(path.abspath(__file__))
FEEDS_DATA_PATH_PREFIX = path.join("data", "v1", "service", "feeds")

DB_TABLES = [
    CpeV2Vulnerability,
    FeedGroupMetadata,
    FeedMetadata,
    FixedArtifact,
    Vulnerability,
]


@pytest.fixture(scope="package", autouse=True)
def clear_database_state(
    request, set_env_vars, anchore_db, teardown_and_recreate_tables
) -> None:
    """
    Writes database seed file content to database. This allows us to ensure consistent vulnerability results (regardless of feed sync status).
    """
    tablenames = [cls.__tablename__ for cls in DB_TABLES]
    teardown_and_recreate_tables(tablenames)
    request.addfinalizer(lambda: teardown_and_recreate_tables(tablenames))
