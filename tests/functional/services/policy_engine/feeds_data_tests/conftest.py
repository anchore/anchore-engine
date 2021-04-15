from os import path

import pytest

from anchore_engine.db.entities.common import get_engine
from anchore_engine.db.entities.policy_engine import (
    CpeV2Vulnerability,
    FeedGroupMetadata,
    FeedMetadata,
    FixedArtifact,
    Vulnerability,
)
from anchore_engine.db.entities.upgrade import do_create_tables

CURRENT_DIR = path.dirname(path.abspath(__file__))
FEEDS_DATA_PATH_PREFIX = path.join("data", "v1", "service", "feeds")

DB_TABLES = [
    CpeV2Vulnerability,
    FeedGroupMetadata,
    FeedMetadata,
    FixedArtifact,
    Vulnerability,
]


def _teardown_vuln_data():
    """
    Drops all vulnerability related data
    """
    tablenames = [cls.__tablename__ for cls in DB_TABLES]
    tablenames_joined = ", ".join(map(str, tablenames))
    engine = get_engine()
    with engine.connect() as connection:
        with connection.begin():
            connection.execute(f"DROP TABLE {tablenames_joined} CASCADE")
    do_create_tables()


@pytest.fixture(scope="package", autouse=True)
def clear_database_state(
    request,
    set_env_vars,
    anchore_db,
) -> None:
    """
    Writes database seed file content to database. This allows us to ensure consistent vulnerability results (regardless of feed sync status).
    """
    _teardown_vuln_data()
    request.addfinalizer(_teardown_vuln_data)
