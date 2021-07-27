from datetime import datetime

import pytest

from anchore_engine.db import GrypeDBFeedMetadata, session_scope
from anchore_engine.db.db_grype_db_feed_metadata import (
    NoActiveGrypeDB,
    get_most_recent_active_grypedb,
)

meta_objs = [
    GrypeDBFeedMetadata(
        archive_checksum="first_meta",
        schema_version="2",
        object_url="1234",
        active=True,
        built_at=datetime.utcnow(),
    ),
    GrypeDBFeedMetadata(
        archive_checksum="second_meta",
        schema_version="2",
        object_url="1234",
        active=True,
        built_at=datetime.utcnow(),
    ),
]


def test_get_most_recent_active_grypedb(anchore_db):
    with session_scope() as session:
        session.add(meta_objs[0])
        session.commit()

        grype_db = get_most_recent_active_grypedb(session)
        assert isinstance(grype_db, GrypeDBFeedMetadata) is True
        assert grype_db.archive_checksum == "first_meta"


def test_get_most_recent_active_grypedb_no_active_Db(anchore_db):
    with session_scope() as session:
        with pytest.raises(NoActiveGrypeDB):
            get_most_recent_active_grypedb(session)


def test_get_most_recent_active_grypedb_multiple_active(anchore_db):
    with session_scope() as session:
        for meta in meta_objs:
            session.add(meta)
        session.commit()

        grype_db = get_most_recent_active_grypedb(session)
        assert isinstance(grype_db, GrypeDBFeedMetadata) is True
        assert grype_db.archive_checksum == "second_meta"
