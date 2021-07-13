from anchore_engine.db import FeedMetadata, session_scope
from anchore_engine.services.policy_engine.engine.feeds.db import get_feed_detached


def test_get_feed_detached(test_data_env):
    requesting_name = "test"
    with session_scope() as session:
        session.add(FeedMetadata(name=requesting_name))
        session.add(FeedMetadata(name="test123"))
        session.commit()

    feed = get_feed_detached(requesting_name)

    assert isinstance(feed, FeedMetadata) is True
    assert feed.name == requesting_name
