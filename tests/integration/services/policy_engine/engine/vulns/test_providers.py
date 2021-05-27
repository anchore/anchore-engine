import pytest

from anchore_engine.db import FeedMetadata, session_scope
from anchore_engine.services.policy_engine.engine.feeds.feeds import GrypeDBFeed
from anchore_engine.services.policy_engine.engine.vulns import providers


class TestLegacyProvider:
    @pytest.fixture(autouse=True)
    def setup_feed_data(self, test_data_env):
        with session_scope() as session:
            session.add(FeedMetadata(name=GrypeDBFeed.__feed_name__))
            session.add(FeedMetadata(name="vulnerabilities"))
            session.commit()

    @pytest.fixture
    def legacy_provider(self):
        return providers.LegacyProvider()

    def test_get_feeds_detached(self, test_data_env, legacy_provider):

        feeds = legacy_provider.get_feeds_detached()

        assert isinstance(feeds, list) is True
        assert len(feeds) == 1
        feed = feeds[0]
        assert feed.name == "vulnerabilities"
