import datetime
from typing import Optional, Type
from unittest.mock import Mock

import pytest

from anchore_engine.clients.grype_wrapper import GrypeWrapperSingleton
from anchore_engine.db.entities.policy_engine import (
    DistroNamespace,
    FeedGroupMetadata,
    GrypeDBFeedMetadata,
)
from anchore_engine.services.policy_engine.engine.policy.gate_util_provider import (
    GateUtilProvider,
    GrypeGateUtilProvider,
    LegacyGateUtilProvider,
)
from tests.unit.anchore_engine.clients.test_grype_wrapper import (
    TestGrypeWrapperSingleton,
    production_grype_db_dir,
    GRYPE_DB_VERSION,
)


@pytest.fixture
def test_grype_wrapper_singleton(
    monkeypatch, production_grype_db_dir
) -> GrypeWrapperSingleton:
    """
    Creates a TestGrypeWrapperSingleton, with attributes attributes for a mock production grype_db.
    That db contains a small number of (mock, not production) vulnerability records.

    Note that this test grype wrapper, unlike a real instance, has those references cleared and recreated
    each time it is called in order to maintain atomicity between tests. This fixture therefore monkey
    patches providers.py so that the wrapper created here is accessed during test execution.
    """
    grype_wrapper_singleton = TestGrypeWrapperSingleton.get_instance()

    grype_wrapper_singleton._grype_db_dir = production_grype_db_dir
    grype_wrapper_singleton._grype_db_version = GRYPE_DB_VERSION

    test_production_grype_db_engine = (
        grype_wrapper_singleton._init_latest_grype_db_engine(
            production_grype_db_dir, GRYPE_DB_VERSION
        )
    )

    grype_wrapper_singleton._grype_db_session_maker = (
        grype_wrapper_singleton._init_latest_grype_db_session_maker(
            test_production_grype_db_engine
        )
    )

    monkeypatch.setattr(
        "anchore_engine.services.policy_engine.engine.policy.gate_util_provider.GrypeWrapperSingleton.get_instance",
        lambda: grype_wrapper_singleton,
    )


class TestGateUtilProvider:
    sync_time = datetime.datetime.utcnow()

    @pytest.mark.parametrize(
        "gate_util_provider, feed_group_metadata, grype_db_feed_metadata, expected_oldest_update",
        [
            # Case, legacy provider, feed group exists
            (
                LegacyGateUtilProvider,
                FeedGroupMetadata(
                    last_sync=sync_time,
                    name="test-feed-out-of-date",
                ),
                None,
                sync_time,
            ),
            # Case, legacy provider, feed group does not exist
            (
                LegacyGateUtilProvider,
                None,
                None,
                None,
            ),
            # Case, grype provider, active grype DB exists
            (
                GrypeGateUtilProvider,
                None,
                GrypeDBFeedMetadata(built_at=sync_time),
                sync_time,
            ),
            # Case, grype provider, active grype DB does not exist
            (
                GrypeGateUtilProvider,
                None,
                None,
                None,
            ),
        ],
    )
    def test_oldest_namespace_feed_sync(
        self,
        gate_util_provider: Type[GateUtilProvider],
        feed_group_metadata: Optional[FeedGroupMetadata],
        grype_db_feed_metadata: Optional[GrypeDBFeedMetadata],
        expected_oldest_update: Optional[datetime.datetime],
        mock_distromapping_query,
        mock_gate_util_provider_oldest_namespace_feed_sync,
    ):
        ns = DistroNamespace(name="DEB", version="10", like_distro=None)
        ns.like_namespace_names = ["debian:10"]

        mock_gate_util_provider_oldest_namespace_feed_sync(
            feed_group_metadata=feed_group_metadata,
            grype_db_feed_metadata=grype_db_feed_metadata,
        )

        provider = gate_util_provider()
        oldest_update = provider.oldest_namespace_feed_sync(ns)

        assert oldest_update == expected_oldest_update

    @pytest.mark.parametrize(
        "distro, version, expected",
        [
            ("amzn", "2", False),
            ("alpine", "3.10", True),
            ("debian", "10", True),
            ("github", "python", True),
        ],
    )
    def test_have_vulnerabilities_for_grype_provider(
        self,
        distro,
        version,
        expected,
        test_grype_wrapper_singleton,
    ):
        # Setup
        distro_namespace = Mock()
        distro_namespace.like_namespace_names = [distro + ":" + version]
        provider = GrypeGateUtilProvider()

        # Method under test
        result = provider.have_vulnerabilities_for(distro_namespace)

        # Assert expected result
        assert result is expected
