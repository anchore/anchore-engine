import datetime
from typing import Optional, Type

import pytest

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
