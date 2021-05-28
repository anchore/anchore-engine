from dataclasses import dataclass
from typing import Dict, List, Type

import pytest

from anchore_engine.common.models.schemas import (
    FeedAPIGroupRecord,
    FeedAPIRecord,
    GrypeDBListing,
)
from anchore_engine.db import FeedGroupMetadata, FeedMetadata
from anchore_engine.db.entities.common import anchore_now_datetime
from anchore_engine.services.policy_engine.engine.feeds import FeedList
from anchore_engine.services.policy_engine.engine.feeds.client import (
    FeedServiceClient,
    GrypeDBServiceClient,
    IFeedSource,
)
from anchore_engine.services.policy_engine.engine.feeds.config import (
    SyncConfig,
    compute_selected_configs_to_sync,
)
from anchore_engine.services.policy_engine.engine.feeds.feeds import (
    GrypeDBFeed,
    VulnerabilityFeed,
)
from anchore_engine.services.policy_engine.engine.feeds.sync_utils import (
    GrypeDBSyncUtilProvider,
    LegacySyncUtilProvider,
    SyncUtilProvider,
)
from anchore_engine.services.policy_engine.engine.vulns.providers import (
    GrypeProvider,
    LegacyProvider,
)


@dataclass
class FeedConfiguration:
    feed_name: str
    enabled: bool


def get_config_for_params(provider: str, feed_configurations: List[FeedConfiguration]):
    return {
        "provider": provider,
        "sync": {
            "enabled": True,
            "ssl_verify": True,
            "connection_timeout_seconds": 3,
            "read_timeout_seconds": 60,
            "data": {
                feed_configuration.feed_name: {
                    "enabled": feed_configuration.enabled,
                    "url": "www.anchore.com",
                }
                for feed_configuration in feed_configurations
            },
        },
    }


class TestSyncUtilProvider:
    @pytest.mark.parametrize(
        "provider, feed_configurations, expected_to_sync_after_compute, expected_to_sync_after_filtering",
        [
            (  # Legacy provider with one invalid config (vulndb), one grype config, and two legacy configs
                "legacy",
                [
                    FeedConfiguration("vulnerabilities", True),
                    FeedConfiguration("nvdv2", True),
                    FeedConfiguration("vulndb", True),
                    FeedConfiguration("grypedb", True),
                ],
                ["nvdv2", "vulnerabilities"],
                ["nvdv2", "vulnerabilities"],
            ),
            (  # Grype provider with one invalid config (vulndb) one grype config, and two legacy configs
                "grype",
                [
                    FeedConfiguration("vulnerabilities", True),
                    FeedConfiguration("nvdv2", True),
                    FeedConfiguration("vulndb", True),
                    FeedConfiguration("grypedb", True),
                ],
                ["grypedb"],
                ["grypedb"],
            ),
            (  # Legacy provider with two disabled configs and one grypedb config that is enabled
                "legacy",
                [
                    FeedConfiguration("vulnerabilities", False),
                    FeedConfiguration("nvdv2", False),
                    FeedConfiguration("grypedb", True),
                ],
                [],
                [],
            ),
            (  # Grype provider disabled grypedb config and two legacy configs enabled
                "grype",
                [
                    FeedConfiguration("vulnerabilities", True),
                    FeedConfiguration("nvdv2", True),
                    FeedConfiguration("grypedb", False),
                ],
                [],
                [],
            ),
            (  # Legacy provider all disabled configs
                "legacy",
                [
                    FeedConfiguration("vulnerabilities", False),
                    FeedConfiguration("nvdv2", False),
                    FeedConfiguration("grypedb", False),
                ],
                [],
                [],
            ),
            (  # Grype provider with all disabled configs
                "grype",
                [
                    FeedConfiguration("vulnerabilities", False),
                    FeedConfiguration("nvdv2", False),
                    FeedConfiguration("grypedb", False),
                ],
                [],
                [],
            ),
            (  # Grype provider with packages and grypedb enabled
                "grype",
                [
                    FeedConfiguration("vulnerabilities", False),
                    FeedConfiguration("nvdv2", False),
                    FeedConfiguration("grypedb", True),
                    FeedConfiguration("packages", True),
                ],
                ["grypedb", "packages"],
                ["grypedb"],
            ),
            (  # legacy provider with packages and grypedb enabled
                "legacy",
                [
                    FeedConfiguration("vulnerabilities", False),
                    FeedConfiguration("nvdv2", False),
                    FeedConfiguration("grypedb", True),
                    FeedConfiguration("packages", True),
                ],
                ["packages"],
                ["packages"],
            ),
        ],
    )
    def test_config_filtering(
        self,
        provider: str,
        feed_configurations: List[FeedConfiguration],
        expected_to_sync_after_compute: List[str],
        expected_to_sync_after_filtering: List[str],
    ):
        """
        This is a bit confusing and probably should be changed, which is why i've written a test for it.
        There are two SyncUtilProviders.
        The LegacySyncUtilProvider works for all feeds that follow the legacy format.
        The GrypeDBSyncUtilProvider works for the GrypeDB feed format.
        However, the VulnerabilitiesProvider has two implementations.
        The LegacyProvider contains all vulnerability logic that changes when the provider is set to "legacy"
        The GrypeProvider contains all vulnerability logic that changes when the provider is set to "grype"
        As such, the GrypeProvider actually returns both "packages" and "grypedb" SyncConfigs,
        while "packages" is actually a Legacy style feed.
        Meanwhile, the "packages" feed can only be synced by the LegacySyncUtilProvider.
        The solution is likely to wrap the entire sync method with the SyncUtilProvider, that way LegacySyncUtilProvider
        can just do legacy feeds, while GrypeDBSyncUtilProvider will first do "grypedb" feed with the grype logic
        and then do "packages" feed with the legacy logic.
        """
        if provider == "legacy":
            vulnerabilities_provider = LegacyProvider()
        else:
            vulnerabilities_provider = GrypeProvider()
        sync_configs = compute_selected_configs_to_sync(
            provider=vulnerabilities_provider.get_config_name(),
            vulnerabilities_config=get_config_for_params(provider, feed_configurations),
            default_provider_sync_config=vulnerabilities_provider.get_default_sync_config(),
        )
        assert set(sync_configs.keys()) == set(expected_to_sync_after_compute)
        sync_utils_provider = vulnerabilities_provider.get_sync_utils(sync_configs)
        filtered_configs = sync_utils_provider._get_filtered_sync_configs(sync_configs)
        assert set(filtered_configs) == set(expected_to_sync_after_filtering)

    @pytest.mark.parametrize(
        "sync_util_provider, sync_configs, expected_client_class",
        [
            (
                LegacySyncUtilProvider,
                {"vulnerabilities": SyncConfig(url="www.anchore.com", enabled=True)},
                FeedServiceClient,
            ),
            (
                GrypeDBSyncUtilProvider,
                {"grypedb": SyncConfig(url="www.anchore.com", enabled=True)},
                GrypeDBServiceClient,
            ),
        ],
    )
    def test_get_client(
        self,
        sync_util_provider: Type[SyncUtilProvider],
        sync_configs: Dict[str, SyncConfig],
        expected_client_class: Type[IFeedSource],
    ):
        client = sync_util_provider(sync_configs).get_client()
        assert isinstance(client, expected_client_class)

    def test_get_groups_to_download_grype(self):
        source_feeds = {
            "grypedb": {
                "meta": FeedList(
                    feeds=[
                        FeedAPIRecord(
                            name="grypedb",
                            description="grypedb feed",
                            access_tier="0",
                        )
                    ]
                ),
                "groups": [
                    FeedAPIGroupRecord(
                        name="grypedb:vulnerabilities",
                        description="grypedb:vulnerabilities group",
                        access_tier="0",
                        grype_listing=GrypeDBListing(
                            built=anchore_now_datetime(),
                            version="2",
                            url="www.anchore.com",
                            checksum="sha256:xxx",
                        ),
                    )
                ],
            }
        }
        feeds_to_sync = [GrypeDBFeed(metadata=FeedMetadata(name="grypedb"))]
        sync_config = {"grypedb": SyncConfig(enabled=True, url="www.anchore.com")}
        groups_to_download = GrypeDBSyncUtilProvider(
            sync_config
        ).get_groups_to_download(source_feeds, feeds_to_sync, "0")
        assert len(groups_to_download) == 1
        group = groups_to_download[0]
        assert group.enabled
        assert group.feed_name == "grypedb"
        assert group.name == "grypedb:vulnerabilities"

    def test_get_groups_to_download_legacy(self):
        feed_group_metadata = [
            FeedGroupMetadata(name="vulnerabilities:alpine:3.10", enabled=True),
            FeedGroupMetadata(name="vulnerabilities:alpine:3.11", enabled=True),
        ]
        feeds_to_sync = [
            VulnerabilityFeed(
                metadata=FeedMetadata(
                    name="vulnerabilities",
                    enabled=True,
                    groups=feed_group_metadata,
                )
            )
        ]
        sync_config = {
            "vulnerabilities": SyncConfig(enabled=True, url="www.anchore.com")
        }
        groups_to_download = LegacySyncUtilProvider(sync_config).get_groups_to_download(
            {}, feeds_to_sync, "0"
        )
        assert groups_to_download == feed_group_metadata
