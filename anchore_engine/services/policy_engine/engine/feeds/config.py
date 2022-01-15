"""
Separate module for accessing feeds configuration. Does not have any dependencies on rest of the feeds code to avoid import loops
"""

from dataclasses import dataclass, field
from typing import Dict

from anchore_engine.configuration import localconfig
from anchore_engine.subsys import logger


@dataclass
class SyncConfig:
    enabled: bool
    url: str
    username: str = field(default=None, repr=False)
    password: str = field(default=None, repr=False)
    connection_timeout_seconds: int = field(default=3)
    read_timeout_seconds: int = field(default=60)
    ssl_verify: bool = field(default=True)


def get_section_for_vulnerabilities() -> Dict:
    """
    Returns the vulnerabilities specific portion of the policy-engine config. To centralized this logic.

    Snippet of the config
    services:
      ...
      policy_engine:
        ...
        vulnerabilities:
          provider: legacy
          sync:
            enabled: true
            ssl_verify: true
            connection_timeout_seconds: 3
            read_timeout_seconds: 60
            data:
              vulnerabilities:
                enabled: true
                url: https://ancho.re/v1/service/feeds
              nvdv2:
                enabled: true
                url: https://ancho.re/v1/service/feeds
              github:
                enabled: true
                url: https://ancho.re/v1/service/feeds

    :return: dict that is the vulnerabilities section of config
    """
    full_config = localconfig.get_config()
    vuln_config = (
        full_config.get("services", {})
        .get(
            "policy_engine", {}
        )  # TODO check if there's a better way to find service config
        .get("vulnerabilities", {})
    )

    return vuln_config if vuln_config is not None else {}


def compute_selected_configs_to_sync(
    provider: str,
    vulnerabilities_config: Dict,
    default_provider_sync_config: Dict[str, SyncConfig],
) -> Dict[str, SyncConfig]:
    """
    Returns the feeds to be synced from the configuration after filtering required/allowed by the provider
    Handles both legacy and grype vulnerabilities provider configurations

    :param provider: name of the provider such as legacy or grype
    :param vulnerabilities_config: vulnerabilities section of config file
    {
       "provider": "legacy",
       "sync": {
          "enabled": True,
          "ssl_verify": True,
          "connection_timeout_seconds": 3,
          "read_timeout_seconds": 60,
          "data": {
             "vulnerabilities": {
                "enabled": True,
                "url": "https://ancho.re/v1/service/feeds"
             },
             "nvdv2": {
                "enabled": True,
                "url": "https://ancho.re/v1/service/feeds"
             },
             "github": {
                "enabled": True,
                "url": "https://ancho.re/v1/service/feeds"
             }
          }
       }
    }
    :param default_provider_sync_config: the default sync configuration for the provider.
    A dictionary with feed names each mapped to its respective SyncConfig
    {
        "grypedb": SyncConfig(enabled=True, url="https://toolbox-data.anchore.io/grype/databases/listing.json"),
        "packages": SyncConfig(enabled=False, url="https://ancho.re/v1/service/feeds")
    }
    :return: dictionary with feed names each mapped to its respective SyncConfig
    """
    # check for the provider first
    if not vulnerabilities_config:
        vulnerabilities_config = {}

    sync_config = vulnerabilities_config.get("sync", {})
    data_config = sync_config.get("data", {})

    connection_timeout_seconds = sync_config.get("connection_timeout_seconds", 3)
    read_timeout_seconds = sync_config.get("read_timeout_seconds", 60)

    if data_config:
        logger.debug(
            "Searching for data feeds to be synced for %s provider in %s",
            provider,
            data_config,
        )
        to_be_synced = dict()
        for feed_name, sync_config_dict in data_config.items():
            # get the default config for both verifying feed_name is a valid data feed and accessing url if necessary
            default_sync_config = default_provider_sync_config.get(feed_name)
            if default_sync_config:
                if sync_config_dict.get("enabled", True):
                    sync_url = sync_config_dict.get("url")
                    if not sync_url:
                        sync_url = default_sync_config.url
                    to_be_synced[feed_name] = SyncConfig(
                        enabled=True,
                        url=sync_url,
                        connection_timeout_seconds=connection_timeout_seconds,
                        read_timeout_seconds=read_timeout_seconds,
                    )
                else:
                    logger.debug("%s data feed is not enabled, skipping", feed_name)
            else:  # implies feed is either invalid or unsupported for the provider
                logger.warn(
                    "%s data feed is unrecognized for %s provider, skipping",
                    feed_name,
                    provider,
                )
                continue

    else:
        logger.debug(
            "Configuration for data feeds not found, falling back to %s provider defaults",
            provider,
        )
        to_be_synced = {
            feed_name: sync_config
            for feed_name, sync_config in default_provider_sync_config.items()
            if sync_config.enabled
        }

    logger.info(
        "Data feeds to be synced for %s provider: %s",
        provider,
        list(to_be_synced.keys()),
    )

    return to_be_synced


def is_sync_enabled(vulnerabilities_config: Dict) -> bool:
    """
    Returns whether a feeds sync is enabled based on the provider config. Returns true if config sections are missing
    to be backwards compatible

    :param vulnerabilities_config: vulnerabilities section of config file
    {
       "provider": "legacy",
       "sync": {
          "enabled": True,
          "ssl_verify": True,
          "connection_timeout_seconds": 3,
          "read_timeout_seconds": 60,
          "data": {
             "vulnerabilities": {
                "enabled": True,
                "url": "https://ancho.re/v1/service/feeds"
             },
             "nvdv2": {
                "enabled": True,
                "url": "https://ancho.re/v1/service/feeds"
             },
             "github": {
                "enabled": True,
                "url": "https://ancho.re/v1/service/feeds"
             }
          }
       }
    }
    :return: True or False
    """
    if not vulnerabilities_config:
        return True

    sync_enabled = vulnerabilities_config.get("sync", {}).get("enabled")
    if isinstance(sync_enabled, bool):
        return sync_enabled
    else:
        return True


def get_provider_name(vulnerabilities_config: Dict):
    """
    Returns the provider if it's configured or a default provider

    :param vulnerabilities_config: vulnerabilities section of config file
    {
       "provider": "legacy",
       "sync": {
          "enabled": True,
          "ssl_verify": True,
          "connection_timeout_seconds": 3,
          "read_timeout_seconds": 60,
          "data": {
             "vulnerabilities": {
                "enabled": True,
                "url": "https://ancho.re/v1/service/feeds"
             },
             "nvdv2": {
                "enabled": True,
                "url": "https://ancho.re/v1/service/feeds"
             },
             "github": {
                "enabled": True,
                "url": "https://ancho.re/v1/service/feeds"
             }
          }
       }
    }
    :returns: a string provider name
    """
    if not vulnerabilities_config:
        return

    configured = vulnerabilities_config.get("provider")
    if configured:
        configured = configured.lower()

    return configured
