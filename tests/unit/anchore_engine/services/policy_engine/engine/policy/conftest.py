from contextlib import contextmanager
from unittest.mock import Mock

import pytest

from anchore_engine.db.db_grype_db_feed_metadata import NoActiveGrypeDB
from anchore_engine.db.entities.policy_engine import DistroMapping
from anchore_engine.services.policy_engine import init_feed_registry

DISTRO_MAPPINGS = [
    DistroMapping(from_distro="alpine", to_distro="alpine", flavor="ALPINE"),
    DistroMapping(from_distro="busybox", to_distro="busybox", flavor="BUSYB"),
    DistroMapping(from_distro="centos", to_distro="rhel", flavor="RHEL"),
    DistroMapping(from_distro="debian", to_distro="debian", flavor="DEB"),
    DistroMapping(from_distro="fedora", to_distro="rhel", flavor="RHEL"),
    DistroMapping(from_distro="ol", to_distro="ol", flavor="RHEL"),
    DistroMapping(from_distro="rhel", to_distro="rhel", flavor="RHEL"),
    DistroMapping(from_distro="ubuntu", to_distro="ubuntu", flavor="DEB"),
    DistroMapping(from_distro="amzn", to_distro="amzn", flavor="RHEL"),
    DistroMapping(from_distro="redhat", to_distro="rhel", flavor="RHEL"),
]
MAPPINGS_MAP = {mapping.from_distro: mapping for mapping in DISTRO_MAPPINGS}


@pytest.fixture
def mock_distromapping_query(monkeypatch):
    # mocks DB query in anchore_engine.db.entities.policy_engine.DistroMapping.distros_for
    mock_db = Mock()
    mock_db.query().get = lambda x: MAPPINGS_MAP.get(x, None)
    monkeypatch.setattr(
        "anchore_engine.db.entities.policy_engine.get_thread_scoped_session",
        lambda: mock_db,
    )


@pytest.fixture
def mock_gate_util_provider_oldest_namespace_feed_sync(
    monkeypatch, mock_distromapping_query
):
    """
    Mocks for anchore_engine.services.policy_engine.engine.policy.gate_util_provider.GateUtilProvider.oldest_namespace_feed_sync
    """
    # required for FeedOutOfDateTrigger.evaluate
    # setup for anchore_engine.services.policy_engine.engine.feeds.feeds.FeedRegistry.registered_vulnerability_feed_names
    init_feed_registry()

    @contextmanager
    def mock_session_scope():
        """
        Mock context manager for anchore_engine.db.session_scope.
        """
        yield None

    def raise_no_active_grypedb(session):
        raise NoActiveGrypeDB

    def _setup_mocks(feed_group_metadata=None, grype_db_feed_metadata=None):
        # required for FeedOutOfDateTrigger.evaluate
        # mocks anchore_engine.services.policy_engine.engine.feeds.db.get_feed_group_detached
        monkeypatch.setattr(
            "anchore_engine.services.policy_engine.engine.policy.gate_util_provider.session_scope",
            mock_session_scope,
        )
        if grype_db_feed_metadata:
            monkeypatch.setattr(
                "anchore_engine.services.policy_engine.engine.policy.gate_util_provider.get_most_recent_active_grypedb",
                lambda x: grype_db_feed_metadata,
            )
        else:
            monkeypatch.setattr(
                "anchore_engine.services.policy_engine.engine.policy.gate_util_provider.get_most_recent_active_grypedb",
                raise_no_active_grypedb,
            )
        # mocks anchore_engine.db.db_grype_db_feed_metadata.get_most_recent_active_grypedb
        # if feed_group_metadata:
        monkeypatch.setattr(
            "anchore_engine.services.policy_engine.engine.policy.gate_util_provider.get_feed_group_detached",
            lambda x, y: feed_group_metadata,
        )

    return _setup_mocks
