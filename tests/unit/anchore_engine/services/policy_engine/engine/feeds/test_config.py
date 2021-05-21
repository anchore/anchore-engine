import pytest

from anchore_engine.configuration import localconfig
from anchore_engine.services.policy_engine.engine.feeds.config import (
    compute_selected_configs_to_sync,
    get_section_for_vulnerabilities,
    get_provider_name,
    is_sync_enabled,
)
from anchore_engine.services.policy_engine.engine.vulns.providers import (
    LegacyProvider,
    GrypeProvider,
)


@pytest.mark.parametrize(
    "test_input, expected",
    [
        pytest.param({}, {}, id="invalid-emtpy-1"),
        pytest.param(
            {"something": {"feeds": {"nothing": True}}}, {}, id="invalid-empty-2"
        ),
        pytest.param(
            {"services": {"policy_engine": {"vulnerabilities": {}}}},
            {},
            id="valid-empty",
        ),
        pytest.param(
            {"services": {"policy_engine": {"vulnerabilities": "something"}}},
            "something",
            id="valid-not-empty",
        ),
    ],
)
def test_get_feeds_config(test_input, expected):
    localconfig.localconfig = test_input
    assert get_section_for_vulnerabilities() == expected


@pytest.mark.parametrize(
    "provider,test_config,expected",
    [
        pytest.param(
            LegacyProvider, {}, {"vulnerabilities", "nvdv2"}, id="invalid-empty"
        ),
        pytest.param(
            LegacyProvider, None, {"vulnerabilities", "nvdv2"}, id="invalid-none"
        ),
        pytest.param(
            LegacyProvider,
            {"a": {"b": {"c": "d"}}},
            {"vulnerabilities", "nvdv2"},
            id="invalid-gibberish",
        ),
        pytest.param(
            LegacyProvider,
            {"sync": {}},
            {"vulnerabilities", "nvdv2"},
            id="invalid-empty-sync",
        ),
        pytest.param(
            LegacyProvider,
            {"sync": {"data": {}}},
            {"vulnerabilities", "nvdv2"},
            id="invalid-empty-data",
        ),
        pytest.param(
            LegacyProvider,
            {"provider": "legacy", "sync": {"data": {}}},
            {"vulnerabilities", "nvdv2"},
            id="invalid-provider-legacy",
        ),
        pytest.param(
            GrypeProvider,
            {"provider": "grype", "sync": {"data": {}}},
            {"grypedb"},
            id="invalid-provider-grype",
        ),
    ],
)
def test_get_selected_configs_to_sync_defaults(provider, test_config, expected):
    assert (
        set(
            compute_selected_configs_to_sync(
                provider.__config__name__,
                test_config,
                provider.__default_sync_config__,
            ).keys()
        )
        == expected
    )


@pytest.mark.parametrize(
    "provider, test_config, expected",
    [
        pytest.param(
            LegacyProvider,
            {"provider": "legacy", "sync": {"data": {"packages": {"enabled": True}}}},
            {"packages"},
            id="valid-legacy-packages",
        ),
        pytest.param(
            LegacyProvider,
            {"provider": "legacy", "sync": {"data": {"github": {"enabled": True}}}},
            {"github"},
            id="valid-legacy-github",
        ),
        pytest.param(
            LegacyProvider,
            {
                "provider": "legacy",
                "sync": {"data": {"vulnerabilities": {"enabled": True}}},
            },
            {"vulnerabilities"},
            id="valid-legacy-vulnerabilities",
        ),
        pytest.param(
            LegacyProvider,
            {"provider": "legacy", "sync": {"data": {"nvdv2": {"enabled": True}}}},
            {"nvdv2"},
            id="valid-legacy-nvdv2",
        ),
        pytest.param(
            LegacyProvider,
            {"provider": "legacy", "sync": {"data": {"vulndb": {"enabled": True}}}},
            {"vulndb"},
            id="valid-legacy-vulndb",
        ),
        pytest.param(
            GrypeProvider,
            {"provider": "grype", "sync": {"data": {"grypedb": {"enabled": True}}}},
            {"grypedb"},
            id="valid-grype-grypedb",
        ),
        pytest.param(
            GrypeProvider,
            {"provider": "grype", "sync": {"data": {"github": {"enabled": True}}}},
            set(),
            id="invalid-grype-github",
        ),
        pytest.param(
            GrypeProvider,
            {
                "provider": "grype",
                "sync": {"data": {"vulnerabilities": {"enabled": True}}},
            },
            set(),
            id="invalid-grype-vulnerabilities",
        ),
        pytest.param(
            GrypeProvider,
            {"provider": "grype", "sync": {"data": {"nvdv2": {"enabled": True}}}},
            set(),
            id="invalid-grype-nvdv2",
        ),
        pytest.param(
            GrypeProvider,
            {"provider": "grype", "sync": {"data": {"vulndb": {"enabled": True}}}},
            set(),
            id="invalid-grype-vulndb",
        ),
        pytest.param(
            LegacyProvider,
            {"provider": "legacy", "sync": {"data": {"grypedb": {"enabled": True}}}},
            set(),
            id="invalid-legacy-grypedb",
        ),
    ],
)
def test_get_selected_configs_to_sync_valid_data(provider, test_config, expected):
    assert (
        set(
            compute_selected_configs_to_sync(
                provider.__config__name__, test_config, provider.__default_sync_config__
            ).keys()
        )
        == expected
    )


@pytest.mark.parametrize(
    "test_input, expected",
    [
        pytest.param(
            {},
            None,
            id="invalid-empty",
        ),
        pytest.param(
            None,
            None,
            id="invalid-none",
        ),
        pytest.param(
            {"provider": "foobar"},
            "foobar",
            id="invalid-provider",
        ),
        pytest.param(
            {"foo": {"bar": {"x": "y"}}},
            None,
            id="invalid-data",
        ),
        pytest.param(
            {"provider": "legacy"},
            "legacy",
            id="valid-legacy",
        ),
        pytest.param(
            {"provider": "grype"},
            "grype",
            id="valid-grype",
        ),
    ],
)
def test_get_provider(test_input, expected):
    assert get_provider_name(test_input) == expected


@pytest.mark.parametrize(
    "test_input, expected",
    [
        pytest.param(
            {},
            True,
            id="invalid-empty",
        ),
        pytest.param(
            None,
            True,
            id="invalid-none",
        ),
        pytest.param(
            {"sync": {"enabled": True}},
            True,
            id="valid-true",
        ),
        pytest.param(
            {"sync": {"enabled": False}},
            False,
            id="valid-false",
        ),
        pytest.param(
            {"sync": {"enabled": "foobar"}},
            True,
            id="valid-gibberish",
        ),
    ],
)
def test_is_sync_enabled(test_input, expected):
    assert is_sync_enabled(test_input) == expected
