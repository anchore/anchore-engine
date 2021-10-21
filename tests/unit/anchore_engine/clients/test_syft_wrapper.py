import pytest

import anchore_engine.configuration.localconfig
from anchore_engine.clients.syft_wrapper import DEFAULT_TMP_DIR, get_tmp_dir_from_config


def _mock_local_config(tmp_dir):
    localconfig = anchore_engine.configuration.localconfig.get_config()
    if tmp_dir:
        localconfig["tmp_dir"] = tmp_dir
    elif "tmp_dir" in localconfig:
        localconfig.pop("tmp_dir")
    anchore_engine.configuration.localconfig.localconfig = localconfig


@pytest.mark.parametrize(
    "tmp_dir, expected", [("/some_dir", "/some_dir"), (None, DEFAULT_TMP_DIR)]
)
def test_get_tmp_dir_from_config(tmp_dir, expected):
    # Mock local_config with the parameterized tmp_dir value
    _mock_local_config(tmp_dir)

    # Function under test
    result = get_tmp_dir_from_config()

    # Validate result
    assert result == expected
