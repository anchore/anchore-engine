import os
import pytest

from anchore_engine.configuration.localconfig import (
    DEFAULT_CONFIG,
    get_config,
    load_defaults,
    load_filepath_to_config,
    load_policy_bundle_paths
)
from pathlib import Path

DEFAULT_CONFIG_FN = "config.yaml"
DEFAULT_ANALYZER_CONFIG_FN = "analyzer_config.yaml"
DEFAULT_POLICY_BUNDLE_FN = "anchore_default_bundle.yaml"
CUSTOM_POLICY_BUNDLE_FN = "anchore_custom_bundle.yaml"

ANALYZER_CONFIG_TEXT = "analyzer\n"
POLICY_BUNDLE_TEXT = "policy bundle\n"

INPUT_CONFIG_DIR = "input_config"
INPUT_BUNDLES_DIR = "input_bundles"


@pytest.fixture
def mock_default_config(tmpdir):
    config_copy = DEFAULT_CONFIG.copy()
    config_fn = tmpdir.join(DEFAULT_CONFIG_FN)
    with open(config_fn.strpath, "w") as fp:
        fp.write(str(config_copy))
        fp.flush()


def mock_test_files(input_dir, config_filenames):
    # setup files to read and/or copy later
    for config_filename in config_filenames:
        mock_test_file(input_dir, config_filename)


def mock_test_file(input_dir, config_filename):
    # setup files to read and/or copy later
    Path(input_dir.strpath + "/" + config_filename).touch()


@pytest.mark.parametrize(
    "config_filenames",
    [
        ([]),
        (["anchore_default_bundle.json"]),
        (["anchore_default_bundle.json", "second_bundle.json"])
    ]
)
def test_load_policy_bundle_paths(mock_default_config, tmpdir, config_filenames):
    # setup files to read
    input_dir = tmpdir.mkdir(INPUT_BUNDLES_DIR)
    mock_test_files(input_dir, config_filenames)
    output_dir_name = tmpdir.strpath + "/bundles"

    # setup the default config
    load_defaults(configdir=tmpdir)

    # function under test
    load_policy_bundle_paths(src_dir=input_dir.strpath)

    # get and validate the relevant config bits
    config = get_config()
    assert config["policy_bundles"] is not None
    assert len(config["policy_bundles"]) == len(config_filenames)
    for config_filename in config_filenames:
        policy_bundle = next(
            policy_bundle
            for policy_bundle in config["policy_bundles"]
            if policy_bundle["bundle_path"] == output_dir_name + "/" + config_filename
        )
        assert policy_bundle is not None
        if config_filename == "anchore_default_bundle.json":
            assert policy_bundle["active"]
        else:
            assert not policy_bundle["active"]
        assert os.path.exists(policy_bundle["bundle_path"])


@pytest.mark.parametrize(
    "config_key, config_filename",
    [
        ("anchore_scanner_analyzer_config_file", "analyzer_config.yaml"),
        ("anchore_scanner_analyzer_config_file", "other_config.yaml")
    ]
)
def test_load_filepath_to_config(
        mock_default_config, tmpdir, config_key, config_filename
):
    # setup files to read
    input_dir = tmpdir.mkdir(INPUT_CONFIG_DIR)
    mock_test_file(input_dir, config_filename)
    output_dir_name = tmpdir.strpath

    # setup the default config
    load_defaults(configdir=tmpdir)

    load_filepath_to_config(config_key, config_filename, src_dir=input_dir.strpath)
    config = get_config()
    assert config["anchore_scanner_analyzer_config_file"] is not None
    assert (
        config["anchore_scanner_analyzer_config_file"]
        == output_dir_name + "/" + config_filename
    )
    assert os.path.exists(config["anchore_scanner_analyzer_config_file"])
