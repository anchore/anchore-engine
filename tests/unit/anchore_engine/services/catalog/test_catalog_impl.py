import json
import os
import pytest

from anchore_engine.services.catalog.catalog_impl import load_policy_bundles


INPUT_BUNDLES_DIR = "bundles"


def get_mock_config_with_policy_bundles(dir, bundle_filenames, simulate_exception):
    policy_bundles = []

    input_dir = dir.mkdir(INPUT_BUNDLES_DIR)
    # setup files to read and/or copy later
    mock_id = 0
    for bundle_filename in bundle_filenames:
        bundle_path = os.path.join(input_dir, bundle_filename)
        if simulate_exception:
            mock_body = "not json"
        else:
            mock_body = json.dumps({"id": str(mock_id), "name": bundle_filename})
        mock_id += 1
        with open(bundle_path, "w") as fp:
            fp.write(mock_body)
            fp.flush()

        policy_bundle = {}
        # Just make the first bundle active since it's arbitrary for these tests
        policy_bundle["active"] = len(policy_bundles) == 0
        policy_bundle["bundle_path"] = bundle_path
        policy_bundles.append(policy_bundle)

    return {"policy_bundles": policy_bundles}


@pytest.mark.parametrize(
    "bundle_filenames, simulate_exception, expected_bundles, expected_exceptions",
    [
        (["first_bundle.json"], False, 1, 0),
        (["first_bundle.json", "first_bundle.json"], False, 2, 0),
        (["first_bundle.json"], True, 0, 1),
    ]
)
def test_load_policy_bundles(
        tmpdir, bundle_filenames, simulate_exception, expected_bundles, expected_exceptions
):
    config = get_mock_config_with_policy_bundles(
        tmpdir, bundle_filenames, simulate_exception
    )
    policy_bundles = []
    bundles = []
    exceptions = []

    def process_bundle(policy_bundle, bundle):
        policy_bundles.append(policy_bundle)
        bundles.append(bundle)

    def process_exception(exception):
        exceptions.append(exception)

    load_policy_bundles(config, process_bundle, process_exception)

    assert len(policy_bundles) == expected_bundles
    assert len(bundles) == expected_bundles
    assert len(exceptions) == expected_exceptions
