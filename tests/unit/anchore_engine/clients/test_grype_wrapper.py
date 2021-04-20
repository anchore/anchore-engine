import anchore_engine.configuration.localconfig
import os
import pytest
import shutil
import sqlalchemy

from anchore_engine.clients import grype_wrapper

TEST_DATA_PATH = "../../data/grype_db/"
GRYPE_DB_DIR = "grype_db/"
OLD_VERSION_NAME = "old_version"
NEW_VERSION_NAME = "new_version"


@pytest.fixture
def grype_db_parent_dir(tmp_path):
    localconfig = anchore_engine.configuration.localconfig.get_config()
    localconfig["service_dir"] = tmp_path
    anchore_engine.configuration.localconfig.localconfig = localconfig

    return os.path.join(tmp_path, GRYPE_DB_DIR)


@pytest.fixture
def grype_db_archive(tmp_path):
    input_dir = os.path.join(tmp_path, "input")
    if not os.path.exists(input_dir):
        os.mkdir(input_dir)
    shutil.copy("../../data/grype_db/grype_db_test_archive.tar.gz", input_dir)
    return os.path.join(input_dir, "grype_db_test_archive.tar.gz")


@pytest.fixture
def grype_db_dir(tmp_path):
    parent_dir = os.path.join(tmp_path, "input")
    if not os.path.exists(parent_dir):
        os.mkdir(parent_dir)
    input_dir = os.path.join(parent_dir, NEW_VERSION_NAME)
    shutil.copytree("../../data/grype_db/new_verison/", input_dir)
    return input_dir


@pytest.fixture
def old_grype_db_dir(tmp_path):
    parent_dir = os.path.join(tmp_path, "input")
    if not os.path.exists(parent_dir):
        os.mkdir(parent_dir)
    input_dir = os.path.join(parent_dir, OLD_VERSION_NAME)
    shutil.copytree("../../data/grype_db/old_version/", input_dir)
    return input_dir


def get_test_sbom(sbom_file_name):
    full_sbom_path = os.path.join(TEST_DATA_PATH, sbom_file_name)
    # with open(full_sbom_path, "r") as read_file:
    #     return read_file.read().replace('\n', '')
    return full_sbom_path


# TODO implement along with function under test
# def test_get_current_grype_db_checksum():
#     # Function under test
#     result = grype_wrapper.get_current_grype_db_checksum()
#
#     # Validate result
#     assert result == None


def test_get_default_cache_dir_from_config(grype_db_parent_dir, tmp_path):
    # Function under test
    local_db_dir = grype_wrapper._get_default_grype_db_dir_from_config()

    # Validate the grype db dir exists and is in the correct location
    assert os.path.exists(local_db_dir)
    assert local_db_dir == grype_db_parent_dir


def test_move_grype_db_archive(tmp_path, grype_db_archive):
    # Setup the output dir to be copied into
    output_dir = os.path.join(tmp_path, "output")
    os.mkdir(output_dir)

    # Function under test
    grype_db_archive_copied_file_location = grype_wrapper._move_grype_db_archive(grype_db_archive, output_dir)

    # Validate archive was copied and to the correct location
    assert os.path.exists(grype_db_archive_copied_file_location)
    assert grype_db_archive_copied_file_location == os.path.join(output_dir, "grype_db_test_archive.tar.gz")


def test_open_grype_db_archive(grype_db_archive):
    # Setup expected output vars
    parent_dir = os.path.abspath(os.path.join(grype_db_archive, os.pardir))
    expected_grype_db_file = os.path.join(parent_dir, NEW_VERSION_NAME)

    # Function under test
    latest_grype_db_dir = grype_wrapper._open_grype_db_archive(grype_db_archive, parent_dir, NEW_VERSION_NAME)

    # Validate expected dir contents and location
    assert os.path.exists(expected_grype_db_file)
    assert latest_grype_db_dir == os.path.join(parent_dir, NEW_VERSION_NAME)
    assert os.path.exists(os.path.join(latest_grype_db_dir, grype_wrapper.VULNERABILITY_FILE_NAME))


def test_remove_grype_db_archive(grype_db_archive):
    # Function under test
    grype_wrapper._remove_grype_db_archive(grype_db_archive)

    # Validate
    assert not os.path.exists(grype_db_archive)


def test_init_grype_db_engine(grype_db_dir):
    # Setup output var
    vuln_file_path = os.path.join(grype_db_dir, grype_wrapper.VULNERABILITY_FILE_NAME)

    # Function under test
    latest_grype_db_engine = grype_wrapper._init_grype_db_engine(grype_db_dir)

    # Validate expected output
    assert str(latest_grype_db_engine.url) == "sqlite:///{}".format(vuln_file_path)


def test_init_grype_db_session(grype_db_dir):
    # Setup db engine
    vuln_file_path = os.path.join(grype_db_dir, grype_wrapper.VULNERABILITY_FILE_NAME)
    db_connect = "sqlite:///{}".format(vuln_file_path)
    latest_grype_db_engine = sqlalchemy.create_engine(db_connect, echo=True)
    assert str(latest_grype_db_engine.url) == "sqlite:///{}".format(vuln_file_path)

    # Function under test
    latest_grype_db_session = grype_wrapper._init_grype_db_session(latest_grype_db_engine)

    # Validate output
    assert latest_grype_db_session is not None


def test_init_grype_db(grype_db_parent_dir, grype_db_archive):
    # Setup out vars
    expected_output_dir = os.path.join(grype_db_parent_dir, NEW_VERSION_NAME)
    expected_output_file = os.path.join(expected_output_dir, grype_wrapper.VULNERABILITY_FILE_NAME)

    # Function under test
    latest_grype_db_dir, latest_grype_db_session = grype_wrapper._init_grype_db(grype_db_archive, NEW_VERSION_NAME)

    # Validate expected output
    assert os.path.exists(latest_grype_db_dir)
    assert latest_grype_db_dir == expected_output_dir

    assert latest_grype_db_session is not None
    assert os.path.exists(expected_output_file)


def test_remove_local_grype_db(old_grype_db_dir):
    # Function under test
    grype_wrapper._remove_local_grype_db(old_grype_db_dir)

    # Validate output
    assert not os.path.exists(old_grype_db_dir)


def test_update_grype_db(grype_db_parent_dir, old_grype_db_dir, grype_db_archive):
    # Setup
    grype_wrapper.grype_db_dir = old_grype_db_dir
    expected_output_dir = os.path.join(grype_db_parent_dir, NEW_VERSION_NAME)
    expected_output_file = os.path.join(expected_output_dir, grype_wrapper.VULNERABILITY_FILE_NAME)

    # Function under test
    grype_wrapper.update_grype_db(grype_db_archive, NEW_VERSION_NAME)

    # Validate output
    assert os.path.exists(grype_wrapper.grype_db_dir)
    assert grype_wrapper.grype_db_dir == expected_output_dir

    assert grype_wrapper.grype_db_session is not None
    assert os.path.exists(expected_output_file)

    assert not os.path.exists(old_grype_db_dir)


@pytest.mark.parametrize(
    "sbom_file_name, expected_output",
    [
        ("sbom-ubuntu-20.04--pruned.json", "ubuntu"),
    ],
)
def test_get_vulnerabilities(grype_db_dir, sbom_file_name, expected_output):
    # Setup test inputs
    grype_wrapper.grype_db_dir = grype_db_dir
    test_sbom = get_test_sbom(sbom_file_name)

    # Function under test
    result = grype_wrapper.get_vulnerabilities(test_sbom)

    # TODO Assert expected results
    assert result["distro"]["name"] == expected_output


@pytest.mark.parametrize(
    "vuln_id, affected_package, namespace, expected_result_length, expected_output",
    [
        ("not_found", None, None, 0, []),
        (None, "not_found", None, 0, []),
        (None, None, "not_found", 0, []),
        (None, None, None, 10, ["CVE-2019-16775", "CVE-2019-16777", "CVE-2019-16776", "CVE-2020-10174", "CVE-2019-2391", "CVE-2020-7610", "CVE-2020-8518", "CVE-2019-9658", "CVE-2019-15690", "CVE-2019-20788"]),
        ("CVE-2019-16775", None, None, 1, ["CVE-2019-16775"]),
        (None, "npm", None, 3, ["CVE-2019-16775", "CVE-2019-16777", "CVE-2019-16776"]),
        (None, None, "debian:10", 10, ["CVE-2019-16775", "CVE-2019-16777", "CVE-2019-16776", "CVE-2020-10174", "CVE-2019-2391", "CVE-2020-7610", "CVE-2020-8518", "CVE-2019-9658", "CVE-2019-15690", "CVE-2019-20788"]),
        ("CVE-2019-16775", "npm", "debian:10", 1, ["CVE-2019-16775"]),
    ],
)
def test_query_vulnerabilities(
        grype_db_dir, vuln_id, affected_package, namespace, expected_result_length, expected_output
):
    # Setup the sqlalchemy artifacts on the test grype db
    test_grype_db_engine = grype_wrapper._init_grype_db_engine(grype_db_dir)
    grype_wrapper.grype_db_session = grype_wrapper._init_grype_db_session(test_grype_db_engine)

    # Test and validate the query param combinations
    results = grype_wrapper.query_vulnerabilities(
        vuln_id=vuln_id,
        affected_package=affected_package,
        namespace=namespace,

    )
    assert len(results) == expected_result_length
    assert list(map(lambda result: result[0].id, results)) == expected_output
