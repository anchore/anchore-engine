import anchore_engine.configuration.localconfig
import os
import pytest
import shutil
import sqlalchemy

from anchore_engine.clients import grype_wrapper

TEST_DATA_PATH = "../../data/grype_db/"
GRYPE_DB_DIR = "grype_db/"


@pytest.fixture
def grype_db_dir(tmp_path):
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
def grype_db_file(tmp_path):
    input_dir = os.path.join(tmp_path, "input")
    if not os.path.exists(input_dir):
        os.mkdir(input_dir)
    shutil.copy("../../data/grype_db/vulnerability.db", input_dir)
    return os.path.join(input_dir, "vulnerability.db")


@pytest.fixture
def old_grype_db_file(tmp_path):
    input_dir = os.path.join(tmp_path, "input")
    if not os.path.exists(input_dir):
        os.mkdir(input_dir)
    shutil.copy("../../data/grype_db/old_vulnerability.db", input_dir)
    return os.path.join(input_dir, "vulnerability.db")


def get_test_sbom(sbom_file_name):
    full_sbom_path = os.path.join(TEST_DATA_PATH, sbom_file_name)
    # with open(full_sbom_path, "r") as read_file:
    #     return read_file.read().replace('\n', '')
    return full_sbom_path


def test_get_current_grype_db_checksum():
    # Function under test
    result = grype_wrapper.get_current_grype_db_checksum()

    # Validate result
    assert result == None


def test_get_default_cache_dir_from_config(grype_db_dir, tmp_path):
    # Function under test
    local_db_dir = grype_wrapper._get_default_grype_db_dir_from_config()

    # Validate the grype db dir exists and is in the correct location
    assert os.path.exists(local_db_dir)
    assert local_db_dir == grype_db_dir


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
    expected_grype_db_file = os.path.join(parent_dir, grype_wrapper.VULNERABILITY_FILE_NAME)

    # Function under test
    latest_grype_db_file = grype_wrapper._open_grype_db_archive(grype_db_archive, parent_dir)

    # Validate expect files and their location
    assert os.path.exists(expected_grype_db_file)
    assert latest_grype_db_file == os.path.join(parent_dir, grype_wrapper.VULNERABILITY_FILE_NAME)


def test_remove_grype_db_archive(grype_db_archive):
    # Function under test
    grype_wrapper._remove_grype_db_archive(grype_db_archive)

    # Validate
    assert not os.path.exists(grype_db_archive)


def test_init_grype_db_engine(grype_db_file):
    # Function under test
    latest_grype_db_engine = grype_wrapper._init_grype_db_engine(grype_db_file)
    assert str(latest_grype_db_engine.url) == "sqlite:///{}".format(grype_db_file)


def test_init_grype_db_session(grype_db_file):
    # Setup db engine
    db_connect = "sqlite:///{}".format(grype_db_file)
    latest_grype_db_engine = sqlalchemy.create_engine(db_connect, echo=True)
    assert str(latest_grype_db_engine.url) == "sqlite:///{}".format(grype_db_file)

    # Function under test
    latest_grype_db_session = grype_wrapper._init_grype_db_session(latest_grype_db_engine)

    # Validate output
    assert latest_grype_db_session is not None


def test_init_grype_db(grype_db_dir, grype_db_archive):
    # Setup out vars
    expected_output_file = os.path.join(grype_db_dir, grype_wrapper.VULNERABILITY_FILE_NAME)

    # Function under test
    latest_grype_db_file, latest_grype_db_session = grype_wrapper._init_grype_db(grype_db_archive)

    assert latest_grype_db_file == expected_output_file
    assert os.path.exists(latest_grype_db_file)
    assert latest_grype_db_session is not None


def test_remove_local_grype_db(grype_db_file):
    # Function under test
    grype_wrapper._remove_local_grype_db(grype_db_file)

    # Validate output
    assert not os.path.exists(grype_db_file)


def test_update_grype_db(grype_db_dir, old_grype_db_file, grype_db_archive):
    # Setup
    grype_wrapper.grype_db_file = old_grype_db_file
    expected_output_file = os.path.join(grype_db_dir, grype_wrapper.VULNERABILITY_FILE_NAME)

    # Function under test
    grype_wrapper.update_grype_db(grype_db_archive)

    # Validate output
    assert grype_wrapper.grype_db_file == expected_output_file
    assert os.path.exists(grype_wrapper.grype_db_file)
    assert grype_wrapper.grype_db_session is not None


# TODO Disabling for now. Something in the test db file used here isn't playing nice with grype. It works ok for the query test below.
# Googling it suggests the sqlite version used to read vs write the db can be a little touchy.
# @pytest.mark.parametrize(
#     "sbom_file_name, expected_output",
#     [
#         ("sbom-ubuntu-20.04--pruned.json", "ubuntu"),
#     ],
# )
# def test_get_vulnerabilities(grype_db_file, sbom_file_name, expected_output):
#     # Setup test inputs
#     grype_wrapper.grype_db_file = grype_db_file
#     test_sbom = get_test_sbom(sbom_file_name)
#
#     # Function under test
#     result = grype_wrapper.get_vulnerabilities(test_sbom)
#
#     # TODO Assert expected results
#     assert result["distro"]["name"] == expected_output


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
        grype_db_file, vuln_id, affected_package, namespace, expected_result_length, expected_output
):
    # Setup the sqlalchemy artifacts on the test grype db file
    test_grype_db_engine = grype_wrapper._init_grype_db_engine(grype_db_file)
    grype_wrapper.grype_db_session = grype_wrapper._init_grype_db_session(test_grype_db_engine)


    # Test and validate the query param combinations
    results = grype_wrapper.query_vulnerabilities(
        vuln_id=vuln_id,
        affected_package=affected_package,
        namespace=namespace,

    )
    assert len(results) == expected_result_length
    assert list(map(lambda result: result[0].id, results)) == expected_output
