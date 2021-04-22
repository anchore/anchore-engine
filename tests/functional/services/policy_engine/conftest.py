import json
import os
from os import path
from typing import Callable, ContextManager, Dict, List, Optional

import jsonschema
import pytest

from anchore_engine.db.entities.common import (
    do_disconnect,
    end_session,
    get_engine,
    initialize,
)

CURRENT_DIR = path.dirname(path.abspath(__file__))
EXPECTED_CONTENT_FOLDER_NAME = "expected_output"
SCHEMA_FILE_FOLDER_NAME = "schema_files"


def read_expected_content(module_path, filename):
    """
    Loads expected vulnerability response json for a given image_digest
    :param filename: name of file from which to load response
    :type filename: str
    :return: expected vulnerability response json
    :rtype: Dict
    """
    module_filename_with_extension = path.basename(module_path)
    test_directory = path.split(module_path)[0]
    module_filename = path.splitext(module_filename_with_extension)[0]
    file_path = path.join(
        CURRENT_DIR,
        test_directory,
        EXPECTED_CONTENT_FOLDER_NAME,
        module_filename,
        f"{filename}.json",
    )
    with open(file_path, "r") as f:
        file_contents = f.read()
        return json.loads(file_contents)


@pytest.fixture
def expected_content(request) -> Callable:
    """
    Returns method that will load expected vulnerability response json for a given image_digest
    :rtype: Callable[[str], Dict]
    :return: method that loads expected response json
    """

    def get_expected_content(filename):
        module_path = request.module.__file__
        return read_expected_content(module_path, filename)

    return get_expected_content


class SchemaResolver:
    """
    Singleton class that wraps the jsonschema loading logic, which allows us to only have to load and check the jsonschema files once.
    """

    def __init__(self, test_directories: List[str]):
        self._test_directories: List[str] = test_directories
        self.resolver: Optional[jsonschema.RefResolver] = None
        self._resolve()

    @classmethod
    def _load_jsonschema(cls, test_directory, filename) -> Dict:
        """
        Load a jsonschema from file
        :param filename: name of jsonschema file to load
        :type filename: str
        :return: schema json as dict
        :rtype: Dict
        """
        file_path = os.path.join(test_directory, filename)
        with open(file_path, "r") as f:
            file_contents = f.read()
        schema = json.loads(file_contents)
        return schema

    def _resolve(self) -> None:
        """
        Load jsonschema files, check that the schemas are valid, and create schema resolver.
        """
        schema_map: Dict[str, Dict] = {}
        for test_directory in self._test_directories:
            test_directory_path = os.path.join(
                CURRENT_DIR, test_directory, SCHEMA_FILE_FOLDER_NAME
            )
            for file in os.listdir(test_directory_path):
                if "schema.json" in file:
                    schema = self._load_jsonschema(test_directory_path, file)
                    jsonschema.Draft7Validator.check_schema(schema)
                    schema_map[schema["$id"]] = schema
        self.resolver = jsonschema.RefResolver(
            base_uri="", referrer="", store=schema_map
        )

    def get_schema(self, url: str) -> Dict:
        """
        Retrieves a given schema file
        :param url: name of the schema file to retrieve
        :type url: str
        :return: schema
        :rtype: Dict
        """
        return self.resolver.resolve_from_url(url)

    def get_validator(self, url) -> jsonschema.Draft7Validator:
        """
        Creates the validator for a given schema
        :param url: name of the schema validator to create
        :type url: str
        :return: jsonschema validator
        :rtype: jsonschema.Draft7Validator
        """
        return jsonschema.Draft7Validator(self.get_schema(url), resolver=self.resolver)


TEST_DIRECTORIES = ["vulnerability_data_tests", "feeds_data_tests"]
SCHEMA_RESOLVER = SchemaResolver(TEST_DIRECTORIES)


@pytest.fixture(scope="class")
def schema_validator() -> Callable[[str], jsonschema.Draft7Validator]:
    """
    Returns function that loads jsonschema validator for given schema filename
    :return: jsonschema validator generator
    :rtype: Callable[[str], jsonschema.Draft7Validator]
    """

    def _schema_validator(schema_filename: str) -> jsonschema.Draft7Validator:
        return SCHEMA_RESOLVER.get_validator(schema_filename)

    return _schema_validator


@pytest.fixture(scope="session")
def set_env_vars(monkeysession) -> None:
    """
    Setup environment variables for database connection.
    """
    if not os.getenv("ANCHORE_TEST_DB_URL"):
        monkeysession.setenv(
            "ANCHORE_TEST_DB_URL",
            "postgresql://postgres:mysecretpassword@anchore-db:5432/postgres",
        )


@pytest.fixture(scope="package")
def anchore_db() -> ContextManager[bool]:
    """
    Sets up a db connection to an existing db, and fails if not found/present
    Different from the fixture in test/fixtures.py in that it does not drop existing data upon making a connection
    :return: True after connection setup (not actual connection object).
    :rtype: ContextManager[bool]
    """

    conn_str = os.getenv("ANCHORE_TEST_DB_URL")
    assert conn_str
    config = {"credentials": {"database": {"db_connect": conn_str}}}
    try:
        ret = initialize(localconfig=config)
        yield ret
    finally:
        end_session()
        do_disconnect()
