import os

import pytest


@pytest.fixture
def expected_content(request):
    def _expected_content(filename):
        module_path = request.module.__file__
        test_directory = os.path.split(module_path)[0]
        module_filename_with_extension = os.path.basename(module_path)
        module_filename = os.path.splitext(module_filename_with_extension)[0]
        file_path = os.path.join(
            test_directory, "expected_content", module_filename, filename
        )

        with open(file_path, "rb") as f:
            return f.read()

    return _expected_content
