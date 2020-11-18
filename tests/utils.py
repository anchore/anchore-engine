"""
Utilities for setting up and running tests of all types
"""
from anchore_engine.subsys.logger import enable_test_logging


def init_test_logging(level="debug", output_file=None):
    """
    Initialize logging configured to use a standard logger rather than a twistd logger
    :return:
    """

    # For other services, but shows output as 'bootstrap'
    enable_test_logging(level=level.upper(), outfile=output_file)
