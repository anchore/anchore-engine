"""
Operations for process things like exit codes, forking etc
"""

import enum
import sys


class ExitCode(enum.Enum):
    """
    Exit codes and conditions for consistency in the CLI
    """

    ok = 0
    failed = 2
    obj_store_failed = (
        5  # Special value for compat with the object store ops return codes
    )


def doexit(ecode: ExitCode):
    """
    Robust exit, closing stdout and stderr

    :param ecode:
    :return:
    """

    try:
        sys.stdout.close()
    except:
        pass
    try:
        sys.stderr.close()
    except:
        pass

    sys.exit(ecode.value)


def fail_exit():
    """
    Simplest way to exit cleanly
    :return:
    """

    doexit(ExitCode.failed)
