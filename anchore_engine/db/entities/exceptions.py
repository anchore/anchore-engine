"""
Exception handling utilities and functions.

NOTE: these are PostgreSQL specific, so any dialect change will require updates here.

"""

from sqlalchemy.exc import ProgrammingError

PG_UNIQUE_CONSTRAINT_VIOLATION_CODE = '23505'
PG_COULD_NOT_GET_ROWLOCK_CODE = '55P03'
PG_RELATION_NOT_FOUND_CODE = '42P01'

from anchore_engine.subsys import logger

class AnchoreDbError(Exception):
    pass


class DuplicateKeyError(AnchoreDbError):
    pass


class LockAcquisitionError(AnchoreDbError):
    pass


class TableNotFoundError(AnchoreDbError):
    pass


def is_unique_violation(ex):
    """
    Is the exception an indication of a unique constraint violation or other

    :param ex: Exception object
    :return: Boolean
    """
    return isinstance(ex, ProgrammingError) and hasattr(ex, 'orig') and str(ex.orig.args[0]) == 'ERROR' and str(ex.orig.args[2]) == PG_UNIQUE_CONSTRAINT_VIOLATION_CODE


def is_lock_acquisition_error(ex):
    """
    Is the exception an indication of a failure to get a row lock.

    :param ex: Exception object
    :return: Boolean
    """
    return isinstance(ex, ProgrammingError) and hasattr(ex, 'orig') and str(ex.orig.args[0]) == 'ERROR' and str(ex.orig.args[2]) == PG_COULD_NOT_GET_ROWLOCK_CODE


def is_table_not_found(ex):
    return isinstance(ex, ProgrammingError) and hasattr(ex, 'orig') and str(ex.orig.args[0]) == 'ERROR' and (str(ex.orig.args[2]) == PG_RELATION_NOT_FOUND_CODE or str(ex.orig.args[2]) == PG_RELATION_NOT_FOUND_CODE)
