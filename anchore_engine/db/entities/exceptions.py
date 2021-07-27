"""
Exception handling utilities and functions.

NOTE: these are PostgreSQL specific, so any dialect change will require updates here.

"""

try:
    # Separate logger for use during bootstrap when logging may not be fully configured
    from anchore_engine.subsys import logger  # pylint: disable=C0412,C0413
except:
    import logging

    logger = logging.getLogger(__name__)

PG_UNIQUE_CONSTRAINT_VIOLATION_CODE = "23505"
PG_COULD_NOT_GET_ROWLOCK_CODE = "55P03"
PG_RELATION_NOT_FOUND_CODE = "42P01"


def _get_pgcode_from_ex(ex):
    pgcode = None
    try:
        pgcode = ex.orig.pgcode
    except:
        try:
            pgcode = ex.orig.args[2]
        except:
            pass

    if not pgcode:
        logger.warn(
            "cannot extract PG code from driver exception - exception details: {}".format(
                ex
            )
        )

    return pgcode


def is_unique_violation(ex):
    """
    Is the exception an indication of a unique constraint violation or other

    :param ex: Exception object
    :return: Boolean
    """
    ret = False
    pgcode = _get_pgcode_from_ex(ex)
    if pgcode and pgcode == PG_UNIQUE_CONSTRAINT_VIOLATION_CODE:
        ret = True
    return ret
    # return isinstance(ex, ProgrammingError) and hasattr(ex, 'orig') and str(ex.orig.args[0]) == 'ERROR' and str(ex.orig.args[2]) == PG_UNIQUE_CONSTRAINT_VIOLATION_CODE


def is_lock_acquisition_error(ex):
    """
    Is the exception an indication of a failure to get a row lock.

    :param ex: Exception object
    :return: Boolean
    """
    ret = False
    pgcode = _get_pgcode_from_ex(ex)
    if pgcode and pgcode == PG_COULD_NOT_GET_ROWLOCK_CODE:
        ret = True
    return ret
    # return isinstance(ex, ProgrammingError) and hasattr(ex, 'orig') and str(ex.orig.args[0]) == 'ERROR' and str(ex.orig.args[2]) == PG_COULD_NOT_GET_ROWLOCK_CODE


def is_table_not_found(ex):
    ret = False
    pgcode = _get_pgcode_from_ex(ex)
    if pgcode and pgcode == PG_RELATION_NOT_FOUND_CODE:
        ret = True
    return ret
    # return isinstance(ex, ProgrammingError) and hasattr(ex, 'orig') and str(ex.orig.args[0]) == 'ERROR' and (str(ex.orig.args[2]) == PG_RELATION_NOT_FOUND_CODE or str(ex.orig.args[2]) == PG_RELATION_NOT_FOUND_CODE)
