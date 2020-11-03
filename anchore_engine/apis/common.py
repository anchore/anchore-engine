from anchore_engine.apis.context import ApiRequestContextProxy


def version_response(versions):
    return {
        "service": {"version": versions.get("service_version", None)},
        "api": {},
        "db": {"schema_version": versions.get("db_version", None)},
    }


def health_check():
    """
    :return: string "ok" always
    """
    return "ok"


def version_check():
    """
    :return:
    """
    return version_response(ApiRequestContextProxy.get_service().versions), 200
