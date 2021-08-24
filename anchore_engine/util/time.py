"""
Time utility functions
"""
import calendar
import datetime

SECONDS_PER_MINUTE = 60
SECONDS_PER_HOUR = SECONDS_PER_MINUTE * 60
SECONDS_PER_DAY = SECONDS_PER_HOUR * 24


def datetime_to_epoch(date_time: datetime.datetime) -> int:
    return calendar.timegm(date_time.timetuple())


def days_to_seconds(days: int) -> int:
    return days * SECONDS_PER_DAY


rfc3339_date_fmt = "%Y-%m-%dT%H:%M:%SZ"
rfc3339_date_input_fmts = [
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%S:%fZ",
]


def rfc3339str_to_epoch(rfc3339_str: str) -> int:
    return int(rfc3339str_to_datetime(rfc3339_str).timestamp())


def rfc3339str_to_datetime(rfc3339_str: str) -> datetime.datetime:
    """
    Convert the rfc3339 formatted string (UTC only) to a datatime object with tzinfo explicitly set to utc. Raises an exception if the parsing fails.

    :param rfc3339_str:
    :return:
    """

    ret = None
    for fmt in rfc3339_date_input_fmts:
        try:
            ret = datetime.datetime.strptime(rfc3339_str, fmt)
            # Force this since the formats we support are all utc formats, to support non-utc
            if ret.tzinfo is None:
                ret = ret.replace(tzinfo=datetime.timezone.utc)
            continue
        except:
            pass

    if ret is None:
        raise Exception(
            "could not convert input value ({}) into datetime using formats in {}".format(
                rfc3339_str, rfc3339_date_input_fmts
            )
        )

    return ret


def datetime_to_rfc3339(dt_obj: datetime.datetime) -> str:
    """
    Simple utility function. Expects a UTC input, does no tz conversion

    :param dt_obj:
    :return:
    """

    return dt_obj.strftime(rfc3339_date_fmt)


def epoch_to_rfc3339(epoch_int: int) -> str:
    """
    Convert an epoch int value to a RFC3339 datetime string

    :param epoch_int:
    :return:
    """
    return datetime_to_rfc3339(datetime.datetime.utcfromtimestamp(epoch_int))
