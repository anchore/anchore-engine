"""
Time utility functions
"""
import calendar
import datetime

SECONDS_PER_MINUTE = 60
SECONDS_PER_HOUR = SECONDS_PER_MINUTE * 60
SECONDS_PER_DAY = SECONDS_PER_HOUR * 24
RFC3339_DATE_OUTPUT_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
RFC3339_DATE_INPUT_FORMATS = [
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%S:%fZ",
]


def datetime_to_epoch(date_time: datetime.datetime) -> int:
    """Convert a datetime object to epoch time and return it as an int

    :param date_time: datetime object to convert
    :return: integer epoch seconds
    """
    return calendar.timegm(date_time.timetuple())


def days_to_seconds(days: int) -> int:
    """Convert specified number of days into seconds

    :param days: number of days as int
    :return: integer number of seconds in the 'days' number of days
    """
    return days * SECONDS_PER_DAY


def rfc3339str_to_epoch(rfc3339_str: str) -> int:
    return int(rfc3339str_to_datetime(rfc3339_str).timestamp())


def rfc3339str_to_datetime(rfc3339_str: str) -> datetime.datetime:
    """
    Convert the rfc3339 formatted string (UTC only) to a datatime object with tzinfo explicitly set to utc. Raises an exception if the parsing fails.

    :param rfc3339_str: the RFC3339 timestamp to convert in string representation
    :return: datetime object for the given RFC3339 timestamp
    """

    ret = None
    for fmt in RFC3339_DATE_INPUT_FORMATS:
        try:
            ret = datetime.datetime.strptime(rfc3339_str, fmt)
            # Force this since the formats we support are all utc formats, to support non-utc
            if ret.tzinfo is None:
                ret = ret.replace(tzinfo=datetime.timezone.utc)
            continue
        except (ValueError, TypeError):
            pass

    if ret is None:
        raise ValueError(
            "could not convert input value ({}) into datetime using formats in {}".format(
                rfc3339_str, RFC3339_DATE_INPUT_FORMATS
            )
        )

    return ret


def datetime_to_rfc3339(dt_obj: datetime.datetime) -> str:
    """
    Simple utility function. Expects a UTC input, does no tz conversion

    :param dt_obj: datetime object to convert
    :return: string datetime in RFC3339 format
    """

    return dt_obj.strftime(RFC3339_DATE_OUTPUT_FORMAT)


def epoch_to_rfc3339(epoch_int: int) -> str:
    """
    Convert an epoch int value to a RFC3339 datetime string

    :param epoch_int: integer epoch time to convert
    :return: string datetime in RFC339 format
    """
    return datetime_to_rfc3339(datetime.datetime.utcfromtimestamp(epoch_int))
