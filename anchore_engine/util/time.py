"""
Time utility functions
"""
import calendar
import datetime

# TODO: move other time utils into this module from utils.py, and other util* locations

SECONDS_PER_MINUTE = 60
SECONDS_PER_HOUR = SECONDS_PER_MINUTE * 60
SECONDS_PER_DAY = SECONDS_PER_HOUR * 24


def datetime_to_epoch(date_time: datetime.datetime) -> int:
    return calendar.timegm(date_time.timetuple())


def days_to_seconds(days: int) -> int:
    return days * SECONDS_PER_DAY
