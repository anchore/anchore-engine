import os

from twisted.python import log, logfile


def logger():
    try:
        if "ANCHORE_LOGFILE" in os.environ:
            thefile = os.environ["ANCHORE_LOGFILE"]
        else:
            thefile = "anchore-general.log"
    except Exception:
        thefile = "anchore-general.log"

    f = logfile.LogFile(thefile, "/var/log/", rotateLength=10000000, maxRotatedFiles=10)
    log_observer = log.FileLogObserver(f)

    return log_observer.emit


# def logger():
#    return log.PythonLoggingObserver().emit
