"""
Common threading utils for anchore engine services.

"""
import time
import threading
from anchore_engine.subsys import logger

# generic monitor_func implementation

click = 0
running = False
last_run = 0
monitor_thread = None


def default_monitor_func(**kwargs):
    """
    Generic monitor thread function for invoking tasks defined in a monitor dict

    :param kwargs:
    :return:
    """
    global click, running, last_run

    my_monitors = kwargs['monitors']
    monitor_threads = kwargs['monitor_threads']
    servicename = kwargs['servicename']

    timer = int(time.time())
    if click < 5:
        click = click + 1
        logger.debug("service ("+str(servicename)+") starting in: " + str(5 - click))
        return (True)

    if round(time.time() - last_run) < kwargs['kick_timer']:
        logger.spew(
            "timer hasn't kicked yet: " + str(round(time.time() - last_run)) + " : " + str(kwargs['kick_timer']))
        return (True)

    try:
        running = True
        last_run = time.time()

        # handle setting the cycle timers based on configuration
        for monitor_name in list(my_monitors.keys()):
            if not my_monitors[monitor_name]['initialized']:
                # first time
                if 'cycle_timers' in kwargs and monitor_name in kwargs['cycle_timers']:
                    try:
                        the_cycle_timer = my_monitors[monitor_name]['cycle_timer']
                        min_cycle_timer = my_monitors[monitor_name]['min_cycle_timer']
                        max_cycle_timer = my_monitors[monitor_name]['max_cycle_timer']

                        config_cycle_timer = int(kwargs['cycle_timers'][monitor_name])
                        if config_cycle_timer < 0:
                            the_cycle_timer = abs(int(config_cycle_timer))
                        elif config_cycle_timer < min_cycle_timer:
                            logger.warn("configured cycle timer for handler ("+str(monitor_name)+") is less than the allowed min ("+str(min_cycle_timer)+") - using allowed min")
                            the_cycle_timer = min_cycle_timer
                        elif config_cycle_timer > max_cycle_timer:
                            logger.warn("configured cycle timer for handler ("+str(monitor_name)+") is greater than the allowed max ("+str(max_cycle_timer)+") - using allowed max")
                            the_cycle_timer = max_cycle_timer
                        else:
                            the_cycle_timer = config_cycle_timer

                        my_monitors[monitor_name]['cycle_timer'] = the_cycle_timer
                    except Exception as err:
                        logger.warn("exception setting custom cycle timer for handler ("+str(monitor_name)+") - using default")

                my_monitors[monitor_name]['initialized'] = True

        # handle the thread (re)starters here
        for monitor_name in list(my_monitors.keys()):
            start_thread = False
            if monitor_name not in monitor_threads:
                start_thread = True
            else:
                if not monitor_threads[monitor_name].isAlive():
                    logger.debug("thread stopped - restarting: " + str(monitor_name))
                    monitor_threads[monitor_name].join()
                    start_thread = True

            if start_thread:
                monitor_threads[monitor_name] = threading.Thread(target=my_monitors[monitor_name]['handler'], args=my_monitors[monitor_name]['args'], kwargs={'mythread': my_monitors[monitor_name]})
                logger.debug("starting up monitor_thread: " + str(monitor_name))
                monitor_threads[monitor_name].start()

    except Exception as err:
        logger.error(str(err))
    finally:
        running = False

    return True


def monitor(*args, **kwargs):
    global monitor_thread
    try:
        donew = False
        if monitor_thread:
            if monitor_thread.isAlive():
                logger.spew("MON: thread still running")
            else:
                logger.spew("MON: thread stopped running")
                donew = True
                monitor_thread.join()
                logger.spew("MON: thread joined: isAlive=" + str(monitor_thread.isAlive()))
        else:
            logger.spew("MON: no thread")
            donew = True

        if donew:
            logger.spew("MON: starting")
            monitor_thread = threading.Thread(target=default_monitor_func, kwargs=kwargs)
            monitor_thread.start()
        else:
            logger.spew("MON: skipping")

    except Exception as err:
        logger.warn("MON thread start exception: " + str(err))
