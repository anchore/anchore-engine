import anchore_engine.configuration.localconfig
from anchore_engine.subsys import logger
from anchore_engine.version import version

from prometheus_client import Histogram, Summary, Gauge, Counter
from prometheus_flask_exporter import PrometheusMetrics

enabled = False
flask_metrics = None
metrics = {}

def init_flask_metrics(flask_app, **kwargs):
    global flask_metrics, enabled

    try:
        localconfig = anchore_engine.configuration.localconfig.get_config()
        enabled = bool(localconfig.get('metrics_enable', False))
    except Exception as err:
        logger.warn("unable to determine if metrics are enabled - exception: " + str(err))
        enabled = False

    if not enabled:
        return(True)
    
    if not flask_metrics:
        flask_metrics = PrometheusMetrics(flask_app)
        flask_metrics.info('anchore_service_info', "Anchore Service Static Information", version=version, **kwargs)

    return(True)

def get_flask_metrics_obj():
    global flask_metrics, enabled

    if not enabled:
        return(True)

    return(flask_metrics)

def get_summary_obj(name, description=""):
    global enabled

    if not enabled:
        return(True)

    ret = None
    try:
        if name not in metrics:
            metrics[name] = Summary(name, description)
        ret = metrics[name]
    except:
        logger.warn("could not create/get named metric ("+str(name)+")")

    return(ret)

def summary_observe(name, observation, description=""):
    global metrics, enabled

    if not enabled:
        return(True)

    try:
        if name not in metrics:
            metrics[name] = Summary(name, description)

        metrics[name].observe(observation)
    except Exception as err:
        logger.warn("adding metric failed - exception: " + str(err))
        
    return(True)

def histogram_observe(name, observation, description="", buckets=None):
    global metrics, enabled

    if not enabled:
        return(True)

    buckets.append(float("inf"))
    try:
        if name not in metrics:
            if buckets:
                metrics[name] = Histogram(name, description, buckets=buckets)
            else:
                metrics[name] = Histogram(name, description)

        metrics[name].observe(observation)
    except Exception as err:
        logger.warn("adding metric failed - exception: " + str(err))
        
    return(True)

def gauge_set(name, observation, description=""):
    global metrics

    if not enabled:
        return(True)

    try:
        if name not in metrics:
            metrics[name] = Gauge(name, description)
        metrics[name].set(observation)
    except Exception as err:
        logger.warn("adding metric failed - exception: " + str(err))
        
    return(True)

def counter_inc(name, step=1, description=""):
    global metrics

    if not enabled:
        return(True)

    try:
        if name not in metrics:
            metrics[name] = Counter(name, description)
        metrics[name].inc(step)
    except Exception as err:
        logger.warn("adding metric failed - exception: " + str(err))
        
    return(True)
