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
        metrics_config = localconfig.get('metrics', {})
        enabled = bool(metrics_config.get('enable', False))
    except Exception as err:
        logger.warn("unable to determine if metrics are enabled - exception: " + str(err))
        enabled = False

    if not enabled:
        return(True)
    
    if not flask_metrics:
        flask_metrics = PrometheusMetrics(flask_app)
        flask_metrics.info('anchore_service_info', "Anchore Service Static Information", version=version, **kwargs)

    return(True)

def is_enabled():
    global enabled
    return(enabled)

def get_flask_metrics_obj():
    global flask_metrics, enabled

    if not enabled:
        return(True)

    return(flask_metrics)

def get_summary_obj(name, description="", **kwargs):
    global enabled

    if not enabled:
        return(True)

    ret = None
    try:
        if name not in metrics:
            metrics[name] = Summary(name, description, kwargs.keys())
        ret = metrics[name]
    except:
        logger.warn("could not create/get named metric ("+str(name)+")")

    return(ret)

def summary_observe(name, observation, description="", **kwargs):
    global metrics, enabled

    if not enabled:
        return(True)

    try:
        if name not in metrics:
            metrics[name] = Summary(name, description, kwargs.keys())

        if kwargs:
            metrics[name].labels(**kwargs).observe(observation)
        else:
            metrics[name].observe(observation)

    except Exception as err:
        logger.warn("adding metric failed - exception: " + str(err))
        
    return(True)

def histogram_observe(name, observation, description="", buckets=None, **kwargs):
    global metrics, enabled

    if not enabled:
        return(True)

    buckets.append(float("inf"))
    try:
        if name not in metrics:
            if buckets:
                metrics[name] = Histogram(name, description, kwargs.keys(), buckets=buckets)
            else:
                metrics[name] = Histogram(name, description, kwargs.keys())

        if kwargs:
            metrics[name].labels(**kwargs).observe(observation)
        else:
            metrics[name].observe(observation)
    except Exception as err:
        logger.warn("adding metric failed - exception: " + str(err))
        
    return(True)

def gauge_set(name, observation, description="", **kwargs):
    global metrics

    if not enabled:
        return(True)

    try:
        if name not in metrics:
            metrics[name] = Gauge(name, description, kwargs.keys())

        if kwargs:
            metrics[name].labels(**kwargs).set(observation)
        else:
            metrics[name].set(observation)

    except Exception as err:
        logger.warn("adding metric failed - exception: " + str(err))
        
    return(True)

def counter_inc(name, step=1, description="", **kwargs):
    global metrics

    if not enabled:
        return(True)

    try:
        if name not in metrics:
            metrics[name] = Counter(name, description, kwargs.keys())

        if kwargs:
            metrics[name].labels(**kwargs).inc(step)
        else:
            metrics[name].inc(step)

    except Exception as err:
        logger.warn("adding metric failed - exception: " + str(err))
        
    return(True)
