from anchore_engine.subsys import logger

from prometheus_client import Histogram, Summary, Gauge, Counter
from prometheus_flask_exporter import PrometheusMetrics

flask_metrics = None
metrics = {}

def init_flask_metrics(flask_app):
    global flask_metrics

    if not flask_metrics:
        flask_metrics = PrometheusMetrics(flask_app)

    return(True)

def get_flask_metrics_obj():
    global flask_metrics
    return(flask_metrics)

def histogram_observe(name, observation, description="", buckets=None):
    global metrics

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

    try:
        if name not in metrics:
            metrics[name] = Gauge(name, description)
        metrics[name].set(observation)
    except Exception as err:
        logger.warn("adding metric failed - exception: " + str(err))
        
    return(True)

def counter_inc(name, step=1, description=""):
    global metrics

    try:
        if name not in metrics:
            metrics[name] = Counter(name, description)
        metrics[name].inc(step)
    except Exception as err:
        logger.warn("adding metric failed - exception: " + str(err))
        
    return(True)
