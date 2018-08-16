import functools
import time

import anchore_engine.configuration.localconfig
from anchore_engine.subsys import logger
from anchore_engine.version import version

from prometheus_client import Histogram, Summary, Gauge, Counter
from prometheus_flask_exporter import PrometheusMetrics

enabled = False
flask_metrics = None
flask_metric_name = "flask_http_request_duration_seconds"
metrics = {}

#class anchore_flask_track(object):
#    def __init__(self, enabled, flask_metrics):
#        self.enabled = enabled
#        self.flask_metrics = flask_metrics
#    def __call__(self, func):
#        if self.enabled and self.flask_metrics:
#            import anchore_engine.subsys.metrics
#            timer = time.time()
#            rc = func
#            anchore_engine.subsys.metrics.histogram_observe("anchore_http_request_duration_seconds", time.time() - timer, path=request.path, method=request.method, status=httpcode)
#            return(rc)
#        else:
#            return(func)
            

#class anchore_flask_track(object):
#    def __init__(self):
#        pass
#    def __call__(self, func):
#        from anchore_engine.subsys.metrics import flask_metrics, enabled
#        if enabled:
#            flask_metrics.do_not_track()
#            with flask_metrics.histogram('anchore_http_request_duration_seconds', "", labels={'path': lambda: request.path, 'method': lambda: request.method, 'status': lambda respon#se: response[1]}).time():
#                rc = func
##            #@flask_metrics.do_not_track()
##            #rc = None
##            #with flask_metrics.histogram('anchore_http_request_duration_seconds', "", labels={'path': lambda: request.path, 'method': lambda: request.method, 'status': lambda resp#o#nse: response[1]}).time():
##            #    rc = func
#            return(rc)
#        else:
#            return(func)

class disabled_flask_metrics(object):
    def _call_nop(self):
        def decorator(f):
            @functools.wraps(f)
            def func(*args, **kwargs):
                return f(*args, **kwargs)
            return func
        return decorator
    def do_not_track(self):
        return self._call_nop()
    def counter(self, *args, **kwargs):
        return self._call_nop()
    def gauge(self, *args, **kwargs):
        return self._call_nop()
    def summary(self, *args, **kwargs):
        return self._call_nop()
    def histogram(self, *args, **kwargs):
        return self._call_nop()

def init_flask_metrics(flask_app, export_defaults=True, **kwargs):
    global flask_metrics, enabled

    try:
        localconfig = anchore_engine.configuration.localconfig.get_config()
        metrics_config = localconfig.get('metrics', {})
        enabled = bool(metrics_config.get('enable', False))
        if not enabled:
            enabled = bool(metrics_config.get('enabled', False))
    except Exception as err:
        logger.warn("unable to determine if metrics are enabled - exception: " + str(err))
        enabled = False

    if not enabled:
        flask_metrics = disabled_flask_metrics()
        return(True)
    
    if not flask_metrics:
        flask_metrics = PrometheusMetrics(flask_app, export_defaults=export_defaults)
        flask_metrics.info('anchore_service_info', "Anchore Service Static Information", version=version, **kwargs)

    return(True)

def is_enabled():
    global enabled
    return(enabled)

def get_flask_metrics_obj():
    global flask_metrics, enabled
    if not enabled:
        return(None)
    return(flask_metrics)

def get_summary_obj(name, description="", **kwargs):
    global metrics, enabled

    if not enabled:
        return(None)

    ret = None
    try:
        if name not in metrics:
            metrics[name] = Summary(name, description, list(kwargs.keys()))
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
            metrics[name] = Summary(name, description, list(kwargs.keys()))

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

    try:
        if name not in metrics:
            if buckets:
                buckets.append(float("inf"))
                metrics[name] = Histogram(name, description, list(kwargs.keys()), buckets=buckets)
            else:
                metrics[name] = Histogram(name, description, list(kwargs.keys()))

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
            metrics[name] = Gauge(name, description, list(kwargs.keys()))

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
            metrics[name] = Counter(name, description, list(kwargs.keys()))

        if kwargs:
            metrics[name].labels(**kwargs).inc(step)
        else:
            metrics[name].inc(step)

    except Exception as err:
        logger.warn("adding metric failed - exception: " + str(err))
        
    return(True)
