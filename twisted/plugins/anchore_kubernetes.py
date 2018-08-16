"""
twistd plugin for running the anchore-kubernetes-webhook service
"""

from twisted.application.service import IServiceMaker
from twisted.plugin import IPlugin
from zope.interface import implementer

from anchore_engine.services.kubernetes_webhook import K8sWebhookHandlerService
from anchore_engine.twisted import WsgiApiServiceMaker, CommonOptions

@implementer(IServiceMaker, IPlugin)
class K8sWebhookHandlerServiceMaker(WsgiApiServiceMaker):
    """
    Anchore Engine Kubernetes Webhook handler service

    Invoke with 'twistd anchore-kubernetes-webhook -c <config_dir>'

    """

    tapname = 'anchore-kubernetes-webhook'
    description = 'Anchore Engine Kubernetes ImagePolicyWebhook handler service'
    service_cls = K8sWebhookHandlerService
    options = CommonOptions


servicemaker = K8sWebhookHandlerServiceMaker()
