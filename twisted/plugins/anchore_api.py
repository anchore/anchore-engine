"""
twistd plugin for running the anchore-api service. Contains service and cli options code.

e.g.
twistd anchore-api -c /config

"""

from twisted.application.service import IServiceMaker
from twisted.plugin import IPlugin
from zope.interface import implementer

from anchore_engine.services.apiext import ExternalApiService
from anchore_engine.twisted import WsgiApiServiceMaker, CommonOptions

@implementer(IServiceMaker, IPlugin)
class ExternalApiServiceMaker(WsgiApiServiceMaker):
    """
    Anchore External API twistd plugin.

    Invoke with 'twistd anchore-api -c <config>'

    """

    tapname = 'anchore-api'
    description = 'Anchore Engine External API Service. Provides the user-facing API.'
    service_cls = ExternalApiService
    options = CommonOptions


servicemaker = ExternalApiServiceMaker()
