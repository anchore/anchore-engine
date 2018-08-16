from twisted.application.service import IServiceMaker
from twisted.plugin import IPlugin
from zope.interface import implementer

# anchore modules
from anchore_engine.services.analyzer import AnalyzerService
from anchore_engine.twisted import WsgiApiServiceMaker, CommonOptions

@implementer(IServiceMaker, IPlugin)
class ExternalApiServiceMaker(WsgiApiServiceMaker):
    """
    Anchore Engine Analyzer Worker twistd plugin.

    Invoke with 'twistd anchore-worker -c <config>'

    """

    tapname = 'anchore-worker'
    description = 'Anchore Engine Worker Service. Provides image analysis services.'
    service_cls = AnalyzerService
    options = CommonOptions


servicemaker = ExternalApiServiceMaker()

