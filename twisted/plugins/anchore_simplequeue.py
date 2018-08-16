from twisted.application.service import IServiceMaker
from twisted.plugin import IPlugin
from zope.interface import implementer

# anchore modules
from anchore_engine.services.simplequeue import SimpleQueueService
from anchore_engine.twisted import WsgiApiServiceMaker, CommonOptions


@implementer(IServiceMaker, IPlugin)
class SimpleQueueServiceMaker(WsgiApiServiceMaker):
    """
    Anchore Engine Analyzer Worker twistd plugin.

    Invoke with 'twistd anchore-worker -c <config>'

    """

    tapname = 'anchore-simplequeue'
    description = 'Anchore Engine SimpleQueue Service. Provides task queues.'
    service_cls = SimpleQueueService
    options = CommonOptions


servicemaker = SimpleQueueServiceMaker()

