from twisted.application.service import IServiceMaker
from twisted.plugin import IPlugin
from zope.interface import implementer

# anchore modules
from anchore_engine.services.policy_engine import PolicyEngineService
from anchore_engine.twisted import WsgiApiServiceMaker, CommonOptions


@implementer(IServiceMaker, IPlugin)
class PolicyEngineServiceMaker(WsgiApiServiceMaker):
    """
    Anchore Engine Policy Engine twistd plugin.

    Invoke with 'twistd anchore-policy-engine -c <config>'

    """

    tapname = 'anchore-policy-engine'
    description = 'Anchore Engine Policy Engine Service. Provides policy evaluation service.'
    service_cls = PolicyEngineService
    options = CommonOptions


servicemaker = PolicyEngineServiceMaker()
