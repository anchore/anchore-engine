import sys
import os

from twisted.application.service import IServiceMaker
from twisted.plugin import IPlugin
from twisted.python import log
from twisted.python import usage
from zope.interface import implements

# anchore modules
from anchore_engine.configuration import localconfig
import anchore_engine.services.common
from anchore_engine.subsys import logger


class Options(usage.Options):
#class Options(usage.Options, strcred.AuthOptionMixin):
#    supportedInterfaces = (credentials.IUsernamePassword,)

    optParameters = [
        ["config", "c", None, "Configuration directory location."]
    ]

class AnchoreServiceMaker(object):
    implements(IServiceMaker, IPlugin)
    tapname = "anchore-catalog"
    servicenames = ["catalog"]
    description = "Anchore Container Image Scanner Service: " + ','.join(servicenames)
    options = Options

    def makeService(self, options): 
        slist = []

        try:
            configfile = os.path.join(options['config'], 'config.yaml')
            config = localconfig.read_config(configfile=configfile)
        except Exception as err:
            log.err("cannot load local configuration: " + str(err))
            raise err

        log_level = 'INFO'
        log_to_db = False
        if 'log_level' in config:
            log_level = config['log_level']
        if 'log_to_db' in config:
            log_to_db = config['log_to_db']

        slist = self.servicenames

        try:
            config_services = config['services']
            
            isEnabled = False
            for sname in slist:
                if 'log_level' in config_services[sname]:
                    log_level = config_services[sname]['log_level']

                if config_services[sname]['enabled']:
                    isEnabled = True
                    break
                    
            if not isEnabled:
                log.err("no services in list ("+str(self.servicenames)+") are enabled in configuration file: shutting down")
                sys.exit(0)

        except Exception as err:
            log.err("error checking for enabled services, check config file - exception: " + str(err))
            raise Exception("error checking for enabled services, check config file - exception: " + str(err))

        try:
            logger.set_log_level(log_level, log_to_db=log_to_db)
        except Exception as err:
            log.err("exception while initializing logger - exception: "  + str(err))
            logger.set_log_level('INFO')

        r = anchore_engine.services.common.makeService(slist, options)
        return(r)

serviceMaker = AnchoreServiceMaker()
