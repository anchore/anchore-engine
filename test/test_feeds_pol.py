import json
from anchore_engine.subsys import logger
from anchore_engine.configuration.localconfig import load_config
load_config('/config')
from anchore_engine.services.policy_engine.engine.feeds import AnchoreFeedServiceClient
import logging
logging.basicConfig(level='DEBUG')
root_log = logging.getLogger()
logger.log = root_log
logger.log.msg = root_log.info

c = AnchoreFeedServiceClient()
print(c.list_feeds())
print(c.list_feed_groups('packages'))
print(json.dumps(c.get_feed_group_data('packages', 'npm'), indent=2))
