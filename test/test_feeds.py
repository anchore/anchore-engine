from anchore_engine.configuration.localconfig import load_config
from anchore_engine.clients.feeds.anchore_io.feeds import get_client
load_config('/config')
c = get_client()
print(c.list_feeds())
print(c.list_feed_groups('vulnerabilities'))
print(c.get_feed_group_data('vulnerabilities', 'alpine:3.3'))
