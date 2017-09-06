from anchore_engine.clients.policy_engine import get_client
from anchore_engine.clients.policy_engine.generated.models import FeedUpdateNotification
c = get_client(host='http://localhost:87/v1',user='admin', password='foobar')
f = FeedUpdateNotification()
f.feed_name = 'vulnerabilities'
f.feed_group = 'centos:7'
r= c.create_feed_update(f)
print(r)
