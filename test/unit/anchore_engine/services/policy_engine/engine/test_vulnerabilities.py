from anchore_engine.services.policy_engine.engine import vulnerabilities
from anchore_engine.subsys import logger

logger.enable_test_logging(level='info')

def test_namespace_has_no_feed():
    """
    Test the caching mechanisms used during feed syncs to optimize lookups w/o db access
    :return:
    """
    # Nothing initially
    assert vulnerabilities.namespace_has_no_feed('debian', '8')

    vulnerabilities.ThreadLocalFeedGroupNameCache.add([('debian:8', True), ('debian:9', True), ('centos:4', False)])
    assert vulnerabilities.ThreadLocalFeedGroupNameCache.lookup('debian:8') == ('debian:8', True)
    assert vulnerabilities.ThreadLocalFeedGroupNameCache.lookup('debian:9') == ('debian:9', True)
    assert vulnerabilities.ThreadLocalFeedGroupNameCache.lookup('centos:4') == ('centos:4', False)
    assert not vulnerabilities.namespace_has_no_feed('debian', '8')
    assert not vulnerabilities.namespace_has_no_feed('debian', '9')
    assert vulnerabilities.namespace_has_no_feed('debian', 'foobar')
    assert vulnerabilities.namespace_has_no_feed('centos', '4')

    # Empty
    vulnerabilities.ThreadLocalFeedGroupNameCache.flush()
    assert vulnerabilities.namespace_has_no_feed('debian', '8')
