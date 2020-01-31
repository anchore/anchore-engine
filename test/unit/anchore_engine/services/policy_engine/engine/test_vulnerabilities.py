from anchore_engine.services.policy_engine.engine import vulnerabilities


def test_namespace_has_no_feed():
    """
    Test the caching mechanisms used during feed syncs to optimize lookups w/o db access
    :return:
    """
    # Nothing initially
    assert vulnerabilities.namespace_has_no_feed('debian', '8')

    vulnerabilities.ThreadLocalFeedGroupNameCache.add(['debian:8', 'debian:9'])
    assert not vulnerabilities.namespace_has_no_feed('debian', '8')
    assert not vulnerabilities.namespace_has_no_feed('debian', '9')
    assert vulnerabilities.namespace_has_no_feed('debian', 'foobar')

    # Empty
    vulnerabilities.ThreadLocalFeedGroupNameCache.flush()
    assert vulnerabilities.namespace_has_no_feed('debian', '8')
