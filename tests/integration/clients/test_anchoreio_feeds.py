import datetime

from anchore_engine.services.policy_engine.engine.feeds.client import get_feeds_client
from anchore_engine.services.policy_engine.engine.feeds.config import SyncConfig
from anchore_engine.subsys import logger
from tests.utils import init_test_logging

feed_url = "https://ancho.re/v1/service/feeds"
init_test_logging(level="info")


def test_anon_user():
    test_client = get_feeds_client(
        SyncConfig(
            enabled=True,
            url=feed_url,
            username="anon@ancho.re",
            password="pbiU2RYZ2XrmYQ",
            connection_timeout_seconds=10,
            read_timeout_seconds=30,
        )
    )
    for f in test_client.list_feeds().feeds:
        try:
            test_client.list_feed_groups(f.name)
        except Exception as e:
            logger.error(("Caught: {} for feed:  {}".format(e, f)))
    test_client.get_feed_group_data(
        "vulnerabilities", "alpine:3.6", since=datetime.datetime.utcnow()
    )


# def test_auth_error():
#    with pytest.raises(InvalidCredentialsError):
#        test_client = get_client(feeds_url=feed_url,
#                                 token_url=token_url,
#                                 client_url=client_url,
#                                 user=('anon@ancho.re', 'foobar'),
#                                 conn_timeout=10,
#                                 read_timeout=30)
#        f = test_client.list_feeds()


def test_feed_sync():
    test_client = get_feeds_client(
        SyncConfig(
            enabled=True,
            url=feed_url,
            username="anon@ancho.re",
            password="pbiU2RYZ2XrmYQ",
            connection_timeout_seconds=10,
            read_timeout_seconds=30,
        )
    )
    for f in test_client.list_feeds().feeds:
        try:
            test_client.list_feed_groups(f.name)
        except Exception as e:
            logger.info(("Caught: {} for feed:  {}".format(e, f)))

    next_token = False
    since_time = None
    feed = "vulnerabilities"
    group = "alpine:3.6"
    last_token = None

    while next_token is not None:
        logger.info("Getting a page of data")
        if next_token:
            last_token = next_token
            logger.info("Using token: {}".format(next_token))
            data = test_client.get_feed_group_data(
                feed, group, since=since_time, next_token=next_token
            )
        else:
            last_token = None
            data = test_client.get_feed_group_data(feed, group, since=since_time)

        next_token = data.next_token
        logger.info(
            "Got {} items and new next token: {}".format(data.record_count, next_token)
        )

        if next_token:
            assert next_token != last_token
        assert len(data.data) > 0
