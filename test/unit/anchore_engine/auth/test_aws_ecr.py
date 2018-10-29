from anchore_engine.auth.aws_ecr import parse_registry_url


def test_parse_registry_url_parses_url():

    urls = [
        '1234567890.dkr.ecr.us-west-2.amazonaws.com',
        '1234567890.dkr.ecr.us-west-2.amazonaws.com/my_app_image',
        'http://1234567890.dkr.ecr.us-west-2.amazonaws.com',
        'http://1234567890.dkr.ecr.us-west-2.amazonaws.com/my_app_image:latest'
    ]

    expected = ('1234567890', 'us-west-2')

    for url in urls:
        assert(expected == parse_registry_url(url))

