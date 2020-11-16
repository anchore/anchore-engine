from anchore_engine.auth.aws_ecr import parse_registry_url, parse_role


def test_parse_registry_url_parses_url():

    urls = [
        ("1234567890.dkr.ecr.us-west-2.amazonaws.com", ("1234567890", "us-west-2")),
        (
            "1234567890.dkr.ecr.us-west-2.amazonaws.com/my_app_image",
            ("1234567890", "us-west-2"),
        ),
        ("account.dkr.ecr.eu-west-1.aws.amazon.com", ("account", "eu-west-1")),
        (
            "http://1234567890.dkr.ecr.us-west-2.amazonaws.com",
            ("1234567890", "us-west-2"),
        ),
        (
            "http://1234567890.dkr.ecr.us-west-2.amazonaws.com/my_app_image:latest",
            ("1234567890", "us-west-2"),
        ),
        ("http://account.dkr.ecr.eu-west-1.aws.amazon.com", ("account", "eu-west-1")),
    ]

    for url, expected in urls:
        print("Testing {} expected {}".format(url, expected))
        assert expected == parse_registry_url(url)


def test_parse_role():
    arns = [
        (
            "arn:aws::1010101123:role/Somerole",
            ("arn:aws::1010101123:role/Somerole", None),
        ),
        (
            "arn:aws::1010101123:role/Somerole;",
            ("arn:aws::1010101123:role/Somerole", None),
        ),
        (
            "arn:aws::1010101123:role/Somerole;0101",
            ("arn:aws::1010101123:role/Somerole", "0101"),
        ),
        (
            "arn:aws::1010101123:role/Somerole;0101;1",
            ("arn:aws::1010101123:role/Somerole", "0101"),
        ),
        (
            "arn:aws::1010101123:role/Somerole;0101;;",
            ("arn:aws::1010101123:role/Somerole", "0101"),
        ),
    ]

    for a in arns:
        assert a[1] == parse_role(a[0])
