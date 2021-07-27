import base64
import time
from urllib.parse import urlparse

import boto3

import anchore_engine.configuration.localconfig
from anchore_engine import utils
from anchore_engine.subsys import logger


def parse_registry_url(registry_url):
    """
    Given an AWS ECR registry URL, parses out the AWS Account ID and Region

    >>> aid, region = parse_registry_url('http://12345.dkr.ecr.us-west-2.amazonaws.com')
    ('12345', 'us-west-2')

    >>> aid, region = parse_registry_url('12345.dkr.ecr.us-west-2.amazonaws.com')
    ('12345', 'us-west-2')

    Args:
      - registry_url (str): The AWS ECR Registry URL

    Returns a tuple of strings (aid, region)
    """
    parsed = urlparse(registry_url)
    host = parsed.hostname if parsed.hostname is not None else parsed.path
    (aid, dkr, ecr, region, rest) = host.split(
        ".", 4
    )  # We only care about the prefix bits to extract account and region
    return aid, region


def parse_role(role_str):
    components = role_str.split(";")  # pass = "role_arn;external_id"
    if len(components) > 1 and components[1]:
        return components[0], components[1]
    else:
        return components[0], None


def refresh_ecr_credentials(registry, access_key_id, secret_access_key):
    localconfig = anchore_engine.configuration.localconfig.get_config()

    try:
        account_id, region = parse_registry_url(registry)

        # aws: assume role on the ec2 instance
        if access_key_id == "awsauto" or secret_access_key == "awsauto":
            if (
                "allow_awsecr_iam_auto" in localconfig
                and localconfig["allow_awsecr_iam_auto"]
            ):
                access_key_id = secret_access_key = None
                client = boto3.client(
                    "ecr",
                    aws_access_key_id=access_key_id,
                    aws_secret_access_key=secret_access_key,
                    region_name=region,
                )
            else:
                raise Exception(
                    "registry is set to 'awsauto', but system is not configured to allow (allow_awsecr_iam_auto: False)"
                )

        # aws: assume cross account roles
        elif access_key_id == "_iam_role":
            try:
                sts = boto3.client("sts")
                role_arn, external_id = parse_role(secret_access_key)
                if external_id:
                    session = sts.assume_role(
                        RoleArn=role_arn,
                        RoleSessionName=str(int(time.time())),
                        ExternalId=external_id,
                    )
                else:
                    session = sts.assume_role(
                        RoleArn=role_arn, RoleSessionName=str(int(time.time()))
                    )

                access_key_id = session["Credentials"]["AccessKeyId"]
                secret_access_key = session["Credentials"]["SecretAccessKey"]
                session_token = session["Credentials"]["SessionToken"]
                client = boto3.client(
                    "ecr",
                    aws_access_key_id=access_key_id,
                    aws_secret_access_key=secret_access_key,
                    aws_session_token=session_token,
                    region_name=region,
                )
            except Exception as err:
                raise err
        # aws: provide key & secret
        else:
            client = boto3.client(
                "ecr",
                aws_access_key_id=access_key_id,
                aws_secret_access_key=secret_access_key,
                region_name=region,
            )
        r = client.get_authorization_token(registryIds=[account_id])
        ecr_data = r["authorizationData"][0]
    except Exception as err:
        logger.warn("failure to get/refresh ECR credential - exception: " + str(err))
        raise err

    ret = {}
    ret["authorizationToken"] = utils.ensure_str(
        base64.decodebytes(utils.ensure_bytes(ecr_data["authorizationToken"]))
    )
    ret["expiresAt"] = int(ecr_data["expiresAt"].strftime("%s"))

    return ret
