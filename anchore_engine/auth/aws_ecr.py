import re
import os
import pytz
import json
import time
import boto3
import datetime

from anchore_engine.subsys import logger
import anchore_engine.configuration.localconfig

def refresh_ecr_credentials(registry, access_key_id, secret_access_key):
    localconfig = anchore_engine.configuration.localconfig.get_config()

    try:
        (aid, dkr, ecr, region,azn,com) = registry.split(".")

        # check for special awsauto case
        if access_key_id == 'awsauto' or secret_access_key == 'awsauto':
            if 'allow_awsecr_iam_auto' in localconfig and localconfig['allow_awsecr_iam_auto']:
                access_key_id = secret_access_key = None
            else:
                raise Exception("registry is set to 'awsauto', but system is not configured to allow (allow_awsecr_iam_auto: False)")

        client = boto3.client('ecr', aws_access_key_id=access_key_id, aws_secret_access_key=secret_access_key, region_name=region)
        r = client.get_authorization_token()
        ecr_data = r['authorizationData'][0]
    except Exception as err:
        logger.warn("failure to get/refresh ECR credential - exception: " + str(err))
        raise err

    ret = {}
    ret['authorizationToken'] = ecr_data['authorizationToken'].decode('base64')
    ret['expiresAt'] = int(ecr_data['expiresAt'].strftime('%s'))

    return(ret)

