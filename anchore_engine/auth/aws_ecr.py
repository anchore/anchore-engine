import re
import os
import pytz
import json
import time
import boto3
import datetime

from anchore_engine.subsys import logger

def refresh_ecr_credentials(registry, access_key_id, secret_access_key):

    try:
        (aid, dkr, ecr, region,azn,com) = registry.split(".")
        client = boto3.client('ecr', aws_access_key_id=access_key_id, aws_secret_access_key=secret_access_key, region_name=region)
        r = client.get_authorization_token()
        ecr_data = r['authorizationData'][0]
    except Exception as err:
        logger.warn("failure to refresh ECR credential - exception: " + str(err))
        raise err

    ret = {}
    ret['authorizationToken'] = ecr_data['authorizationToken'].decode('base64')
    ret['expiresAt'] = int(ecr_data['expiresAt'].strftime('%s'))

    return(ret)

