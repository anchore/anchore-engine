import json
from anchore_engine.subsys import logger

def get_docker_registry_userpw(registry_record):
    user = pw = None

    try:
        if 'registry_type' in registry_record and registry_record['registry_type'] == 'awsecr':
            ecr_creds = json.loads(registry_record['registry_meta'])
            docker_auth_token = ecr_creds['authorizationToken']
            user, pw = docker_auth_token.split(":", 1)
        else:
            user = registry_record['registry_user']
            pw = registry_record['registry_pass']
    except Exception as err:
        logger.error("cannot fetch registry creds from registry record - exception: " + str(err))
        raise err

    return(user, pw)
