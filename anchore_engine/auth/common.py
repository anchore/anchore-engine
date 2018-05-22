import time
import json
from anchore_engine.subsys import logger

def get_docker_registry_userpw(registry_record):
    user = pw = None

    try:
        if 'registry_type' in registry_record and registry_record['registry_type'] == 'awsecr':
            try:
                ecr_creds = json.loads(registry_record['registry_meta'])
            except Exception as err:
                raise Exception("cannot access/parse registry metadata for awsecr registry type - exception: {}".format(str(err)))

            docker_auth_token = ecr_creds['authorizationToken']
            user, pw = docker_auth_token.split(":", 1)
        else:
            user = registry_record['registry_user']
            pw = registry_record['registry_pass']
    except Exception as err:
        logger.error("cannot fetch registry creds from registry record - exception: " + str(err))
        raise err

    return(user, pw)

def get_creds_by_registry(registry, registry_creds=[]):
    user = pw = registry_verify = None
    try:
        for registry_record in registry_creds:
            if registry_record['registry'] == registry:
                if registry_record['record_state_key'] not in ['active']:
                    try:
                        last_try = int(registry_record['record_state_val'])
                    except:
                        last_try = 0

                    if (int(time.time()) - last_try) < 60:
                        logger.debug("SKIPPING REGISTRY ATTEMPT: " + str(registry_record['record_state_key']))
                        raise Exception("registry not available - " + str(registry_record['record_state_key']))

                user, pw = get_docker_registry_userpw(registry_record)
                registry_verify = registry_record['registry_verify']
                break
    except Exception as err:
        raise err

    return(user, pw, registry_verify)
