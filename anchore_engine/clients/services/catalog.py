import json
import hashlib

import anchore_engine.common.helpers
from anchore_engine.clients.services import http
import anchore_engine.configuration.localconfig
import anchore_engine.common
import anchore_engine.clients.services.common
from anchore_engine.subsys import logger
from anchore_engine.subsys.events import Event
from anchore_engine.clients.services.internal import InternalServiceClient


class CatalogClient(InternalServiceClient):
    __service__ = 'catalog'

    def lookup_registry_image(self, tag=None, digest=None):
        if not tag and not digest:
            logger.error("no input (tag=, digest=)")
            raise Exception("bad input")

        return self.call_api(http.anchy_get, 'registry_lookup', query_params={'digest': digest, 'tag': tag})

    def query_vulnerabilities(self, id=None, affected_package=None, affected_package_version=None):
        return self.call_api(http.anchy_get, 'query/vulnerabilities', query_params={'id': id, 'affected_package': affected_package, 'affected_package_version': affected_package_version})

    def query_images_by_vulnerability(self, vulnerability_id=None, severity=None, namespace=None, affected_package=None, page=1, limit=None, vendor_only=True):
        params = {
            'vulnerability_id': vulnerability_id,
            'severity': severity,
            'namespace': namespace,
            'affected_package': affected_package,
            'vendor_only': vendor_only
        }

        return self.call_api(http.anchy_get, 'query/images/by_vulnerability', query_params=params)

    def query_images_by_package(self, name=None, version=None, package_type=None, page=1, limit=None):
        return self.call_api(http.anchy_get, 'query/images/by_package', query_params={'name': name, 'version': version, 'package_type': package_type, 'page': page, 'limit': limit})

    def add_repo(self, regrepo=None, autosubscribe=False, lookuptag=None):
        return self.call_api(http.anchy_post, 'repo', query_params={'regrepo': regrepo, 'autosubscribe': autosubscribe, 'lookuptag': lookuptag})

    def add_image(self, tag=None, digest=None, dockerfile=None, annotations=None, created_at=None):
        payload = {}
        if dockerfile:
            payload['dockerfile'] = dockerfile

        if annotations:
            payload['annotations'] = annotations

        return self.call_api(http.anchy_post, 'image', query_params={'tag': tag, 'digest': digest, 'created_at': created_at}, body=json.dumps(payload))

    def get_imagetags(self):
        return self.call_api(http.anchy_get, 'summaries/imagetags')

    def get_image(self, tag=None, digest=None, imageId=None, imageDigest=None, registry_lookup=False, history=False):
        if imageDigest:
            return self.call_api(http.anchy_get, 'image/{imageDigest}', path_params={'imageDigest': imageDigest})
        else:
            return self.call_api(http.anchy_get, 'image', query_params={'tag': tag, 'history': history, 'registry_lookup': registry_lookup, 'digest': digest, 'imageId': imageId})

    def update_image(self, imageDigest, image_record=None):
        payload = {}
        if image_record:
            payload.update(image_record)

        return self.call_api(http.anchy_put, 'image/{imageDigest}', path_params={'imageDigest': imageDigest}, body=json.dumps(payload))

    def delete_image(self, imageDigest, force=False):
        return self.call_api(http.anchy_delete, 'image/{imageDigest}', path_params={'imageDigest': imageDigest}, query_params={'force': force})

    def import_image(self, anchore_data):
        return self.call_api(http.anchy_post, 'import', body=json.dumps(anchore_data))

    def add_policy(self, bundle, active=False):
        try:
            payload = anchore_engine.common.helpers.make_policy_record(self.request_namespace, bundle, active=active)
        except Exception as err:
            logger.error("couldn't prep input as valid policy add payload: " + str(err))
            raise err

        return self.call_api(http.anchy_post, 'policies', body=json.dumps(payload))

    def get_active_policy(self):
        policies = self.list_policies(active=True)
        if policies:
            return policies[0]
        else:
            return {}

    def get_policy(self, policyId):
        return self.call_api(http.anchy_get, 'policies/{policy_id}', path_params={'policy_id':policyId})

    def list_policies(self, active=None):
        return self.call_api(http.anchy_get, 'policies', query_params={'active': active})

    def update_policy(self, policyId, policy_record=None):
        return self.call_api(http.anchy_put, 'policies/{policyId}', path_params={'policyId': policyId}, body=json.dumps(policy_record))

    def delete_policy(self, policyId=None, cleanup_evals=True):
        return self.call_api(http.anchy_delete, 'policies/{policyId}', path_params={'policyId': policyId}, query_params={'cleanup_evals': cleanup_evals})

    def get_evals(self, policyId=None, imageDigest=None, tag=None, evalId=None, newest_only=False, interactive=False, history_only=False):
        return self.call_api(http.anchy_get, 'evals', query_params={'policyId': policyId, 'imageDigest': imageDigest, 'evalId': evalId, 'tag': tag, 'newest_only': newest_only, 'interactive': interactive, 'history_only': history_only})

    def get_eval_interactive(self, policyId=None, imageDigest=None, tag=None, evalId=None):
        evals = self.get_evals(policyId, imageDigest, tag, evalId, interactive=True)
        if evals:
            return evals[0]
        else:
            return {}

    def get_eval_latest(self, policyId=None, imageDigest=None, tag=None, evalId=None):
        evals = self.get_evals(policyId, imageDigest, tag, evalId, newest_only=True)
        if evals:
            return evals[0]
        else:
            return {}

    def get_eval_history(self, policyId=None, imageDigest=None, tag=None, evalId=None):
        evals = self.get_evals(policyId, imageDigest, tag, evalId, history_only=True)
        if evals:
            return evals[0]
        else:
            return {}

    def add_eval(self, evalId, policyId, imageDigest, tag, final_action, eval_url):
        try:
            payload = anchore_engine.common.helpers.make_eval_record(self.request_namespace, evalId, policyId, imageDigest, tag,
                                                                     final_action, eval_url)
        except Exception as err:
            logger.error("couldn't prep input as valid eval add payload: " + str(err))
            raise err

        return self.call_api(http.anchy_post, 'evals', body=json.dumps(payload))

    def get_subscription(self, subscription_id=None, subscription_key=None, subscription_type=None):
        if subscription_id:
            return self.call_api(http.anchy_get, 'subscriptions/{id}', path_params={'id': subscription_id})
        else:
            return self.call_api(http.anchy_get, 'subscriptions', query_params={'subscription_key': subscription_key, 'subscription_type': subscription_type})

    def delete_subscription(self, subscription_key=None, subscription_type=None, subscription_id=None):
        if subscription_key and subscription_type:
            subscription_id = hashlib.md5('+'.join([self.request_namespace, subscription_key, subscription_type]).encode('utf8')).hexdigest()

        return self.call_api(http.anchy_delete, 'subscriptions/{id}', path_params={'id': subscription_id})

    def update_subscription(self, subscriptiondata, subscription_type=None, subscription_key=None, subscription_id=None):
        if subscription_key and subscription_type:
            subscription_id = hashlib.md5('+'.join([self.request_namespace, subscription_key, subscription_type]).encode('utf8')).hexdigest()

        return self.call_api(http.anchy_put, 'subscriptions/{id}', path_params={'id': subscription_id}, body=json.dumps(subscriptiondata))

    def add_subscription(self, payload):
        return self.call_api(http.anchy_post, 'subscriptions', body=json.dumps(payload))

    def get_subscription_types(self):
        return self.call_api(http.anchy_get, 'system/subscriptions')

    def get_document(self, bucket, name):
        resp = self.call_api(http.anchy_get, 'archive/{bucket}/{name}', path_params={'bucket': bucket, 'name': name})
        return resp['document']

    def put_document(self, bucket, name, inobj):
        payload = {
            'document': inobj
        }

        return self.call_api(http.anchy_post, 'archive/{bucket}/{name}', path_params={'bucket': bucket, 'name': name}, body=json.dumps(payload))

    def delete_document(self, bucket, name):
        return self.call_api(http.anchy_delete, 'archive/{bucket}/{name}', path_params={'bucket': bucket, 'name': name})

    def get_service(self, servicename=None, hostid=None):
        if servicename:
            if hostid:
                return self.call_api(http.anchy_get, 'system/services/{servicename}/{hostid}',
                                     path_params={'servicename': servicename, 'hostid': hostid})
            else:
                return self.call_api(http.anchy_get, 'system/services/{servicename}', path_params={'servicename': servicename})
        else:
            return self.call_api(http.anchy_get, 'system/services')

    def delete_service(self, servicename=None, hostid=None):
        if not servicename or not hostid:
            raise Exception("invalid input - must specify a servicename and hostid to delete")

        return self.call_api(http.anchy_delete, 'system/services/{name}/{hostid}', path_params={'name': servicename, 'hostid': hostid})

    def get_registry(self, registry=None):
        if registry:
            return self.call_api(http.anchy_get, 'system/registries/{registry}', path_params={'registry': registry})
        else:
            return self.call_api(http.anchy_get, 'system/registries/')

    def add_registry(self, registrydata, validate=True):
        return self.call_api(http.anchy_post, 'system/registries', query_params={'validate': validate},
                             body=json.dumps(registrydata))

    def update_registry(self, registry, registrydata, validate=True):
        return self.call_api(http.anchy_put, 'system/registries/{registry}', path_params={'registry': registry}, query_params={'validate': validate},
                             body=json.dumps(registrydata))

    def delete_registry(self, registry):
        if not registry:
            raise Exception("invalid input - must specify a registry to delete")

        return self.call_api(http.anchy_delete, 'system/registries/{registry}', path_params={'registry': registry})

    def add_event(self, event):
        if not isinstance(event, Event):
            raise TypeError('Invalid event definition')

        return self.call_api(http.anchy_post, 'events', body=event.to_json())

    def get_events(self, source_servicename=None, source_hostid=None, resource_type=None, resource_id=None, level=None, since=None, before=None, page=None, limit=None):
        query_params = {
            'source_servicename': source_servicename,
            'source_hostid': source_hostid,
            'resource_type': resource_type,
            'resource_id': resource_id,
            'level': level,
            'since': since,
            'before': before,
            'page': page,
            'limit': limit
        }
        return self.call_api(http.anchy_get, 'events', query_params=query_params)

    def delete_events(self, since=None, before=None, level=None):
        query_params = {
            'since': since,
            'before': before,
            'level': level
        }
        return self.call_api(http.anchy_delete, 'events', query_params=query_params)

    def get_event(self, eventId):
        return self.call_api(http.anchy_get, 'events/{id}', path_params={'id': eventId})

    def delete_event(self, eventId):
        return self.call_api(http.anchy_delete, 'events/{id}', path_params={'id': eventId})

    # def create_user(self, accountname, username, password=None):
    #     return self.call_api(http.anchy_post, 'accounts/{account}/users', path_params={'account': accountname}, body=json.dumps({'username': username, 'password': password}))
    #
    # def delete_user(self, account, username):
    #     return self.call_api(http.anchy_delete, 'accounts/{account}/users/{username}', path_params={'account': account, 'username': username})
    #
    # def add_user_credential(self, account, username, credential_type, value):
    #     payload = {
    #         'type': credential_type.value if type(credential_type) != str else credential_type,
    #         'value': value
    #     }
    #
    #     return self.call_api(http.anchy_delete, 'accounts/{account}/users/{user}/credentials', path_params={'account': account, 'user': username}, body=json.dumps(payload))
    #
    # def delete_user_credential(self, account, username, cred_id):
    #     return self.call_api(http.anchy_delete, '/accounts/{account}/users/{user}/credentials', path_params={'account': account, 'user': username}, query_params={'uuid': cred_id})
    #
    # def list_accounts(self, is_active=None):
    #     return self.call_api(http.anchy_get, 'accounts', query_params={'is_active': is_active})
    #
    # def create_account(self, name, account_type, email):
    #
    #     payload = {
    #         'name': name,
    #         'type': account_type,
    #         'email': email
    #     }
    #     return self.call_api(http.anchy_post, 'accounts', body=json.dumps(payload))
    #
    # def get_account(self, name):
    #     return self.call_api(http.anchy_get, 'accounts/{name}', path_params={'name': name})
    #
    # def delete_account(self, name):
    #     return self.call_api(http.anchy_delete, 'accounts/{name}', path_params={'name': name})
    #
    # def activate_account(self, name):
    #     return self.call_api(http.anchy_post, 'accounts/{name}/activate', path_params={'name': name})
    #
    # def dectivate_account(self, name):
    #     return self.call_api(http.anchy_post, 'accounts/{name}/deactivate', path_params={'name': name})
