import json
from anchore_engine.clients.services.internal import InternalServiceClient
from anchore_engine.clients.services.http import anchy_get, anchy_post, anchy_delete


class PolicyEngineClient(InternalServiceClient):
    __service__ = 'policy_engine'

    # Service operations
    def get_status(self):
        return self.call_api(anchy_get, 'status')

    def ingress_image(self, user_id, image_id, analysis_fetch_url):
        return self.call_api(anchy_post, 'images', body=json.dumps({'user_id': user_id, 'image_id': image_id, 'fetch_url': analysis_fetch_url}))

    def list_image_users(self):
        return self.call_api(anchy_get, 'users')

    # Image/User operations
    def list_user_images(self, user_id):
        return self.call_api(anchy_get, 'users/{user_id}/images', path_params={'user_id': user_id})

    def delete_image(self, user_id, image_id):
        return self.call_api(anchy_delete, 'users/{user_id}/images/{image_id}', path_params={'user_id': user_id, 'image_id': image_id})

    def check_user_image_inline(self, user_id, image_id, tag, policy_bundle):
        return self.call_api(anchy_post, 'users/{user_id}/images/{image_id}/check_inline', path_params={'user_id': user_id, 'image_id': image_id}, query_params={'tag': tag}, body=json.dumps(policy_bundle))

    def get_image_vulnerabilities(self, user_id, image_id, force_refresh=False, vendor_only=None):
        return self.call_api(anchy_get, 'users/{user_id}/images/{image_id}/vulnerabilities', path_params={'user_id': user_id, 'image_id': image_id}, query_params={'force_refresh': force_refresh, 'vendor_only': vendor_only})

    def query_vulnerabilities(self, vuln_id=None, affected_package=None, affected_package_version=None):
        return self.call_api(anchy_get, 'query/vulnerabilities',
                             query_params={'id': vuln_id, 'affected_package': affected_package,
                                           'affected_package_version': affected_package_version})

    def query_images_by_vulnerability(self, user_id, vulnerability_id=None, severity=None, namespace=None, affected_package=None, vendor_only=None):
        return self.call_api(anchy_get, 'users/{user_id}/query/images/by_vulnerability', path_params={'user_id': user_id},
                             query_params={'vulnerability_id': vulnerability_id,
                                           'severity': severity,
                                           'namespace': namespace,
                                           'affected_package': affected_package,
                                           'vendor_only': vendor_only})

    def query_images_by_package(self, user_id, name=None, version=None, package_type=None):
        return self.call_api(anchy_get, 'users/{user_id}/query/images/by_package',
                             path_params={'user_id': user_id},
                             query_params={'name': name,
                                           'version': version,
                                           'package_type': package_type})

    # Policy/Bundle operations
    def validate_bundle(self, bundle):
        return self.call_api(anchy_post, 'validate_bundle', body=json.dumps(bundle))

    def describe_policy(self):
        return self.call_api(anchy_get, 'policy_spec')

    # Distro mapping management
    def list_distro_mappings(self):
        return self.call_api(anchy_get, 'distro_mappings')

    def add_distro_mapping(self, from_distro, to_distro, flavor):
        return self.call_api(anchy_post, 'distro_mappings', body={'from_distro': from_distro, 'to_distro': to_distro, 'flavor': flavor})

    def delete_distro_mapping(self, from_distro):
        return self.call_api(anchy_delete, 'distro_mappings', body={'from_distro': from_distro})

    # Feed operations
    def list_feeds(self, include_counts=False):
        return self.call_api(anchy_get, 'feeds', query_params={'include_counts': include_counts})

    def sync_feeds(self, force_flush=False):
        return self.call_api(anchy_post, 'feeds', query_params={'force_flush': force_flush})
