import json

import services.apiext_impl
from flask import request, Blueprint

# anchore modules
import services.common

# api = Blueprint('api_v1', __name__)
# apiversion = "v1"

# @api.route('/')
# def default():
#     request_inputs = services.common.do_request_prep(request, default_params={})
#
#     routes = ['images', 'images/checkall', 'images/<anchoreId>', 'images/<anchoreId>/check', 'images/<anchoreId>/content', 'images/<anchoreId>/vuln', 'images/by_id/<imageId>', 'images/by_id/<imageId>/check', 'images/by_id/<imageId>/content', 'images/by_id/<imageId>/vuln', 'imageimport', 'policies', 'policies/<policyId>', 'subscriptions', 'subscriptions/<subscription_id>', 'registries', 'registries/<registry>']
#     (return_object, httpcode) = services.common.make_response_routes(apiversion, routes)
#
#     return(json.dumps(return_object, indent=4)+"\n", httpcode)

# @api.route('/status', methods=['GET'])
# def status():
#     try:
#         request_inputs = services.common.do_request_prep(request, default_params={})
#
#         return_object = {
#             'busy':False,
#             'up':True,
#             'message': 'all good'
#         }
#         try:
#             service_detail,httpcode = services.apiext_impl.get_service_detail(request_inputs)
#         except:
#             service_detail = {}
#
#         return_object['detail'] = service_detail
#     except Exception as err:
#         return_object = str(err)
#
#     return(json.dumps(return_object, indent=4)+"\n", 200)

# images CRUD
# @api.route('/images', methods=['POST', 'GET'])
# def images():
#     try:
#         request_inputs = services.common.do_request_prep(request, default_params={'force':False, 'history':False})
#         return_object, httpcode = services.apiext_impl.images(request_inputs)
#     except Exception as err:
#         httpcode = 500
#         return_object = str(err)
#
#     return(json.dumps(return_object, indent=4)+"\n", httpcode)

# @api.route('/images/<anchoreId>', methods=['GET', 'DELETE'])
# def images_anchoreId(anchoreId):
#     try:
#         request_inputs = services.common.do_request_prep(request, default_params={})
#         return_object, httpcode = services.apiext_impl.images_anchoreId(request_inputs, anchoreId)
#     except Exception as err:
#         httpcode = 500
#         return_object = str(err)
#
#     return(json.dumps(return_object, indent=4)+"\n", httpcode)

# @api.route('/images/by_id/<imageId>', methods=['GET', 'DELETE'])
# def images_imageId(imageId):
#     try:
#         request_inputs = services.common.do_request_prep(request, default_params={})
#         try:
#             anchoreId = services.apiext_impl.lookup_anchoreId_from_imageId(request_inputs, imageId)
#         except:
#             anchoreId = imageId
#
#         request_inputs = services.common.do_request_prep(request, default_params={})
#         return_object, httpcode = services.apiext_impl.images_anchoreId(request_inputs, anchoreId)
#     except Exception as err:
#         httpcode = 500
#         return_object = str(err)
#
#     return(json.dumps(return_object, indent=4)+"\n", httpcode)

# @api.route('/images/<anchoreId>/check', methods=['GET'])
# def images_anchoreId_check(anchoreId):
#     try:
#         request_inputs = services.common.do_request_prep(request, default_params={'tag':None, 'detail':True, 'history':False, 'policyId':None})
#         return_object, httpcode = services.apiext_impl.images_anchoreId_check(request_inputs, anchoreId)
#     except Exception as err:
#         httpcode = 500
#         return_object = str(err)
#
#     return(json.dumps(return_object, indent=4)+"\n", httpcode)
#
# @api.route('/images/by_id/<imageId>/check', methods=['GET'])
# def images_imageId_check(imageId):
#     try:
#         request_inputs = services.common.do_request_prep(request, default_params={})
#         try:
#             anchoreId = services.apiext_impl.lookup_anchoreId_from_imageId(request_inputs, imageId)
#         except:
#             anchoreId = imageId
#
#         request_inputs = services.common.do_request_prep(request, default_params={'tag':None, 'detail':True, 'history':False, 'policyId':None})
#         return_object, httpcode = services.apiext_impl.images_anchoreId_check(request_inputs, anchoreId)
#     except Exception as err:
#         httpcode = 500
#         return_object = str(err)
#
#     return(json.dumps(return_object, indent=4)+"\n", httpcode)
#
# @api.route('/images/checkall', methods=['GET'])
# def images_checkall():
#     try:
#         request_inputs = services.common.do_request_prep(request, default_params={'detail':True, 'history':False, 'policyId':None})
#         return_object, httpcode = services.apiext_impl.images_checkall(request_inputs)
#
#     except Exception as err:
#         httpcode = 500
#         return_object = str(err)
#
#     return(json.dumps(return_object, indent=4)+"\n", httpcode)
#
# @api.route('/images/<anchoreId>/content')
# def images_anchoreId_content(anchoreId):
#     try:
#         return_object = ['os', 'npm', 'gem', 'files']
#         httpcode = 200
#     except Exception as err:
#         httpcode = 500
#         return_object = str(err)
#
#     return(json.dumps(return_object, indent=4)+"\n", httpcode)
#
# @api.route('/images/by_id/<imageId>/content')
# def images_imageId_content(imageId):
#     try:
#         return_object = ['os', 'npm', 'gem', 'files']
#         httpcode = 200
#     except Exception as err:
#         httpcode = 500
#         return_object = str(err)
#
#     return(json.dumps(return_object, indent=4)+"\n", httpcode)
#
# @api.route('/images/<anchoreId>/content/<ctype>')
# def images_anchoreId_content_ctype(anchoreId, ctype):
#     try:
#         if ctype == 'os':
#             queryType = "list-package-detail"
#         elif ctype == 'npm':
#             queryType = "list-npm-detail"
#         elif ctype == 'gem':
#             queryType = "list-gem-detail"
#         elif ctype == 'files':
#             queryType = "list-files-detail"
#         else:
#             queryType = ctype
#
#         request_inputs = services.common.do_request_prep(request, default_params={'anchoreId':anchoreId})
#         return_object, httpcode = services.apiext_impl.query(request_inputs, queryType, doformat=True)
#
#     except Exception as err:
#         httpcode = 500
#         return_object = str(err)
#
#     return(json.dumps(return_object, indent=4)+"\n", httpcode)
#
# @api.route('/images/by_id/<imageId>/content/<ctype>')
# def images_imageId_content_ctype(imageId, ctype):
#     try:
#         request_inputs = services.common.do_request_prep(request, default_params={})
#         try:
#             anchoreId = services.apiext_impl.lookup_anchoreId_from_imageId(request_inputs, imageId)
#         except:
#             anchoreId = imageId
#
#         if ctype == 'os':
#             queryType = "list-package-detail"
#         elif ctype == 'npm':
#             queryType = "list-npm-detail"
#         elif ctype == 'gem':
#             queryType = "list-gem-detail"
#         elif ctype == 'files':
#             queryType = "list-files-detail"
#         else:
#             queryType = ctype
#
#         request_inputs = services.common.do_request_prep(request, default_params={'anchoreId':anchoreId})
#         return_object, httpcode = services.apiext_impl.query(request_inputs, queryType, doformat=True)
#
#     except Exception as err:
#         httpcode = 500
#         return_object = str(err)
#
#     return(json.dumps(return_object, indent=4)+"\n", httpcode)
#
# @api.route('/images/<anchoreId>/vuln')
# def images_anchoreId_vuln(anchoreId):
#     try:
#         return_object = ['os']
#         httpcode = 200
#
#     except Exception as err:
#         httpcode = 500
#         return_object = str(err)
#
#     return(json.dumps(return_object, indent=4)+"\n", httpcode)
#
# @api.route('/images/by_id/<imageId>/vuln')
# def images_imageId_vuln(imageId):
#     try:
#         return_object = ['os']
#         httpcode = 200
#
#     except Exception as err:
#         httpcode = 500
#         return_object = str(err)
#
#     return(json.dumps(return_object, indent=4)+"\n", httpcode)
#
# @api.route('/images/<anchoreId>/vuln/<vtype>')
# def images_anchoreId_vuln_vtype(anchoreId, vtype):
#     try:
#         if vtype == 'os':
#             queryType = "cve-scan"
#         else:
#             queryType = vtype
#
#         request_inputs = services.common.do_request_prep(request, default_params={'anchoreId':anchoreId})
#         return_object, httpcode = services.apiext_impl.query(request_inputs, queryType, doformat=True)
#
#     except Exception as err:
#         httpcode = 500
#         return_object = str(err)
#
#     return(json.dumps(return_object, indent=4)+"\n", httpcode)
#
# @api.route('/images/by_id/<imageId>/vuln/<vtype>')
# def images_imageId_vuln_vtype(imageId, vtype):
#     try:
#         request_inputs = services.common.do_request_prep(request, default_params={})
#         try:
#             anchoreId = services.apiext_impl.lookup_anchoreId_from_imageId(request_inputs, imageId)
#         except:
#             anchoreId = imageId
#
#         if vtype == 'os':
#             queryType = "cve-scan"
#         else:
#             queryType = vtype
#
#         request_inputs = services.common.do_request_prep(request, default_params={'anchoreId':anchoreId})
#         return_object, httpcode = services.apiext_impl.query(request_inputs, queryType, doformat=True)
#
#     except Exception as err:
#         httpcode = 500
#         return_object = str(err)
#
#     return(json.dumps(return_object, indent=4)+"\n", httpcode)
#
# @api.route('/imageimport', methods=['POST'])
# def import_image():
#     try:
#         request_inputs = services.common.do_request_prep(request, default_params={})
#         return_object, httpcode = services.apiext_impl.import_image(request_inputs)
#
#     except Exception as err:
#         httpcode = 500
#         return_object = str(err)
#
#     return(json.dumps(return_object, indent=4)+"\n", httpcode)
#
# # policy bundle CRUD
# @api.route('/policies', methods=['GET', 'POST'])
# def policies():
#     try:
#         request_inputs = services.common.do_request_prep(request, default_params={'detail':True})
#         return_object, httpcode = services.apiext_impl.policies(request_inputs)
#
#     except Exception as err:
#         httpcode = 500
#         return_object = str(err)
#
#     return(json.dumps(return_object, indent=4)+"\n", httpcode)
#
# @api.route('/policies/<policyId>', methods=['GET', 'PUT', 'DELETE'])
# def policies_policyId(policyId):
#     try:
#         request_inputs = services.common.do_request_prep(request, default_params={'detail':True})
#         return_object, httpcode = services.apiext_impl.policies_policyId(request_inputs, policyId)
#
#     except Exception as err:
#         httpcode = 500
#         return_object = str(err)
#
#     return(json.dumps(return_object, indent=4)+"\n", httpcode)

# subscription CRUD
# @api.route('/subscriptions', methods=['GET', 'POST'])
# def subscriptions():
#     try:
#         request_inputs = services.common.do_request_prep(request, default_params={})
#         return_object, httpcode = services.apiext_impl.subscriptions(request_inputs)
#
#     except Exception as err:
#         httpcode = 500
#         return_object = str(err)
#
#     return(json.dumps(return_object, indent=4)+"\n", httpcode)
#
# @api.route('/subscriptions/<subscriptionId>', methods=['GET', 'PUT', 'DELETE'])
# def subscriptions_subscriptionId(subscriptionId):
#     try:
#         request_inputs = services.common.do_request_prep(request, default_params={})
#         return_object, httpcode = services.apiext_impl.subscriptions(request_inputs, subscriptionId=subscriptionId)
#
#     except Exception as err:
#         httpcode = 500
#         return_object = str(err)
#
#     return(json.dumps(return_object, indent=4)+"\n", httpcode)

# service operations
# @api.route('/system/services', methods=['GET'])
# def system_services():
#     try:
#         request_inputs = services.common.do_request_prep(request, default_params={})
#         return_object, httpcode = services.apiext_impl.system_services(request_inputs)
#
#     except Exception as err:
#         httpcode = 500
#         return_object = str(err)
#
#     return(json.dumps(return_object, indent=4)+"\n", httpcode)

# @api.route('/system/services/<servicename>', methods=['GET'])
# def system_services_servicename(servicename):
#     try:
#         request_inputs = services.common.do_request_prep(request, default_params={})
#         return_object, httpcode = services.apiext_impl.system_services(request_inputs, servicename=servicename)
#
#     except Exception as err:
#         httpcode = 500
#         return_object = str(err)
#
#     return(json.dumps(return_object, indent=4)+"\n", httpcode)

# @api.route('/system/services/<servicename>/<hostid>', methods=['GET', 'DELETE'])
# def system_services_servicename_hostid(servicename, hostid):
#     try:
#         request_inputs = services.common.do_request_prep(request, default_params={})
#         return_object, httpcode = services.apiext_impl.system_services(request_inputs, servicename=servicename, hostid=hostid)
#
#     except Exception as err:
#         httpcode = 500
#         return_object = str(err)
#
#     return(json.dumps(return_object, indent=4)+"\n", httpcode)

# @api.route('/registries', methods=['GET', 'POST'])
# def system_registries():
#     try:
#         request_inputs = services.common.do_request_prep(request, default_params={})
#         return_object, httpcode = services.apiext_impl.system_registries(request_inputs)
#
#     except Exception as err:
#         httpcode = 500
#         return_object = str(err)
#
#     return(json.dumps(return_object, indent=4)+"\n", httpcode)
#
#
# @api.route('/registries/<registry>', methods=['GET', 'DELETE', 'PUT'])
# def system_registries_registry(registry):
#     try:
#         request_inputs = services.common.do_request_prep(request, default_params={})
#         return_object, httpcode = services.apiext_impl.system_registries(request_inputs, registry=registry)
#
#     except Exception as err:
#         httpcode = 500
#         return_object = str(err)
#
#     return(json.dumps(return_object, indent=4)+"\n", httpcode)
