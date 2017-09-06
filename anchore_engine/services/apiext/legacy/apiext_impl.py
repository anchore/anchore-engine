# anchore modules

# anchore modules

#
# def images(request_inputs):
#     user_auth = request_inputs['auth']
#     method = request_inputs['method']
#     bodycontent = request_inputs['bodycontent']
#     params = request_inputs['params']
#
#     return_object = {}
#     httpcode = 500
#
#     userId, pw = user_auth
#     digest = tag = imageId = anchoreId = dockerfile = None
#
#     history = False
#     if params and 'history' in params:
#         history = params['history']
#
#     force = False
#     if params and 'force' in params:
#         force = params['force']
#
#     if bodycontent:
#         jsondata = json.loads(bodycontent)
#
#         if 'digest' in jsondata:
#             digest = jsondata['digest']
#         elif 'tag' in jsondata:
#             tag = jsondata['tag']
#         elif 'anchoreId' in jsondata:
#             anchoreId = jsondata['anchoreId']
#         elif 'imageId' in jsondata:
#             imageId = jsondata['imageId']
#
#         if 'dockerfile' in jsondata:
#             dockerfile = jsondata['dockerfile']
#
#     try:
#         if method == 'GET':
#             logger.debug("handling GET: ")
#             try:
#                 return_object = []
#                 image_records = clients.catalog.get_image(user_auth, digest=digest, tag=tag, imageId=imageId,
#                                                           anchoreId=anchoreId, history=history)
#                 for image_record in image_records:
#                     return_object.append(make_response_image(image_record, params))
#                 httpcode = 200
#             except Exception as err:
#                 raise err
#
#         elif method == 'POST':
#             logger.debug("handling POST: ")
#
#             # if not, add it and set it up to be analyzed
#             if not tag:
#                 # dont support digest add, yet
#                 httpcode = 500
#                 raise Exception("digest add unsupported")
#             else:
#                 # add the image to the catalog
#                 image_record = clients.catalog.add_image(user_auth, tag=tag, dockerfile=dockerfile)
#                 anchoreId = image_record['anchoreId']
#
#             # finally, do any state updates and return
#             if image_record:
#                 logger.debug("fetched image_info: " + json.dumps(image_record, indent=4))
#
#                 # auto-subscribe for NOW
#                 for image_detail in image_record['image_detail']:
#                     fulltag = image_detail['registry'] + "/" + image_detail['repo'] + ":" + image_detail['tag']
#                     sub_types = services.common.subscription_types
#                     for sub_type in sub_types:
#                         try:
#                             clients.catalog.add_subscription(user_auth, {'active': True, 'subscription_type': sub_type,
#                                                                          'subscription_key': fulltag})
#                         except:
#                             try:
#                                 clients.catalog.update_subscription(user_auth,
#                                                                     {'active': True, 'subscription_type': sub_type,
#                                                                      'subscription_key': fulltag})
#                             except:
#                                 pass
#
#                 # set the state of the image appropriately
#                 currstate = image_record['analysis_status']
#                 if not currstate:
#                     newstate = subsys.taskstate.init_state('analyze', None)
#                 elif force:
#                     newstate = subsys.taskstate.reset_state('analyze')
#                 elif image_record['image_status'] == 'deleted':
#                     newstate = subsys.taskstate.reset_state('analyze')
#                 else:
#                     newstate = currstate
#
#                 if (currstate != newstate) or (force):
#                     logger.debug("state change detected: " + str(currstate) + " : " + str(newstate))
#                     image_record.update({'image_status': 'active', 'analysis_status': newstate})
#                     rc = clients.catalog.update_image(user_auth, anchoreId, image_record)
#                 else:
#                     logger.debug("no state change detected: " + str(currstate) + " : " + str(newstate))
#
#                 httpcode = 200
#                 image_records = clients.catalog.get_image(user_auth, digest=digest, tag=tag, registry_lookup=False)
#
#                 return_object = []
#                 for image_record in image_records:
#                     return_object.append(make_response_image(image_record, params))
#
#             else:
#                 httpcode = 500
#                 raise Exception("failed to add image")
#
#     except Exception as err:
#         logger.debug("operation exception: " + str(err))
#         return_object = services.common.make_response_error(err, in_httpcode=httpcode)
#         httpcode = return_object['httpcode']
#
#     return (return_object, httpcode)
#
#
# def images_anchoreId(request_inputs, anchoreId):
#     user_auth = request_inputs['auth']
#     method = request_inputs['method']
#     bodycontent = request_inputs['bodycontent']
#     params = request_inputs['params']
#
#     return_object = {}
#     httpcode = 500
#
#     userId, pw = user_auth
#
#     try:
#         if method == 'GET':
#             logger.debug("handling GET on anchoreId: " + str(anchoreId))
#
#             image_records = clients.catalog.get_image(user_auth, anchoreId=anchoreId)
#             if image_records:
#                 return_object = []
#                 for image_record in image_records:
#                     return_object.append(make_response_image(image_record, params))
#                 httpcode = 200
#             else:
#                 httpcode = 404
#                 raise Exception("cannot locate specified image")
#
#         elif method == 'DELETE':
#             logger.debug("handling DELETE on anchoreId: " + str(anchoreId))
#
#             rc = False
#             try:
#                 rc = clients.catalog.delete_image(user_auth, anchoreId)
#             except Exception as err:
#                 raise err
#
#             if rc:
#                 return_object = rc
#                 httpcode = 200
#             else:
#                 httpcode = 500
#                 raise Exception("failed to delete")
#
#     except Exception as err:
#         logger.debug("operation exception: " + str(err))
#         return_object = services.common.make_response_error(err, in_httpcode=httpcode)
#         httpcode = return_object['httpcode']
#
#     return (return_object, httpcode)
#
#
# def images_check_impl(request_inputs, image_records):
#     user_auth = request_inputs['auth']
#     method = request_inputs['method']
#     bodycontent = request_inputs['bodycontent']
#     params = request_inputs['params']
#
#     return_object = []
#     httpcode = 500
#     userId, pw = user_auth
#
#     try:
#         if 'policyId' in params and params['policyId']:
#             bundle_records = clients.catalog.get_policy(user_auth, policyId=params['policyId'])
#             policyId = params['policyId']
#         else:
#             bundle_records = clients.catalog.get_active_policy(user_auth)
#             policyId = None
#         if not bundle_records:
#             httpcode = 404
#             raise Exception("image has no active policy to evalute: " + str(anchoreId))
#
#         if image_records:
#             for image_record in image_records:
#                 anchoreId = image_record['anchoreId']
#                 return_object_el = {}
#                 return_object_el[anchoreId] = {}
#
#                 tags = []
#                 if params and 'tag' in params and params['tag']:
#                     image_info = services.common.get_image_info(userId, "docker", params['tag'], registry_lookup=False,
#                                                                 registry_creds=[])
#                     if 'fulltag' in image_info and image_info['fulltag']:
#                         params['tag'] = image_info['fulltag']
#                     tags.append(params['tag'])
#
#                 else:
#                     for image_detail in image_record['image_detail']:
#                         fulltag = image_detail['registry'] + "/" + image_detail['repo'] + ":" + image_detail['tag']
#                         tags.append(fulltag)
#
#                 for tag in tags:
#                     if tag not in return_object_el[anchoreId]:
#                         return_object_el[anchoreId][tag] = []
#
#                     try:
#                         if params and 'history' in params and params['history']:
#                             results = clients.catalog.get_eval(user_auth, anchoreId=anchoreId, tag=tag,
#                                                                policyId=policyId)
#                         else:
#                             results = [clients.catalog.get_eval_latest(user_auth, anchoreId=anchoreId, tag=tag,
#                                                                        policyId=policyId)]
#                     except Exception as err:
#                         results = []
#
#                     httpcode = 200
#                     for result in results:
#                         fresult = make_response_policyeval(user_auth, result, params)
#                         return_object_el[anchoreId][tag].append(fresult[tag])
#                 if return_object_el:
#                     return_object.append(return_object_el)
#         else:
#             httpcode = 404
#             raise Exception("could not find image record(s) input anchoreId(s)")
#
#     except Exception as err:
#         logger.debug("operation exception: " + str(err))
#         return_object = services.common.make_response_error(err, in_httpcode=httpcode)
#         httpcode = return_object['httpcode']
#
#     return (return_object, httpcode)
#
#
# def images_anchoreId_check(request_inputs, anchoreId):
#     user_auth = request_inputs['auth']
#     method = request_inputs['method']
#     bodycontent = request_inputs['bodycontent']
#     params = request_inputs['params']
#
#     return_object = {}
#     httpcode = 500
#     userId, pw = user_auth
#     try:
#         image_records = clients.catalog.get_image(user_auth, anchoreId=anchoreId)
#         return_object, httpcode = images_check_impl(request_inputs, image_records)
#     except Exception as err:
#         logger.debug("operation exception: " + str(err))
#         return_object = services.common.make_response_error(err, in_httpcode=httpcode)
#         httpcode = return_object['httpcode']
#
#     return (return_object, httpcode)

#
# def policies(request_inputs):
#     user_auth = request_inputs['auth']
#     method = request_inputs['method']
#     bodycontent = request_inputs['bodycontent']
#     params = request_inputs['params']
#
#     return_object = []
#     httpcode = 500
#     userId, pw = user_auth
#
#     try:
#         if method == 'GET':
#             logger.debug("handling GET")
#
#             try:
#                 policy_records = clients.catalog.get_policy(user_auth)
#             except Exception as err:
#                 httpcode = 404
#                 raise Exception("unable to get policy_records for user (" + str(userId) + ") - exception: " + str(err))
#
#             if policy_records:
#                 httpcode = 200
#                 ret = []
#                 for policy_record in policy_records:
#                     ret.append(make_response_policy(user_auth, policy_record, params))
#                 return_object = ret
#             else:
#                 httpcode = 404
#                 raise Exception('no policies found for user')
#
#         elif method == 'POST':
#             logger.debug("handling POST: ")
#
#             jsondata = json.loads(bodycontent)
#
#             # schema check
#             try:
#                 import anchore.anchore_policy
#                 rc = anchore.anchore_policy.verify_policy_bundle(bundle=jsondata)
#                 if not rc:
#                     raise Exception("input bundle does not conform to anchore bundle schema")
#             except Exception as err:
#                 raise Exception("cannot run bundle schema verification - exception: " + str(err))
#
#             if 'id' in jsondata and jsondata['id']:
#                 policyId = jsondata['id']
#             else:
#                 policyId = hashlib.md5(str(userId + ":" + jsondata['name'])).hexdigest()
#                 jsondata['id'] = policyId
#
#             try:
#                 policybundle = jsondata
#                 policy_record = clients.catalog.add_policy(user_auth, policybundle)
#             except Exception as err:
#                 raise Exception("cannot store policy data to catalog - exception: " + str(err))
#
#             if policy_record:
#                 return_object = make_response_policy(user_auth, policy_record, params)
#                 httpcode = 200
#             else:
#                 raise Exception('failed to add policy to catalog DB')
#
#     except Exception as err:
#         logger.debug("operation exception: " + str(err))
#         return_object = services.common.make_response_error(err, in_httpcode=httpcode)
#         httpcode = return_object['httpcode']
#
#     return (return_object, httpcode)
#
#
# def policies_policyId(request_inputs, policyId):
#     user_auth = request_inputs['auth']
#     method = request_inputs['method']
#     bodycontent = request_inputs['bodycontent']
#     params = request_inputs['params']
#
#     return_object = {}
#     httpcode = 500
#     userId, pw = user_auth
#     try:
#         if method == 'GET':
#             try:
#                 policy_records = clients.catalog.get_policy(user_auth, policyId=policyId)
#             except Exception as err:
#                 logger.warn("unable to get policy_records for user (" + str(userId) + ") - exception: " + str(err))
#                 policy_records = []
#
#             if policy_records:
#                 ret = []
#
#                 for policy_record in policy_records:
#                     ret.append(make_response_policy(user_auth, policy_record, params))
#                 return_object = ret
#                 httpcode = 200
#             else:
#                 httpcode = 404
#                 raise Exception("cannot locate specified policyId")
#
#         elif method == 'PUT':
#             logger.debug("handling PUT")
#
#             jsondata = json.loads(bodycontent)
#
#             try:
#                 policy_records = clients.catalog.get_policy(user_auth, policyId=policyId)
#             except Exception as err:
#                 logger.warn("unable to get policy_records for user (" + str(userId) + ") - exception: " + str(err))
#                 policy_records = []
#
#             if policy_records:
#                 policy_record = policy_records[0]
#                 if policy_record['active'] and not jsondata['active']:
#                     httpcode = 500
#                     raise Exception("cannot deactivate an active policy - can only activate an inactive policy")
#                 elif policyId != jsondata['policyId']:
#                     httpcode = 500
#                     raise Exception("policyId in route is different from policyId in payload")
#
#                 policy_record.update(jsondata)
#                 policy_record['policyId'] = policyId
#                 return_policy_record = clients.catalog.update_policy(user_auth, policyId, policy_record=policy_record)
#                 return_object = [make_response_policy(user_auth, return_policy_record, params)]
#                 httpcode = 200
#             else:
#                 httpcode = 404
#                 raise Exception("cannot locate specified policyId")
#
#         elif method == 'DELETE':
#             logger.debug("handling DELETE")
#
#             try:
#                 try:
#                     policy_records = clients.catalog.get_policy(user_auth, policyId=policyId)
#                 except Exception as err:
#                     logger.warn("unable to get policy_records for user (" + str(userId) + ") - exception: " + str(err))
#                     policy_records = []
#
#                 if not policy_records:
#                     rc = True
#                 else:
#                     policy_record = policy_records[0]
#                     if policy_record['active']:
#                         httpcode = 500
#                         raise Exception(
#                             "cannot delete an active policy - activate a different policy then delete this one")
#
#                 rc = clients.catalog.delete_policy(user_auth, policyId=policyId)
#             except Exception as err:
#                 raise err
#
#             if rc:
#                 httpcode = 200
#                 return_object = "deleted"
#             else:
#                 httpcode = 500
#                 raise Exception('not deleted')
#
#     except Exception as err:
#         return_object = services.common.make_response_error(err, in_httpcode=httpcode)
#         httpcode = return_object['httpcode']
#
#     return (return_object, httpcode)
#
#
# def subscriptions(request_inputs, subscriptionId=None):
#     user_auth = request_inputs['auth']
#     method = request_inputs['method']
#     bodycontent = request_inputs['bodycontent']
#     params = request_inputs['params']
#
#     return_object = []
#     httpcode = 500
#     userId, pw = user_auth
#
#     try:
#         if method == 'GET':
#             subscription_records = clients.catalog.get_subscription(user_auth, subscription_id=subscriptionId)
#             for subscription_record in subscription_records:
#                 return_object.append(make_response_subscription(user_auth, subscription_record, params))
#             httpcode = 200
#         elif method == 'POST':
#             subscriptiondata = json.loads(bodycontent)
#             subscription_records = clients.catalog.add_subscription(user_auth, subscriptiondata)
#             for subscription_record in subscription_records:
#                 return_object.append(make_response_subscription(user_auth, subscription_record, params))
#             httpcode = 200
#         elif method == 'PUT':
#             subscriptiondata = json.loads(bodycontent)
#             subscription_records = clients.catalog.update_subscription(user_auth, subscriptiondata,
#                                                                        subscription_id=subscriptionId)
#             for subscription_record in subscription_records:
#                 return_object.append(make_response_subscription(user_auth, subscription_record, params))
#             httpcode = 200
#         elif method == 'DELETE':
#             return_object = clients.catalog.delete_subscription(user_auth, subscription_id=subscriptionId)
#             if return_object:
#                 httpcode = 200
#
#     except Exception as err:
#         return_object = services.common.make_response_error(err, in_httpcode=httpcode)
#         httpcode = return_object['httpcode']
#
#     return (return_object, httpcode)
#
#
# def subscriptions_types(request_inputs):
#     user_auth = request_inputs['auth']
#     method = request_inputs['method']
#     bodycontent = request_inputs['bodycontent']
#     params = request_inputs['params']
#
#     return_object = {}
#     httpcode = 500
#     userId, pw = user_auth
#
#     try:
#         if method == 'GET':
#             httpcode = 404
#             return_object = services.common.make_response_error("cannot locate subscription types",
#                                                                 in_httpcode=httpcode)
#             httpcode = return_object['httpcode']
#
#             subscription_records = clients.catalog.get_subscription_types(user_auth)
#             if subscription_records:
#                 return_object = subscription_records
#                 httpcode = 200
#
#     except Exception as err:
#         return_object = services.common.make_response_error(err, in_httpcode=httpcode)
#         httpcode = return_object['httpcode']
#
#     return (return_object, httpcode)


# def query(request_inputs, queryType, doformat=False):
#     user_auth = request_inputs['auth']
#     method = request_inputs['method']
#     bodycontent = request_inputs['bodycontent']
#     params = request_inputs['params']
#
#     return_object = {}
#     httpcode = 500
#     userId, pw = user_auth
#     try:
#         tag = params.pop('tag', None)
#         anchoreId = params.pop('anchoreId', None)
#         digest = params.pop('digest', None)
#
#         image_reports = clients.catalog.get_image(user_auth, tag=tag, digest=digest, anchoreId=anchoreId)
#         for image_report in image_reports:
#             anchoreId = image_report['anchoreId']
#             # query_data = json.loads(clients.catalog.get_document(user_auth, 'query_data', anchoreId))
#             query_data = clients.catalog.get_document(user_auth, 'query_data', anchoreId)
#             if not queryType:
#                 return_object[anchoreId] = query_data.keys()
#             elif queryType in query_data:
#
#                 if doformat:
#                     return_object[anchoreId] = make_response_query(queryType, query_data[queryType])
#                 else:
#                     return_object[anchoreId] = query_data[queryType]
#
#             else:
#                 return_object[anchoreId] = {}
#
#         httpcode = 200
#     except Exception as err:
#         return_object = services.common.make_response_error(err, in_httpcode=httpcode)
#         httpcode = return_object['httpcode']
#
#     return (return_object, httpcode)

#
# def interactive_analyze(request_inputs):
#     user_auth = request_inputs['auth']
#     method = request_inputs['method']
#     bodycontent = request_inputs['bodycontent']
#     params = request_inputs['params']
#
#     return_object = {}
#     httpcode = 500
#     userId, pw = user_auth
#     try:
#         if not bodycontent:
#             raise Exception("must provide body JSON in request")
#
#         jsondata = json.loads(bodycontent)
#         tag = jsondata.pop('tag', None)
#
#         return_object = clients.worker.analyze(user_auth, tag)
#         httpcode = 200
#     except Exception as err:
#         return_object = services.common.make_response_error(err, in_httpcode=httpcode)
#         httpcode = return_object['httpcode']
#
#     return (return_object, httpcode)
#
#
# def interactive_query(request_inputs):
#     user_auth = request_inputs['auth']
#     method = request_inputs['method']
#     bodycontent = request_inputs['bodycontent']
#     params = request_inputs['params']
#
#     return_object = {}
#     httpcode = 500
#     userId, pw = user_auth
#     try:
#         if not bodycontent:
#             raise Exception("must provide body JSON in request")
#
#         jsondata = json.loads(bodycontent)
#
#         anchoreId = jsondata.pop('anchoreId', None)
#         query = jsondata.pop('query', None)
#
#         return_object = clients.worker.query(user_auth, anchoreId, query)
#         httpcode = 200
#     except Exception as err:
#         return_object = services.common.make_response_error(err, in_httpcode=httpcode)
#         httpcode = return_object['httpcode']
#
#     return (return_object, httpcode)
#
#
# def interactive_eval(request_inputs):
#     user_auth = request_inputs['auth']
#     method = request_inputs['method']
#     bodycontent = request_inputs['bodycontent']
#     params = request_inputs['params']
#
#     return_object = {}
#     httpcode = 500
#     userId, pw = user_auth
#     try:
#         if not bodycontent:
#             raise Exception("must provide body JSON in request")
#
#         jsondata = json.loads(bodycontent)
#
#         anchoreId = jsondata.pop('anchoreId', None)
#         policyId = jsondata.pop('policyId', None)
#         policyBundle = jsondata.pop('policyBundle', None)
#         tag = jsondata.pop('tag', None)
#
#         return_object = clients.worker.evaluate(user_auth, anchoreId, tag, policyId=policyId, policyBundle=policyBundle)
#         httpcode = 200
#     except Exception as err:
#         return_object = services.common.make_response_error(err, in_httpcode=httpcode)
#         httpcode = return_object['httpcode']
#
#     return (return_object, httpcode)


# def get_service_detail(request_inputs):
#     user_auth = request_inputs['auth']
#     method = request_inputs['method']
#     bodycontent = request_inputs['bodycontent']
#     params = request_inputs['params']
#
#     return_object = {}
#     httpcode = 500
#     try:
#         ret_queues = {}
#         queues = clients.simplequeue.get_queues(user_auth)
#         for queuename in queues:
#             ret_queues[queuename] = {}
#             qlen = clients.simplequeue.qlen(user_auth, queuename)
#             ret_queues[queuename]['qlen'] = qlen
#
#         return_object['queues'] = ret_queues
#         httpcode = 200
#     except Exception as err:
#         return_object = services.common.make_response_error(err, in_httpcode=httpcode)
#         httpcode = return_object['httpcode']
#
#     return (return_object, httpcode)
#
#
# def system_services(request_inputs, servicename=None, hostid=None):
#     user_auth = request_inputs['auth']
#     method = request_inputs['method']
#     bodycontent = request_inputs['bodycontent']
#     params = request_inputs['params']
#
#     return_object = []
#     httpcode = 500
#     try:
#         if method == 'GET':
#             service_records = clients.catalog.get_service(user_auth, servicename=servicename, hostid=hostid)
#             for service_record in service_records:
#                 return_object.append(make_response_service(user_auth, service_record, params))
#
#             httpcode = 200
#         elif method == 'DELETE':
#             return_object = clients.catalog.delete_service(user_auth, servicename=servicename, hostid=hostid)
#             if return_object:
#                 httpcode = 200
#
#     except Exception as err:
#         return_object = services.common.make_response_error(err, in_httpcode=httpcode)
#         httpcode = return_object['httpcode']
#
#     return (return_object, httpcode)


# def system_registries(request_inputs, registry=None):
#     user_auth = request_inputs['auth']
#     method = request_inputs['method']
#     bodycontent = request_inputs['bodycontent']
#     params = request_inputs['params']
#
#     return_object = []
#     httpcode = 500
#
#     try:
#         if method == 'GET':
#             registry_records = clients.catalog.get_registry(user_auth, registry=registry)
#             for registry_record in registry_records:
#                 return_object.append(make_response_registry(user_auth, registry_record, params))
#             httpcode = 200
#         elif method == 'POST':
#             registrydata = json.loads(bodycontent)
#             registry_records = clients.catalog.add_registry(user_auth, registrydata)
#             for registry_record in registry_records:
#                 return_object.append(make_response_registry(user_auth, registry_record, params))
#             httpcode = 200
#         elif method == 'PUT':
#             registrydata = json.loads(bodycontent)
#             registry_records = clients.catalog.update_registry(user_auth, registry, registrydata)
#             for registry_record in registry_records:
#                 return_object.append(make_response_registry(user_auth, registry_record, params))
#             httpcode = 200
#         elif method == 'DELETE':
#             return_object = clients.catalog.delete_registry(user_auth, registry=registry)
#             if return_object:
#                 httpcode = 200
#
#     except Exception as err:
#         return_object = services.common.make_response_error(err, in_httpcode=httpcode)
#         httpcode = return_object['httpcode']
#
#     return (return_object, httpcode)


#####################################

# def impl_template(request_inputs):
#     user_auth = request_inputs['auth']
#     method = request_inputs['method']
#     bodycontent = request_inputs['bodycontent']
#     params = request_inputs['params']
#
#     return_object = {}
#     httpcode = 500
#     try:
#         pass
#     except Exception as err:
#         return_object = services.common.make_response_error(err, in_httpcode=httpcode)
#         httpcode = return_object['httpcode']
#
#     return (return_object, httpcode)
#
#
# def lookup_anchoreId_from_imageId(request_inputs, imageId):
#     user_auth = request_inputs['auth']
#     method = request_inputs['method']
#     bodycontent = request_inputs['bodycontent']
#     params = request_inputs['params']
#
#     userId, pw = user_auth
#
#     ret = None
#
#     try:
#         image_records = clients.catalog.get_image(user_auth, imageId=imageId)
#         if image_records:
#             image_record = image_records[0]
#
#         anchoreId = image_record['anchoreId']
#         ret = anchoreId
#
#     except Exception as err:
#         logger.debug("operation exception: " + str(err))
#         raise err
#
#     return (ret)


#####################################

# def make_response_registry(user_auth, registry_record, params):
#     ret = {}
#     userId, pw = user_auth
#
#     try:
#         for k in ['registry', 'userId', 'registry_user', 'registry_verify', 'registry_meta']:
#             ret[k] = registry_record[k]
#
#         for datekey in ['last_updated', 'created_at']:
#             try:
#                 ret[datekey] = datetime.datetime.utcfromtimestamp(registry_record[datekey]).isoformat()
#             except:
#                 pass
#     except Exception as err:
#         raise Exception("failed to format registry response: " + str(err))
#
#     return (ret)


# def make_response_service(user_auth, service_record, params):
#     ret = {}
#     userId, pw = user_auth
#
#     try:
#         for k in ['hostid', 'version', 'base_url', 'status_message', 'servicename']:
#             ret[k] = service_record[k]
#     except Exception as err:
#         raise Exception("failed to format service response: " + str(err))
#
#     return (ret)


# def make_response_subscription(user_auth, subscription_record, params):
#     ret = {}
#     userId, pw = user_auth
#
#     try:
#         ret = subscription_record
#         # for k in ['userId', 'created_at', 'last_updated']:
#         #    ret.pop(k, None)
#     except Exception as err:
#         raise Exception("failed to format subscription response: " + str(err))
#
#     return (ret)


# def make_response_policy(user_auth, policy_record, params):
#     ret = {}
#     userId, pw = user_auth
#
#     try:
#         if 'detail' in params and not params['detail']:
#             # strip out the detail
#             policy_record['policybundle'] = {}
#
#         for datekey in ['last_updated', 'created_at']:
#             try:
#                 policy_record[datekey] = datetime.datetime.utcfromtimestamp(policy_record[datekey]).isoformat()
#             except:
#                 pass
#
#         ret = policy_record
#
#     except Exception as err:
#         raise Exception("failed to format policy eval response: " + str(err))
#
#     return (ret)

#
# def make_response_policyeval(user_auth, eval_record, params):
#     ret = {}
#     userId, pw = user_auth
#
#     try:
#         tag = eval_record['tag']
#
#         ret[tag] = {}
#
#         if eval_record['evalId'] and eval_record['policyId']:
#             ret[tag]['detail'] = {}
#             if params and 'detail' in params and params['detail']:
#                 eval_data = clients.catalog.get_document(user_auth, 'policy_evaluations', eval_record['evalId'])
#                 # ret[tag]['detail']['result'] = json.loads(eval_data)
#                 ret[tag]['detail']['result'] = eval_data
#                 bundle_data = clients.catalog.get_document(user_auth, 'policy_bundles', eval_record['policyId'])
#                 # ret[tag]['detail']['policy'] = json.loads(bundle_data)
#                 ret[tag]['detail']['policy'] = bundle_data
#
#             ret[tag]['policyId'] = eval_record['policyId']
#
#             if eval_record['final_action'] == 'GO':
#                 ret[tag]['status'] = 'pass'
#             else:
#                 ret[tag]['status'] = 'fail'
#
#             ret[tag]['last_evaluation'] = datetime.datetime.fromtimestamp(eval_record['created_at']).isoformat()
#
#         else:
#             ret[tag]['policyId'] = "N/A"
#             ret[tag]['final_action'] = "fail"
#             ret[tag]['last_evaluation'] = "N/A"
#             ret[tag]['detail'] = {}
#
#     except Exception as err:
#         raise Exception("failed to format policy eval response: " + str(err))
#
#     return (ret)
#
#
# def make_response_image(image_record, params={}):
#     ret = image_record
#
#     # try to assemble full strings
#     if image_record and 'image_detail' in image_record:
#         for image_detail in image_record['image_detail']:
#             try:
#                 image_detail['fulldigest'] = image_detail['registry'] + "/" + image_detail['repo'] + "@" + image_detail[
#                     'digest']
#                 image_detail['fulltag'] = image_detail['registry'] + "/" + image_detail['repo'] + ":" + image_detail[
#                     'tag']
#             except:
#                 image_detail['fulldigest'] = None
#                 image_detail['fulltag'] = None
#
#             for datekey in ['last_updated', 'created_at']:
#                 try:
#                     image_detail[datekey] = datetime.datetime.utcfromtimestamp(image_detail[datekey]).isoformat()
#                 except:
#                     pass
#
#     if params and 'detail' in params and not params['detail']:
#         image_record['image_detail'] = []
#
#     for datekey in ['last_updated', 'created_at']:
#         try:
#             image_record[datekey] = datetime.datetime.utcfromtimestamp(image_record[datekey]).isoformat()
#         except:
#             pass
#
#     return (ret)
#
#
# def make_response_query(queryType, query_data):
#     ret = []
#
#     if not query_data:
#         logger.warn("empty query data given to format - returning empty result")
#         return (ret)
#
#     if queryType == 'cve-scan':
#         keymap = {
#             'vuln': 'CVE_ID',
#             'severity': 'Severity',
#             'package': 'Vulnerable_Package',
#             'fix': 'Fix_Available'
#         }
#
#         try:
#             for imageId in query_data.keys():
#                 header = query_data[imageId]['result']['header']
#                 rows = query_data[imageId]['result']['rows']
#                 for row in rows:
#                     el = {}
#                     for k in keymap.keys():
#                         try:
#                             el[k] = row[header.index(keymap[k])]
#                         except:
#                             el[k] = None
#
#                         # conversions
#                         if el[k] == 'N/A':
#                             el[k] = None
#
#                     ret.append(el)
#         except Exception as err:
#             logger.warn("could not prepare query response - exception: " + str(err))
#             ret = []
#
#
#     elif queryType in ['list-package-detail', 'list-npm-detail', 'list-gem-detail']:
#         keymap = {
#             'package': 'Package_Name',
#             'type': 'Type',
#             'size': 'Size',
#             'version': 'Version',
#             'origin': 'Origin',
#             'license': 'License',
#             'location': 'Location'
#         }
#
#         try:
#             for imageId in query_data.keys():
#                 header = query_data[imageId]['result']['header']
#                 rows = query_data[imageId]['result']['rows']
#                 for row in rows:
#                     el = {}
#                     for k in keymap.keys():
#                         try:
#                             el[k] = row[header.index(keymap[k])]
#                         except:
#                             el[k] = None
#
#                         # conversions
#                         if el[k] == 'N/A':
#                             el[k] = None
#                         elif k == 'size':
#                             try:
#                                 el[k] = int(el[k])
#                             except:
#                                 el[k] = None
#                         elif k == 'type' and not el[k]:
#                             if queryType == 'list-npm-detail':
#                                 el[k] = 'NPM'
#                             elif queryType == 'list-gem-detail':
#                                 el[k] = 'GEM'
#                     if queryType == 'list-package-detail' and 'location' in el:
#                         el.pop('location', None)
#                     ret.append(el)
#         except Exception as err:
#             logger.warn("could not prepare query response - exception: " + str(err))
#             ret = []
#
#     elif queryType == 'list-files-detail':
#         keymap = {
#             'filename': 'Filename',
#             'type': 'Type',
#             'size': 'Size',
#             'mode': 'Mode',
#             'sha256': 'Checksum',
#             'linkdest': 'Link_Dest'
#         }
#
#         try:
#             for imageId in query_data.keys():
#                 header = query_data[imageId]['result']['header']
#                 rows = query_data[imageId]['result']['rows']
#                 for row in rows:
#                     el = {}
#                     for k in keymap.keys():
#                         try:
#                             el[k] = row[header.index(keymap[k])]
#                         except:
#                             el[k] = None
#
#                         # conversions
#                         if el[k] == 'N/A':
#                             el[k] = None
#                         elif el[k] == 'DIRECTORY_OR_OTHER':
#                             el[k] = None
#                         elif k == 'size':
#                             el[k] = int(el[k])
#
#                     ret.append(el)
#         except Exception as err:
#             logger.warn("could not prepare query response - exception: " + str(err))
#             ret = []
#     else:
#         ret = query_data
#
#     return (ret)
