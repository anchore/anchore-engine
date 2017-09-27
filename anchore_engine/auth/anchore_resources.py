from anchore_engine.subsys import logger

def operation_access(userId, operation, operation_access_scope={}):
    allowed = False
    allowed_reason = "unknown"
    
    try:
        if 'allowed_userIds' in operation_access_scope:
            if userId in operation_access_scope['allowed_userIds']:
                allowed = True
            else:
                allowed_reason = "userId ("+str(userId)+") is not in list of allowed userIds for this operation"
        else:
            raise Exception("input operation_access_scope does not 'allowed_userIds' key with list of allowed userIds as value, cannot determine access")
            
    except Exception as err:
        allowed_reason = "cannot determine access - exception: " + str(err)
        allowed = False

    if not allowed:
        logger.warn("access denied: reason - " + str(allowed_reason))
    else:
        logger.debug("access granted")

    return(allowed)


def registry_access(userId, registry):
    return(True)

def image_access(userId, image):
    return(True)

def bundle_access(userId, bundleId):
    return(True)
